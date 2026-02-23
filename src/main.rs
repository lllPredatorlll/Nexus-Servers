use anyhow::Result;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UdpSocket, TcpListener};
use tokio::sync::RwLock;
use log::{info, error, warn, debug};
use flexi_logger::{Logger, FileSpec, Criterion, Naming, Cleanup, Duplicate};
use tun::Configuration;
use serde::{Serialize, Deserialize};
use socket2::{Socket, Domain, Type, Protocol};
use bytes::{Bytes, BytesMut, BufMut};

mod utils;
mod config;


const VERSION: &str = "0.9.003 dev";

struct Peer {
    _tx: async_channel::Sender<Bytes>,
    last_seen: Arc<AtomicU64>,
    client_token: Option<String>,
    ipv4: Ipv4Addr,
    ipv6: Ipv6Addr,
    _stats_tx: Option<Arc<AtomicU64>>,
    stats_rx: Option<Arc<AtomicU64>>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct ClientEntry {
    name: String,
    token: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct ClientsConfig {
    #[serde(default)]
    clients: Vec<ClientEntry>,
}

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::args().any(|arg| arg == "--version") {
        println!("{}", VERSION);
        return Ok(());
    }

    Logger::try_with_str("info")
        .expect("Не удалось инициализировать логгер")
        .log_to_file(FileSpec::default().directory(".").basename("server"))
        .rotate(
            Criterion::Size(10 * 1024 * 1024),
            Naming::Numbers,
            Cleanup::KeepLogFiles(5),
        )
        .duplicate_to_stdout(Duplicate::All)
        .start()
        .expect("Не удалось запустить логгер");

    let config_data = config::load("server_config.toml")
        .map_err(|e| anyhow::anyhow!("Не удалось загрузить server_config.toml: {}", e))?;
    let app_config = Arc::new(config_data);

    let mut config = Configuration::default();
    config
        .address(app_config.tun.address.parse::<std::net::Ipv4Addr>()?)
        .destination(app_config.tun.destination.parse::<std::net::Ipv4Addr>()?)
        .netmask((255, 255, 255, 0))
        .name("nexus0")
        .mtu(app_config.tun.mtu)
        .up();

    let dev = tun::create_as_async(&config)?;
    let (mut tun_reader, mut tun_writer) = tokio::io::split(dev);

    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("ip")
            .args(&["-6", "addr", "add", &app_config.tun.address_v6, "dev", "nexus0"])
            .output();
    }

    let (tun_tx, tun_rx) = async_channel::bounded::<Bytes>(16384);
    tokio::spawn(async move {
        while let Ok(pkt) = tun_rx.recv().await {
            let _ = tun_writer.write_all(&pkt).await;
        }
    });

    let addr: SocketAddr = app_config.net.endpoint.parse()?;
    let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    
    if domain == Domain::IPV6 {
        let _ = socket.set_only_v6(false);
    }
    
    let _ = socket.set_recv_buffer_size(8 * 1024 * 1024);
    let _ = socket.set_send_buffer_size(8 * 1024 * 1024);
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    
    let socket = UdpSocket::from_std(socket.into())?;
    let socket = Arc::new(socket);
    
    let tcp_listener = TcpListener::bind(&app_config.net.endpoint).await?;
    info!("Nexus Server listening on UDP & TCP {}", app_config.net.endpoint);

    let peers: Arc<RwLock<HashMap<SocketAddr, Peer>>> = Arc::new(RwLock::new(HashMap::new()));
    let ip_map: Arc<RwLock<HashMap<IpAddr, async_channel::Sender<Bytes>>>> = Arc::new(RwLock::new(HashMap::new()));
    
    let client_allowlist: Arc<RwLock<HashMap<String, String>>> = Arc::new(RwLock::new(HashMap::new()));
    let client_stats: Arc<RwLock<HashMap<String, (Arc<AtomicU64>, Arc<AtomicU64>)>>> = Arc::new(RwLock::new(HashMap::new()));

    let next_ip = Arc::new(Mutex::new(2u8));

    let total_tx = Arc::new(AtomicU64::new(0));
    let total_rx = Arc::new(AtomicU64::new(0));
    let total_err = Arc::new(AtomicU64::new(0));

    let allowlist_reloader = client_allowlist.clone();
    let stats_saver = client_stats.clone();
    tokio::spawn(async move {
        loop {
            if let Ok(content) = tokio::fs::read_to_string("clients.toml").await {
                if let Ok(config) = toml::from_str::<ClientsConfig>(&content) {
                    let mut lock = allowlist_reloader.write().await;
                    lock.clear();
                    for client in config.clients {
                        lock.insert(client.token, client.name);
                    }
                }
            }

            {
                let lock = stats_saver.read().await;
                let mut stats_map = HashMap::new();
                for (token, (tx, rx)) in lock.iter() {
                    stats_map.insert(token.clone(), (
                        tx.load(Ordering::Relaxed),
                        rx.load(Ordering::Relaxed)
                    ));
                }
                if !stats_map.is_empty() {
                    if let Ok(json) = serde_json::to_string_pretty(&stats_map) {
                        let _ = tokio::fs::write("client_stats.json", json).await;
                    }
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
        }
    });

    let t_tx = total_tx.clone();
    let t_rx = total_rx.clone();
    let t_err = total_err.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            info!("[Server Stats] Tx: {} B | Rx: {} B | Errors: {}", 
                t_tx.load(Ordering::Relaxed), t_rx.load(Ordering::Relaxed), t_err.load(Ordering::Relaxed));
        }
    });

    let peers_clean = peers.clone();
    let ip_map_clean = ip_map.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            let timeout = 120;

            let mut to_remove = Vec::new();
            {
                let peers = peers_clean.read().await;
                for (addr, peer) in peers.iter() {
                    if now - peer.last_seen.load(Ordering::Relaxed) > timeout {
                        to_remove.push((*addr, peer.ipv4, peer.ipv6));
                    }
                }
            }

            if !to_remove.is_empty() {
                let mut peers = peers_clean.write().await;
                let mut ip_map = ip_map_clean.write().await;
                
                for (addr, ipv4, ipv6) in to_remove {
                    peers.remove(&addr);
                    ip_map.remove(&IpAddr::V4(ipv4));
                    ip_map.remove(&IpAddr::V6(ipv6));
                    info!("Клиент {} отключен по таймауту", addr);
                }
            }
        }
    });

    let peers_recv = peers.clone();
    let ip_map_recv = ip_map.clone();
    let socket_recv = socket.clone();
    let socket_udp_send = socket.clone();
    let tun_tx_udp = tun_tx.clone();
    let udp_config = app_config.clone();
    let next_ip_udp = next_ip.clone();
    let udp_rx_metric = total_rx.clone();
    let udp_tx_metric = total_tx.clone();
    let udp_err_metric = total_err.clone();
    let udp_allowlist = client_allowlist.clone();
    let udp_client_stats = client_stats.clone();

    let num_workers = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    let (_udp_tx_dispatch, _) = tokio::sync::broadcast::channel::<()>(1);

    tokio::spawn(async move {
        let (tx_pkt, rx_pkt) = async_channel::bounded::<(BytesMut, SocketAddr)>(16384);


        for _ in 0..num_workers {
            let rx_pkt = rx_pkt.clone();
            let peers_recv = peers_recv.clone();
            let ip_map_recv = ip_map_recv.clone();
            let socket_recv = socket_recv.clone();
            let socket_udp_send = socket_udp_send.clone();
            let tun_tx_udp = tun_tx_udp.clone();
            let udp_rx_metric = udp_rx_metric.clone();
            let udp_tx_metric = udp_tx_metric.clone();
            let udp_allowlist = udp_allowlist.clone();
            let udp_client_stats = udp_client_stats.clone();
            let next_ip_udp = next_ip_udp.clone();
            let auth_token = udp_config.security.auth_token.as_bytes().to_vec();

            tokio::spawn(async move {
                while let Ok((buf, addr)) = rx_pkt.recv().await {
                    let len = buf.len();
                    udp_rx_metric.fetch_add(len as u64, Ordering::Relaxed);
                    if len < 1 { continue; }

                    let packet_type = buf[0];

                    // Check if it's a known peer (Data packet)
                    let (peer_tx, _peer_token, peer_stats_rx, peer_last_seen) = {
                        let lock = peers_recv.read().await;
                        if let Some(p) = lock.get(&addr) {
                            (Some(p._tx.clone()), p.client_token.clone(), p.stats_rx.clone(), Some(p.last_seen.clone()))
                        } else {
                            (None, None, None, None)
                        }
                    };

                    // If peer exists and it's a data packet (IPv4 starts with 0x4, IPv6 with 0x6)
                    // Handshake starts with 0x01.
                    if let Some(_) = peer_tx {
                        if packet_type != 0x01 {
                            if let Some(rx) = &peer_stats_rx {
                                rx.fetch_add(len as u64, Ordering::Relaxed);
                            }
                            if let Some(ls) = peer_last_seen {
                                ls.store(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(), Ordering::Relaxed);
                            }
                            let data_bytes = Bytes::copy_from_slice(&buf);
                            let _ = tun_tx_udp.send(data_bytes).await;
                            continue;
                        }
                    }

                    // Handshake: [0x01 | token_len | token]
                    if packet_type == 0x01 {
                        if len < 2 { continue; }
                        let token_len = buf[1] as usize;
                        if len < 2 + token_len { continue; }
                        
                        let token_sent = &buf[2..2+token_len];
                        let mut client_token_found = None;

                        if token_sent != auth_token.as_slice() {
                            let lock = udp_allowlist.read().await;
                            if let Some(token_str) = std::str::from_utf8(token_sent).ok() {
                                if lock.contains_key(token_str) {
                                    client_token_found = Some(token_str.to_string());
                                }
                            }
                            if client_token_found.is_none() {
                                warn!("Auth failed (UDP): Invalid token from {}", addr);
                                continue;
                            }
                        }

                        let client_ip_octet = {
                            let mut ip = next_ip_udp.lock().unwrap();
                            let val = *ip;
                            *ip = if val >= 253 { 2 } else { val + 1 };
                            val
                        };
                        let client_ip = Ipv4Addr::new(10, 0, 0, client_ip_octet);
                        let client_ip_v6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, client_ip_octet as u16);

                        let (peer_stats_tx, peer_stats_rx) = if let Some(token) = &client_token_found {
                            let mut lock = udp_client_stats.write().await;
                            let entry = lock.entry(token.clone()).or_insert_with(|| (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0))));
                            (Some(entry.0.clone()), Some(entry.1.clone()))
                        } else {
                            (None, None)
                        };

                        let (tx, rx) = async_channel::bounded::<Bytes>(16384);
                        let socket_sender = socket_udp_send.clone();
                        let tx_metric = udp_tx_metric.clone();
                        let tx_stats_inner = peer_stats_tx.clone();
                        
                        tokio::spawn(async move {
                            let rx = rx;
                            while let Ok(packet) = rx.recv().await {
                                if socket_sender.send_to(&packet, addr).await.is_ok() {
                                    tx_metric.fetch_add(packet.len() as u64, Ordering::Relaxed);
                                    if let Some(tx) = &tx_stats_inner {
                                        tx.fetch_add(packet.len() as u64, Ordering::Relaxed);
                                    }
                                }
                            }
                        });

                        let last_seen = Arc::new(AtomicU64::new(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()));

                        {
                            let mut lock = peers_recv.write().await;
                            lock.insert(addr, Peer { 
                                _tx: tx.clone(), 
                                last_seen, 
                                client_token: client_token_found.clone(),
                                ipv4: client_ip,
                                ipv6: client_ip_v6,
                                _stats_tx: peer_stats_tx,
                                stats_rx: peer_stats_rx,
                            });
                        }

                        {
                            let mut lock = ip_map_recv.write().await;
                            lock.insert(IpAddr::V4(client_ip), tx.clone());
                            lock.insert(IpAddr::V6(client_ip_v6), tx.clone());
                        }
                        println!("Новый клиент: {} -> {}", addr, client_ip);

                        // Response: [0x02 | ipv4 | ipv6]
                        let mut response = Vec::with_capacity(1 + 4 + 16);
                        response.push(0x02);
                        response.extend_from_slice(&client_ip.octets());
                        response.extend_from_slice(&client_ip_v6.octets());

                        if socket_recv.send_to(&response, addr).await.is_ok() {
                            udp_tx_metric.fetch_add(response.len() as u64, Ordering::Relaxed);
                        }
                    }
                }
            });
        }

        let mut buf = vec![0u8; 65536];
        loop {
            match socket_recv.recv_from(&mut buf).await {
                Ok((len, addr)) => {
                    let packet = BytesMut::from(&buf[..len]);
                    if tx_pkt.send((packet, addr)).await.is_err() { break; }
                },
                Err(e) => {
                    error!("UDP Recv Error: {}", e);
                    udp_err_metric.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    });

    let ip_map_tcp = ip_map.clone();
    let tcp_config = app_config.clone();
    let next_ip_tcp = next_ip.clone();
    let tcp_rx_metric = total_rx.clone();
    let tcp_tx_metric = total_tx.clone();
    let tcp_err_metric = total_err.clone();
    let tcp_allowlist = client_allowlist.clone();
    let tcp_client_stats = client_stats.clone();

        tokio::spawn(async move {
        let auth_token = tcp_config.security.auth_token.as_bytes().to_vec();
        
        loop {
            let (stream, addr) = match tcp_listener.accept().await {
                Ok(v) => v,
                Err(_) => continue,
            };
            stream.set_nodelay(true).ok();
            debug!("TCP подключение: {}", addr);
            
            let tun_tx_tcp = tun_tx.clone();
            let ip_map = ip_map_tcp.clone();
            let auth_token = auth_token.clone();
            let next_ip = next_ip_tcp.clone();
            let rx_m = tcp_rx_metric.clone();
            let tx_m = tcp_tx_metric.clone();
            let _err_m = tcp_err_metric.clone();
            let allowlist = tcp_allowlist.clone();
            let client_stats = tcp_client_stats.clone();

            tokio::spawn(async move {
                let mut stream = stream;
                // Read handshake frame: [len(2) | 0x01 | token_len | token]
                let mut len_buf = [0u8; 2];
                if stream.read_exact(&mut len_buf).await.is_err() { return; }
                let len = u16::from_be_bytes(len_buf) as usize;
                
                let mut buf = vec![0u8; len];
                if stream.read_exact(&mut buf).await.is_err() { return; }
                rx_m.fetch_add((2 + len) as u64, Ordering::Relaxed);

                if len < 2 || buf[0] != 0x01 { return; }
                let token_len = buf[1] as usize;
                if len < 2 + token_len { return; }
                
                let token_sent = &buf[2..2+token_len];
                let mut client_token_found = None;

                if token_sent != auth_token.as_slice() {
                    let lock = allowlist.read().await;
                    if let Some(token_str) = std::str::from_utf8(token_sent).ok() {
                        if lock.contains_key(token_str) {
                            client_token_found = Some(token_str.to_string());
                        }
                    }
                    if client_token_found.is_none() {
                        warn!("Auth failed (TCP): Invalid token from {}", addr);
                        return;
                    }
                }

                let client_ip_octet = {
                    let mut ip = next_ip.lock().unwrap();
                    let val = *ip;
                    *ip = if val >= 253 { 2 } else { val + 1 };
                    val
                };
                let client_ip = Ipv4Addr::new(10, 0, 0, client_ip_octet);
                let client_ip_v6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, client_ip_octet as u16);

                // Response: [len(2) | 0x02 | ipv4 | ipv6]
                let mut response = Vec::with_capacity(1 + 4 + 16);
                response.push(0x02);
                response.extend_from_slice(&client_ip.octets());
                response.extend_from_slice(&client_ip_v6.octets());
                
                let mut combined = Vec::with_capacity(2 + response.len());
                combined.extend_from_slice(&(response.len() as u16).to_be_bytes());
                combined.extend_from_slice(&response);
                if stream.write_all(&combined).await.is_err() { return; }
                tx_m.fetch_add(combined.len() as u64, Ordering::Relaxed);

                if let Some(token) = &client_token_found {
                    let mut lock = client_stats.write().await;
                    if !lock.contains_key(token) {
                        lock.insert(token.clone(), (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0))));
                    }
                }

                let (peer_stats_tx, peer_stats_rx) = if let Some(token) = &client_token_found {
                    let lock = client_stats.read().await;
                    if let Some((tx, rx)) = lock.get(token) {
                        (Some(tx.clone()), Some(rx.clone()))
                    } else { (None, None) }
                } else { (None, None) };

                let (tx, rx) = async_channel::bounded::<Bytes>(8192);
                {
                    let mut lock = ip_map.write().await;
                    lock.insert(IpAddr::V4(client_ip), tx.clone());
                    lock.insert(IpAddr::V6(client_ip_v6), tx.clone());
                }
                info!("TCP клиент подключен: {} -> {}", addr, client_ip);

                let (mut read_half, write_half) = stream.into_split();
                let tx_m_inner = tx_m.clone();
                let rx_m_inner = rx_m.clone();
                let tx_stats_inner = peer_stats_tx.clone();
                let rx_stats_inner = peer_stats_rx.clone();

                let t_write = tokio::spawn(async move {
                    let rx = rx;
                    let mut write_half = write_half;
                    let mut combined_buf = BytesMut::with_capacity(2048);
                    
                    while let Ok(packet) = rx.recv().await {
                        combined_buf.clear();
                        combined_buf.put_u16(packet.len() as u16);
                        combined_buf.put_slice(&packet);

                        if write_half.write_all(&combined_buf).await.is_err() { break; }
                        tx_m_inner.fetch_add((2 + packet.len()) as u64, Ordering::Relaxed);
                        if let Some(tx) = &tx_stats_inner {
                            tx.fetch_add((2 + packet.len()) as u64, Ordering::Relaxed);
                        }
                    }
                });

                let mut buf = BytesMut::with_capacity(65536);
                loop {
                    let mut hdr = [0u8; 5];
                    if read_half.read_exact(&mut hdr[..2]).await.is_err() { break; }
                    let len = u16::from_be_bytes([hdr[0], hdr[1]]) as usize;

                    if buf.capacity() < len { buf.reserve(len); }
                    buf.resize(len, 0);
                    if read_half.read_exact(&mut buf).await.is_err() { break; }

                    rx_m_inner.fetch_add((2 + len) as u64, Ordering::Relaxed);
                    if let Some(rx) = &rx_stats_inner {
                        rx.fetch_add((2 + len) as u64, Ordering::Relaxed);
                    }

                    let data = Bytes::copy_from_slice(&buf);
                    let _ = tun_tx_tcp.send(data).await;
                }

                t_write.abort();
                {
                    let mut lock = ip_map.write().await;
                    lock.remove(&IpAddr::V4(client_ip));
                    lock.remove(&IpAddr::V6(client_ip_v6));
                }
                info!("TCP клиент отключен: {}", client_ip);
            });
        }
    });

    let mut buf = BytesMut::with_capacity(65536);
    loop {
        buf.reserve(65536);
        let n = match tun_reader.read_buf(&mut buf).await {
            Ok(n) if n > 0 => n,
            _ => break,
        };

        let packet = buf.split_to(n);

        if n < 20 { continue; }
        
        let dst_ip = match packet[0] >> 4 {
            4 => IpAddr::V4(Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19])),
            6 => {
                if n < 40 { continue; }
                let addr_bytes: [u8; 16] = packet[24..40].try_into().unwrap_or([0; 16]);
                IpAddr::V6(Ipv6Addr::from(addr_bytes))
            },
            _ => continue,
        };

        let target_tx = {
            let lock = ip_map.read().await;
            lock.get(&dst_ip).cloned()
        };

        if let Some(tx) = target_tx {
            let _ = tx.send(packet.freeze()).await;
        }
    }

    Ok(())
}