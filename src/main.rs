use anyhow::Result;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UdpSocket, TcpListener};
use tokio::sync::RwLock;
use log::{info, error};
use flexi_logger::{Logger, FileSpec, Criterion, Naming, Cleanup, Duplicate};
use tun::Configuration;
use serde::{Serialize, Deserialize};
use socket2::{Socket, Domain, Type, Protocol};
use bytes::{Bytes, BytesMut};
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{StaticSecret, PublicKey};

mod config;


const VERSION: &str = "0.9.003 dev";

struct Peer {
    tunn: Mutex<Tunn>,
    last_seen: AtomicU64,
    endpoint: SocketAddr,
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
        let _ = std::process::Command::new("ip")
            .args(&["link", "set", "dev", "nexus0", "txqueuelen", "1000"])
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
    
    let _tcp_listener = TcpListener::bind(&app_config.net.endpoint).await?;
    info!("Nexus Server listening on UDP & TCP {}", app_config.net.endpoint);

    let peers: Arc<RwLock<HashMap<SocketAddr, Arc<Peer>>>> = Arc::new(RwLock::new(HashMap::new()));
    let ip_map: Arc<RwLock<HashMap<IpAddr, Arc<Peer>>>> = Arc::new(RwLock::new(HashMap::new()));
    
    // Map derived Public Key -> Client Name
    let client_allowlist: Arc<RwLock<HashMap<PublicKey, String>>> = Arc::new(RwLock::new(HashMap::new()));
    let client_stats: Arc<RwLock<HashMap<String, (Arc<AtomicU64>, Arc<AtomicU64>)>>> = Arc::new(RwLock::new(HashMap::new()));


    let total_tx = Arc::new(AtomicU64::new(0));
    let total_rx = Arc::new(AtomicU64::new(0));
    let total_err = Arc::new(AtomicU64::new(0));

    let allowlist_reloader = client_allowlist.clone();
    let stats_saver = client_stats.clone();
    let config_reloader = app_config.clone();

    tokio::spawn(async move {
        loop {
            {
                let mut lock: tokio::sync::RwLockWriteGuard<HashMap<PublicKey, String>> = allowlist_reloader.write().await;
                lock.clear();

                // Всегда добавляем Админа (из server_config)
                let admin_key_bytes = blake3::hash(config_reloader.security.auth_token.as_bytes());
                let admin_private = StaticSecret::from(*admin_key_bytes.as_bytes());
                lock.insert(PublicKey::from(&admin_private), "admin".to_string());

                if let Ok(content) = tokio::fs::read_to_string("clients.toml").await {
                    if let Ok(config) = toml::from_str::<ClientsConfig>(&content) {
                        for client in config.clients {
                            let private_key_bytes = blake3::hash(client.token.as_bytes());
                            let private_key = StaticSecret::from(*private_key_bytes.as_bytes());
                            lock.insert(PublicKey::from(&private_key), client.name);
                        }
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
                        to_remove.push((*addr, Ipv4Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED)); // IP cleanup handled by map scan or weak refs ideally
                    }
                }
            }

            if !to_remove.is_empty() {
                let mut peers = peers_clean.write().await;
                let mut ip_map = ip_map_clean.write().await;
                
                for (addr, _, _) in to_remove {
                    peers.remove(&addr);
                    // Cleanup IP map (inefficient but safe)
                    let mut ips_to_remove = Vec::new();
                    for (ip, p) in ip_map.iter() {
                        if p.endpoint == addr {
                            ips_to_remove.push(*ip);
                        }
                    }
                    for ip in ips_to_remove { ip_map.remove(&ip); }
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
    let udp_rx_metric = total_rx.clone();
    let udp_tx_metric = total_tx.clone();
    let udp_err_metric = total_err.clone();
    let udp_allowlist = client_allowlist.clone();

    let server_private_key = {
        let key_bytes = blake3::hash(udp_config.security.wg_private_key.as_bytes());
        StaticSecret::from(*key_bytes.as_bytes())
    };

    let num_workers = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    let (_udp_tx_dispatch, _) = tokio::sync::broadcast::channel::<()>(1);

    tokio::spawn(async move {
        let (tx_pkt, rx_pkt) = async_channel::bounded::<(BytesMut, SocketAddr)>(16384);


        for _ in 0..num_workers {
            let rx_pkt = rx_pkt.clone();
            let peers_recv = peers_recv.clone();
            let ip_map_recv = ip_map_recv.clone();
            let _socket_recv = socket_recv.clone();
            let socket_udp_send = socket_udp_send.clone();
            let tun_tx_udp = tun_tx_udp.clone();
            let udp_rx_metric = udp_rx_metric.clone();
            let udp_tx_metric = udp_tx_metric.clone();
            let udp_allowlist = udp_allowlist.clone();
            let server_key = server_private_key.clone();
            let mut buf_tun = vec![0u8; 65535];

            tokio::spawn(async move {
                while let Ok((buf, addr)) = rx_pkt.recv().await {
                    let len = buf.len();
                    udp_rx_metric.fetch_add(len as u64, Ordering::Relaxed);
                    
                    let peer_opt = {
                        let lock = peers_recv.read().await;
                        lock.get(&addr).cloned()
                    };

                    if let Some(peer) = peer_opt {
                        // Existing peer
                        peer.last_seen.store(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(), Ordering::Relaxed);
                        
                        let result = {
                            let mut tunn = peer.tunn.lock().unwrap();
                            tunn.decapsulate(Some(addr.ip()), &buf, &mut buf_tun)
                        };

                        match result {
                            TunnResult::WriteToNetwork(b) => {
                                let _ = socket_udp_send.send_to(b, addr).await;
                                udp_tx_metric.fetch_add(b.len() as u64, Ordering::Relaxed);
                            },
                            TunnResult::WriteToTunnelV4(b, _) | TunnResult::WriteToTunnelV6(b, _) => {
                                // Learn IP mapping
                                if b.len() > 20 {
                                    let src_ip = match b[0] >> 4 {
                                        4 => IpAddr::V4(Ipv4Addr::new(b[12], b[13], b[14], b[15])),
                                        6 => {
                                            let octets: [u8; 16] = b[8..24].try_into().unwrap_or([0; 16]);
                                            IpAddr::V6(Ipv6Addr::from(octets))
                                        },
                                        _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                                    };
                                    if !src_ip.is_unspecified() {
                                        let mut map = ip_map_recv.write().await;
                                        if !map.contains_key(&src_ip) {
                                            map.insert(src_ip, peer.clone());
                                            info!("Registered IP {} for peer {}", src_ip, addr);
                                        }
                                    }
                                }
                                let data = Bytes::copy_from_slice(b);
                                let _ = tun_tx_udp.send(data).await;
                            },
                            _ => {}
                        }
                    } else if buf.len() >= 148 && buf[0] == 1 {
                        // Handshake Initiation from unknown peer
                        // Try to identify by iterating allowed keys (inefficient but works for small scale)
                        let allowed_keys = {
                            let lock: tokio::sync::RwLockReadGuard<HashMap<PublicKey, String>> = udp_allowlist.read().await;
                            lock.keys().cloned().collect::<Vec<_>>()
                        };

                        let mut handshake_success = false;
                        for client_pub_key in allowed_keys {
                            let mut tunn = Tunn::new(server_key.clone(), client_pub_key, None, None, 0, None);
                            match tunn.decapsulate(Some(addr.ip()), &buf, &mut buf_tun) {
                                TunnResult::WriteToNetwork(b) => {
                                    // Handshake valid!
                                    let _ = socket_udp_send.send_to(b, addr).await;
                                    udp_tx_metric.fetch_add(b.len() as u64, Ordering::Relaxed);
                                    
                                    let peer = Arc::new(Peer {
                                        tunn: Mutex::new(tunn),
                                        last_seen: AtomicU64::new(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()),
                                        endpoint: addr,
                                    });
                                    
                                    {
                                        let mut lock = peers_recv.write().await;
                                        lock.insert(addr, peer);
                                    }
                                    info!("New WireGuard peer authenticated: {}", addr);
                                    handshake_success = true;
                                    break;
                                },
                                _ => continue, // Try next key
                            }
                        }
                        if !handshake_success {
                            info!("Handshake failed from {}: No matching key found (Wrong Token?)", addr);
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

    // TCP Support for WireGuard over TCP (Stream)
    // This requires framing. BoringTun doesn't handle TCP framing natively.
    // For now, we disable TCP or need to implement a wrapper that feeds Tunn.
    // Given the complexity, we focus on UDP first as per standard WG.
    // If TCP is required, it needs a similar logic: Read frame -> Tunn.decapsulate -> Write frame.

    // TUN -> Network
    let mut buf_out = vec![0u8; 65535];

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

        let peer_opt = {
            let lock = ip_map.read().await;
            lock.get(&dst_ip).cloned()
        };

        if let Some(peer) = peer_opt {
            let mut tunn = peer.tunn.lock().unwrap();
            match tunn.encapsulate(&packet, &mut buf_out) {
                TunnResult::WriteToNetwork(b) => {
                    let _ = socket.send_to(b, peer.endpoint).await;
                    total_tx.fetch_add(b.len() as u64, Ordering::Relaxed);
                },
                _ => {}
            }
        }
    }

    Ok(())
}