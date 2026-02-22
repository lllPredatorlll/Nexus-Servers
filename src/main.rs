use anyhow::Result;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UdpSocket, TcpListener};
use tokio::sync::RwLock;
use chacha20poly1305::aead::{Aead, AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::{RngCore, rngs::{OsRng, StdRng}, SeedableRng};
use x25519_dalek::{EphemeralSecret, PublicKey};
use log::{info, error, warn, debug};
use flexi_logger::{Logger, FileSpec, Criterion, Naming, Cleanup, Duplicate};
use tun::Configuration;
use serde::{Serialize, Deserialize};
use socket2::{Socket, Domain, Type, Protocol};
use bytes::{Bytes, BytesMut, BufMut};

mod utils;
mod config;


const VERSION: &str = "0.9.001 dev";

struct FecGroup {
    parity: Option<Bytes>,
    packets: HashMap<u32, Bytes>,
    received_count: usize,
    created_at: std::time::Instant,
}

struct FecReconstructor {
    active_groups: HashMap<u32, FecGroup>,
    last_cleanup: std::time::Instant,
}

impl FecReconstructor {
    fn new() -> Self {
        Self { 
            active_groups: HashMap::new(),
            last_cleanup: std::time::Instant::now(),
        }
    }

    fn on_packet(&mut self, seq: u32, data: Bytes) -> Option<Vec<u8>> {
        self.cleanup();
        let group_seq = if seq > 0 { ((seq - 1) / 20) * 20 + 1 } else { 0 };
        
        let group = self.active_groups.entry(group_seq).or_insert_with(|| FecGroup { 
            parity: None, 
            packets: HashMap::new(), 
            received_count: 0,
            created_at: std::time::Instant::now() 
        });

        if !group.packets.contains_key(&seq) {
            group.packets.insert(seq, data);
            group.received_count += 1;
        }
        self.try_recover(group_seq)
    }

     fn on_parity(&mut self, group_seq: u32, parity: Bytes) -> Option<Vec<u8>> {
        self.cleanup();

        let group = self.active_groups.entry(group_seq).or_insert_with(|| FecGroup { 
            parity: None, 
            packets: HashMap::new(), 
            received_count: 0,
            created_at: std::time::Instant::now() 
        });
        group.parity = Some(parity);
        self.try_recover(group_seq)
    }

    fn try_recover(&mut self, group_seq: u32) -> Option<Vec<u8>> {
        let group = self.active_groups.get_mut(&group_seq)?;
        let k = 20;
        if group.received_count == k { self.active_groups.remove(&group_seq); return None; }

        if group.received_count == k - 1 && group.parity.is_some() {
            let mut recovered = group.parity.as_ref().unwrap().to_vec();
            for (_, pkt) in &group.packets {
                let len_bytes = (pkt.len() as u16).to_be_bytes();
                if recovered.len() < 2 { recovered.resize(2, 0); }
                recovered[0] ^= len_bytes[0]; recovered[1] ^= len_bytes[1];
                if recovered.len() < 2 + pkt.len() { recovered.resize(2 + pkt.len(), 0); }
                
                crate::utils::xor_bytes(&mut recovered[2..2+pkt.len()], pkt);
            }
            if recovered.len() < 2 { return None; }
            let rec_len = u16::from_be_bytes([recovered[0], recovered[1]]) as usize;
            if recovered.len() >= 2 + rec_len { self.active_groups.remove(&group_seq); return Some(recovered[2..2+rec_len].to_vec()); }
        }
        None
    }

    fn cleanup(&mut self) {
        let now = std::time::Instant::now();
        if now.duration_since(self.last_cleanup).as_secs() >= 1 {
            self.active_groups.retain(|_, group| now.duration_since(group.created_at).as_secs() < 2);
            self.last_cleanup = now;
        }
    }
}

struct ShardedFecReconstructor {
    shards: Vec<Mutex<FecReconstructor>>,
    mask: usize,
}

impl ShardedFecReconstructor {
    fn new() -> Self {
        let parallelism = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
        let count = parallelism.next_power_of_two();
        let mut shards = Vec::with_capacity(count);
        for _ in 0..count {
            shards.push(Mutex::new(FecReconstructor::new()));
        }
        Self { shards, mask: count - 1 }
    }

    fn on_packet(&self, seq: u32, data: Bytes) -> Option<Vec<u8>> {
        let group_idx = if seq > 0 { (seq - 1) / 20 } else { 0 };
        let idx = (group_idx as usize) & self.mask;
        self.shards[idx].lock().unwrap().on_packet(seq, data)
    }

    fn on_parity(&self, group_seq: u32, parity: Bytes) -> Option<Vec<u8>> {
        let group_idx = if group_seq > 0 { (group_seq - 1) / 20 } else { 0 };
        let idx = (group_idx as usize) & self.mask;
        self.shards[idx].lock().unwrap().on_parity(group_seq, parity)
    }
}

struct Peer {
    cipher: ChaCha20Poly1305,
    _tx: async_channel::Sender<Bytes>,
    last_seen: Arc<AtomicU64>,
    client_token: Option<String>,
    ipv4: Ipv4Addr,
    ipv6: Ipv6Addr,
    _stats_tx: Option<Arc<AtomicU64>>,
    stats_rx: Option<Arc<AtomicU64>>,
    fec: Arc<ShardedFecReconstructor>,
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
    let obf_key: Arc<Vec<u8>> = Arc::new(udp_config.security.psk.as_bytes().iter().cycle().take(4096).cloned().collect());

    let num_workers = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    let (_udp_tx_dispatch, _) = tokio::sync::broadcast::channel::<()>(1);

    tokio::spawn(async move {
        let (tx_pkt, rx_pkt) = async_channel::bounded::<(BytesMut, SocketAddr)>(16384);

        let psk = udp_config.security.psk.as_bytes();
        let handshake_cipher_base = match ChaCha20Poly1305::new_from_slice(psk) {
            Ok(c) => c,
            Err(e) => {
                error!("UDP Task Error: Invalid PSK length: {}", e);
                return;
            }
        };
        let auth_token = udp_config.security.auth_token.as_bytes();

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
            let handshake_cipher = handshake_cipher_base.clone();
            let auth_token = auth_token.to_vec();
            let obf_key = obf_key.clone();

            tokio::spawn(async move {
                let mut rng = StdRng::from_entropy();
                while let Ok((mut buf, addr)) = rx_pkt.recv().await {
                    let len = buf.len();
                    utils::xor_bytes(&mut buf, &obf_key);
                    udp_rx_metric.fetch_add(len as u64, Ordering::Relaxed);
                    if len < 28 { continue; }

                    let (peer_cipher, _peer_token, peer_stats_rx, peer_last_seen, peer_fec) = {
                        let lock = peers_recv.read().await;
                        if let Some(p) = lock.get(&addr) {
                            (Some(p.cipher.clone()), p.client_token.clone(), p.stats_rx.clone(), Some(p.last_seen.clone()), Some(p.fec.clone()))
                        } else {
                            (None, None, None, None, None)
                        }
                    };

                    if let Some(rx) = &peer_stats_rx {
                        rx.fetch_add(len as u64, Ordering::Relaxed);
                    }
                    if let Some(ls) = peer_last_seen {
                        ls.store(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(), Ordering::Relaxed);
                    }

                    let mut decrypted_data = Vec::new();
                    let mut is_handshake = false;

                    if let Some(ref cipher) = peer_cipher {
                        let mut nonce_arr = [0u8; 12];
                        nonce_arr.copy_from_slice(&buf[..12]);
                        let nonce = Nonce::from_slice(&nonce_arr);

                        let ciphertext_len = len - 12;
                        let data_len = ciphertext_len - 16;
                        
                        let mut tag_arr = [0u8; 16];
                        tag_arr.copy_from_slice(&buf[len-16..len]);
                        let tag = chacha20poly1305::Tag::from_slice(&tag_arr);
                        
                        if cipher.decrypt_in_place_detached(nonce, &[], &mut buf[12..12+data_len], tag).is_ok() {
                            let pad_len = buf[12] as usize;
                            
                            if pad_len == 254 {
                                if let Some(fec_lock) = peer_fec {
                                    if data_len > 5 {
                                        let mut seq_bytes = [0u8; 4];
                                        seq_bytes.copy_from_slice(&buf[13..17]);
                                        let group_seq = u32::from_be_bytes(seq_bytes);
                                        let parity_data = &buf[17..12+data_len];
                                        let parity_bytes = Bytes::copy_from_slice(parity_data);
                                        
                                        let recovered_opt = fec_lock.on_parity(group_seq, parity_bytes);
                                        if let Some(recovered) = recovered_opt {
                                            let _ = tun_tx_udp.send(Bytes::from(recovered)).await;
                                            debug!("FEC: Восстановлен пакет в группе {}", group_seq);
                                        }
                                    }
                                }
                                continue; 
                            }

                            if data_len > 1 + 4 + pad_len {
                                let mut seq_bytes = [0u8; 4];
                                seq_bytes.copy_from_slice(&buf[13..17]);
                                let seq = u32::from_be_bytes(seq_bytes);
                                let data = &buf[17 .. 12 + data_len - pad_len];
                                let data_bytes = Bytes::copy_from_slice(data);
                                
                                let _ = tun_tx_udp.send(data_bytes.clone()).await;
                                
                                if let Some(fec_lock) = peer_fec {
                                    let recovered_opt = fec_lock.on_packet(seq, data_bytes);
                                    if let Some(recovered) = recovered_opt {
                                        let _ = tun_tx_udp.send(Bytes::from(recovered)).await;
                                        debug!("FEC: Восстановлен пакет {} (позднее прибытие)", seq);
                                    }
                                }
                                continue;
                            } else {
                                decrypted_data = buf[12..12+data_len].to_vec();
                            }
                        }
                    }

                    if decrypted_data.is_empty() {
                        let nonce = Nonce::from_slice(&buf[..12]);
                        if let Ok(plaintext) = handshake_cipher.decrypt(nonce, &buf[12..len]) {
                            if plaintext.len() >= 32 {
                                is_handshake = true;
                                decrypted_data = plaintext;
                            }
                        }
                    }

                    if decrypted_data.is_empty() { continue; }

                    if is_handshake {
                        if decrypted_data.len() < 33 { continue; }
                        let token_len = decrypted_data[32] as usize;
                        if decrypted_data.len() < 33 + token_len { continue; }
                        
                        let token_sent = &decrypted_data[33..33+token_len];
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

                        let mut client_pub_bytes = [0u8; 32];
                        client_pub_bytes.copy_from_slice(&decrypted_data[..32]);
                        let client_public = PublicKey::from(client_pub_bytes);

                        let server_secret = EphemeralSecret::random_from_rng(OsRng);
                        let server_public = PublicKey::from(&server_secret);
                        let shared_secret = server_secret.diffie_hellman(&client_public);
                        
                        let session_key = shared_secret.as_bytes();
                        let session_cipher = ChaCha20Poly1305::new(session_key.into());

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
                        let cipher_sender = session_cipher.clone();
                        let tx_metric = udp_tx_metric.clone();
                        let tx_stats_inner = peer_stats_tx.clone();
                        let obf_key_sender = obf_key.clone();
                        
                        tokio::spawn(async move {
                            let rx = rx;
                            let mut rng = StdRng::from_entropy();
                            let mut final_pkt = BytesMut::with_capacity(2048);
                            
                            let mut nonce_salt = [0u8; 4];
                            rng.fill_bytes(&mut nonce_salt);
                            let mut seq: u64 = 0;

                            while let Ok(packet) = rx.recv().await {
                                let payload_len = 1 + packet.len();
                                let pad_len = (16 - (payload_len % 16)) % 16;

                                seq = seq.wrapping_add(1);
                                let mut nonce_bytes = [0u8; 12];
                                nonce_bytes[..4].copy_from_slice(&nonce_salt);
                                nonce_bytes[4..].copy_from_slice(&seq.to_be_bytes());
                                let nonce = Nonce::from_slice(&nonce_bytes);

                                let total_len = 12 + 1 + packet.len() + pad_len + 16;
                                final_pkt.clear();
                                final_pkt.reserve(total_len);
                                
                                final_pkt.put_slice(&nonce_bytes);
                                final_pkt.put_u8(pad_len as u8);
                                final_pkt.put_slice(&packet);
                                final_pkt.put_bytes(0, pad_len);

                                if let Ok(tag) = cipher_sender.encrypt_in_place_detached(nonce, &[], &mut final_pkt[12..]) {
                                    final_pkt.put_slice(tag.as_slice());
                                    utils::xor_bytes(&mut final_pkt, &obf_key_sender);
                                    if socket_sender.send_to(&final_pkt, addr).await.is_ok() {
                                        tx_metric.fetch_add(final_pkt.len() as u64, Ordering::Relaxed);
                                        if let Some(tx) = &tx_stats_inner {
                                            tx.fetch_add(final_pkt.len() as u64, Ordering::Relaxed);
                                        }
                                    }
                                }
                            }
                        });

                        let last_seen = Arc::new(AtomicU64::new(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()));

                        {
                            let mut lock = peers_recv.write().await;
                            lock.insert(addr, Peer { 
                                cipher: session_cipher, 
                                _tx: tx.clone(), 
                                last_seen, 
                                client_token: client_token_found.clone(),
                                ipv4: client_ip,
                                ipv6: client_ip_v6,
                                _stats_tx: peer_stats_tx,
                                stats_rx: peer_stats_rx,
                        fec: Arc::new(ShardedFecReconstructor::new())
                            });
                        }

                        {
                            let mut lock = ip_map_recv.write().await;
                            lock.insert(IpAddr::V4(client_ip), tx.clone());
                            lock.insert(IpAddr::V6(client_ip_v6), tx.clone());
                        }
                        println!("Новый клиент: {} -> {}", addr, client_ip);

                        let mut nonce_bytes = [0u8; 12];
                        OsRng.fill_bytes(&mut nonce_bytes);
                        let nonce = Nonce::from_slice(&nonce_bytes);

                        let mut payload = Vec::with_capacity(70);
                        payload.extend_from_slice(server_public.as_bytes());
                        payload.extend_from_slice(&client_ip.octets());
                        payload.extend_from_slice(&client_ip_v6.octets());
                        payload.resize(64, 0);
                        OsRng.fill_bytes(&mut payload[52..]);

                        if let Ok(encrypted) = handshake_cipher.encrypt(nonce, payload.as_slice()) {
                            let mut packet = Vec::with_capacity(12 + encrypted.len());
                            packet.extend_from_slice(&nonce_bytes);
                            packet.extend_from_slice(&encrypted);
                            utils::xor_bytes(&mut packet, &obf_key);
                            if socket_recv.send_to(&packet, addr).await.is_ok() {
                                udp_tx_metric.fetch_add(packet.len() as u64, Ordering::Relaxed);
                            }
                        }

                    } else {
                        let pad_len = decrypted_data[0] as usize;
                        if decrypted_data.len() <= 1 + pad_len { 
                            if let Some(cipher) = peer_cipher {
                                let mut rand_buf = [0u8; 32];
                                rng.fill_bytes(&mut rand_buf);

                                let resp_pad_len = 15;
                                let nonce_bytes = &rand_buf[0..12];
                                let nonce = Nonce::from_slice(nonce_bytes);
                                let padding_bytes = &rand_buf[12..12+resp_pad_len];

                                let total_len = 12 + 1 + 0 + resp_pad_len + 16;
                                let mut final_pkt = Vec::with_capacity(total_len);
                                
                                final_pkt.extend_from_slice(nonce_bytes);
                                final_pkt.push(resp_pad_len as u8);
                                final_pkt.extend_from_slice(padding_bytes);

                                if let Ok(tag) = cipher.encrypt_in_place_detached(nonce, &[], &mut final_pkt[12..]) {
                                    final_pkt.extend_from_slice(tag.as_slice());
                                    utils::xor_bytes(&mut final_pkt, &obf_key);
                                    let _ = socket_udp_send.send_to(&final_pkt, addr).await;
                                }
                            }
                            continue; 
                        }
                        let data = &decrypted_data[1..decrypted_data.len() - pad_len]; 

                        {
                            let _ = tun_tx_udp.send(Bytes::copy_from_slice(data)).await;
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
        let psk = tcp_config.security.psk.as_bytes();
        let handshake_cipher = match ChaCha20Poly1305::new_from_slice(psk) {
            Ok(c) => c,
            Err(e) => {
                error!("TCP Task Error: Invalid PSK length: {}", e);
                return;
            }
        };
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
            let handshake_cipher = handshake_cipher.clone();
            let auth_token = auth_token.clone();
            let next_ip = next_ip_tcp.clone();
            let rx_m = tcp_rx_metric.clone();
            let tx_m = tcp_tx_metric.clone();
            let _err_m = tcp_err_metric.clone();
            let allowlist = tcp_allowlist.clone();
            let client_stats = tcp_client_stats.clone();

            tokio::spawn(async move {
                let mut stream = stream;
                let mut first_byte = [0u8; 1];
                if stream.read_exact(&mut first_byte).await.is_err() { return; }

                if first_byte[0] != 0x16 { return; }

                let mut header = [0u8; 4];
                if stream.read_exact(&mut header).await.is_err() { return; }
                let ch_len = u16::from_be_bytes([header[2], header[3]]) as usize;
                let mut ch_buf = vec![0u8; ch_len];
                if stream.read_exact(&mut ch_buf).await.is_err() { return; }

                let mut rng = StdRng::from_entropy();
                let mut rand_bytes = [0u8; 32];
                rng.fill_bytes(&mut rand_bytes);
                let mut session_id = [0u8; 32];
                rng.fill_bytes(&mut session_id);

                let mut sh_payload = Vec::new();
                sh_payload.extend_from_slice(&[0x03, 0x03]);
                sh_payload.extend_from_slice(&rand_bytes);
                sh_payload.push(32);
                sh_payload.extend_from_slice(&session_id);
                sh_payload.extend_from_slice(&[0x13, 0x01]);
                sh_payload.push(0x00);
                sh_payload.extend_from_slice(&[0x00, 0x00]);

                let mut sh_record = Vec::new();
                sh_record.push(0x16);
                sh_record.extend_from_slice(&[0x03, 0x03]);
                sh_record.extend_from_slice(&(4 + sh_payload.len() as u16).to_be_bytes());
                sh_record.push(0x02);
                sh_record.extend_from_slice(&(sh_payload.len() as u32).to_be_bytes()[1..4]);
                sh_record.extend_from_slice(&sh_payload);

                let ccs = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
                let mut fake_fin = vec![0x17, 0x03, 0x03, 0x00, 0x20];
                let mut fin_payload = [0u8; 32];
                rng.fill_bytes(&mut fin_payload);
                fake_fin.extend_from_slice(&fin_payload);

                stream.write_all(&sh_record).await.ok();
                stream.write_all(&ccs).await.ok();
                stream.write_all(&fake_fin).await.ok();

                let mut buf = [0u8; 1024];
                let mut hdr = [0u8; 5];
                if stream.read_exact(&mut hdr).await.is_ok() && hdr[0] == 0x14 {
                    let l = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                    if l <= buf.len() { stream.read_exact(&mut buf[..l]).await.ok(); }
                    if stream.read_exact(&mut hdr).await.is_ok() && hdr[0] == 0x17 {
                        let l = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                        if l <= buf.len() { stream.read_exact(&mut buf[..l]).await.ok(); }
                    }
                }

                if stream.read_exact(&mut hdr).await.is_err() { return; }
                if hdr[0] != 0x17 { return; }
                let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;

                let mut buf = vec![0u8; len];
                if stream.read_exact(&mut buf).await.is_err() { return; }
                rx_m.fetch_add((2 + len) as u64, Ordering::Relaxed);

                if len < 12 { return; }
                let nonce = Nonce::from_slice(&buf[..12]);
                let decrypted = match handshake_cipher.decrypt(nonce, &buf[12..]) {
                    Ok(d) => d,
                    Err(_) => return,
                };
                
                if decrypted.len() < 33 { return; }
                let token_len = decrypted[32] as usize;
                if decrypted.len() < 33 + token_len { return; }
                
                let token_sent = &decrypted[33..33+token_len];
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

                let mut client_pub_bytes = [0u8; 32];
                client_pub_bytes.copy_from_slice(&decrypted[..32]);
                let client_public = PublicKey::from(client_pub_bytes);

                let server_secret = EphemeralSecret::random_from_rng(OsRng);
                let server_public = PublicKey::from(&server_secret);
                let shared_secret = server_secret.diffie_hellman(&client_public);
                let session_key = shared_secret.as_bytes();
                let session_cipher = ChaCha20Poly1305::new(session_key.into());

                let client_ip_octet = {
                    let mut ip = next_ip.lock().unwrap();
                    let val = *ip;
                    *ip = if val >= 253 { 2 } else { val + 1 };
                    val
                };
                let client_ip = Ipv4Addr::new(10, 0, 0, client_ip_octet);
                let client_ip_v6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, client_ip_octet as u16);

                let mut nonce_bytes = [0u8; 12];
                OsRng.fill_bytes(&mut nonce_bytes);
                let nonce = Nonce::from_slice(&nonce_bytes);

                let mut payload = Vec::with_capacity(70);
                payload.extend_from_slice(server_public.as_bytes());
                payload.extend_from_slice(&client_ip.octets());
                payload.extend_from_slice(&client_ip_v6.octets());
                payload.resize(64, 0);
                OsRng.fill_bytes(&mut payload[52..]);

                if let Ok(encrypted) = handshake_cipher.encrypt(nonce, payload.as_slice()) {
                    let mut packet = Vec::with_capacity(12 + encrypted.len());
                    packet.extend_from_slice(&nonce_bytes);
                    packet.extend_from_slice(&encrypted);
                    
                    let mut combined = Vec::with_capacity(2 + packet.len());
                    combined.extend_from_slice(&(packet.len() as u16).to_be_bytes());
                    combined.extend_from_slice(&packet);
                    if stream.write_all(&combined).await.is_err() { return; }
                    tx_m.fetch_add((2 + packet.len()) as u64, Ordering::Relaxed);
                }

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
                let cipher_enc = session_cipher.clone();
                let cipher_dec = session_cipher.clone();
                let tx_m_inner = tx_m.clone();
                let rx_m_inner = rx_m.clone();
                let tx_echo = tx.clone();
                let tx_stats_inner = peer_stats_tx.clone();
                let rx_stats_inner = peer_stats_rx.clone();

                let t_write = tokio::spawn(async move {
                    let rx = rx;
                    let mut write_half = write_half;
                    let mut combined_buf = BytesMut::with_capacity(2048);
                    let mut rng = StdRng::from_entropy();
                    
                    let mut nonce_salt = [0u8; 4];
                    rng.fill_bytes(&mut nonce_salt);
                    let mut seq: u64 = 0;

                    while let Ok(packet) = rx.recv().await {
                        let payload_len = 1 + packet.len();
                        let pad_len = (16 - (payload_len % 16)) % 16;

                        seq = seq.wrapping_add(1);
                        let mut nonce_bytes = [0u8; 12];
                        nonce_bytes[..4].copy_from_slice(&nonce_salt);
                        nonce_bytes[4..].copy_from_slice(&seq.to_be_bytes());
                        let nonce = Nonce::from_slice(&nonce_bytes);

                        let total_len = 12 + 1 + packet.len() + pad_len + 16;
                        let mut final_pkt = BytesMut::with_capacity(total_len);
                        
                        final_pkt.put_slice(&nonce_bytes);
                        final_pkt.put_u8(pad_len as u8);
                        final_pkt.put_slice(&packet);
                        final_pkt.put_bytes(0, pad_len);

                        if let Ok(tag) = cipher_enc.encrypt_in_place_detached(nonce, &[], &mut final_pkt[12..]) {
                            final_pkt.put_slice(tag.as_slice());
                            
                            combined_buf.clear();
                            combined_buf.put_u8(0x17);
                            combined_buf.put_slice(&[0x03, 0x03]);
                            combined_buf.put_u16(final_pkt.len() as u16);
                            combined_buf.put_slice(&final_pkt);

                            if write_half.write_all(&combined_buf).await.is_err() { break; }
                            tx_m_inner.fetch_add((2 + final_pkt.len()) as u64, Ordering::Relaxed);
                            if let Some(tx) = &tx_stats_inner {
                                tx.fetch_add((2 + final_pkt.len()) as u64, Ordering::Relaxed);
                            }
                        }
                    }
                });

                let mut buf = BytesMut::with_capacity(65536);
                loop {
                    let mut hdr = [0u8; 5];
                    if read_half.read_exact(&mut hdr).await.is_err() { break; }
                    if hdr[0] != 0x17 { break; }
                    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;

                    if buf.capacity() < len { buf.reserve(len); }
                    buf.resize(len, 0);
                    if read_half.read_exact(&mut buf).await.is_err() { break; }

                    rx_m_inner.fetch_add((2 + len) as u64, Ordering::Relaxed);
                    if let Some(rx) = &rx_stats_inner {
                        rx.fetch_add((2 + len) as u64, Ordering::Relaxed);
                    }

                    if len < 28 { continue; }
                    let nonce = Nonce::from_slice(&buf[..12]);
                    if let Ok(plaintext) = cipher_dec.decrypt(nonce, &buf[12..]) {
                        if plaintext.is_empty() { continue; }
                        let pad_len = plaintext[0] as usize;
                        if plaintext.len() <= 1 + 4 + pad_len {
                            let _ = tx_echo.send(Bytes::new()).await; 
                            continue; 
                        }
                        let data = &plaintext[5..plaintext.len() - pad_len];

                        {
                            let _ = tun_tx_tcp.send(Bytes::copy_from_slice(data)).await;
                        }
                    }
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