#![allow(dead_code)]
use std::net::ToSocketAddrs;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use crate::config;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

#[cfg(feature = "client")]
pub fn get_config_path(_app_handle: &tauri::AppHandle) -> std::path::PathBuf {
    if let Ok(mut path) = std::env::current_exe() {
        path.pop();
        path.push("client_config.toml");
        return path;
    }
    std::path::PathBuf::from("client_config.toml")
}

#[cfg(feature = "client")]
pub fn load_merged_config(app_handle: &tauri::AppHandle, path: Option<&std::path::Path>) -> Result<config::Config, String> {
    let config_path = if let Some(p) = path {
        p.to_path_buf()
    } else {
        get_config_path(app_handle)
    };

    let mut config = config::load(config_path.to_str().unwrap_or("client_config.toml")).map_err(|e| e.to_string())?;

    let config_dir = get_config_path(app_handle).parent().unwrap_or(std::path::Path::new(".")).to_path_buf();
    let settings_path = config_dir.join("settings.toml");
    
    if settings_path.exists() {
        let content = std::fs::read_to_string(&settings_path).map_err(|e| e.to_string())?;
        #[derive(serde::Deserialize)]
        struct UiOnly { ui: config::UiConfig }
        if let Ok(ui_only) = toml::from_str::<UiOnly>(&content) {
            config.ui = ui_only.ui;
        }
    }
    Ok(config)
}

#[cfg(feature = "client")]
pub fn save_split_config(app_handle: &tauri::AppHandle, config: &config::Config, path: Option<&std::path::Path>, update_settings: bool) -> Result<(), String> {
    let config_dir = get_config_path(app_handle).parent().unwrap_or(std::path::Path::new(".")).to_path_buf();
    
    if update_settings {
        let settings_path = config_dir.join("settings.toml");
        #[derive(serde::Serialize)]
        struct UiOnly { ui: config::UiConfig }
        let ui_data = UiOnly { ui: config.ui.clone() };
        let ui_content = toml::to_string_pretty(&ui_data).map_err(|e| e.to_string())?;
        std::fs::write(settings_path, ui_content).map_err(|e| e.to_string())?;
    }

    let target_path = if let Some(p) = path { p.to_path_buf() } else { get_config_path(app_handle) };
    
    let mut config_val = toml::Value::try_from(config).map_err(|e| e.to_string())?;
    if let Some(table) = config_val.as_table_mut() {
        table.remove("ui");
    }
    
    let config_content = toml::to_string_pretty(&config_val).map_err(|e| e.to_string())?;
    std::fs::write(target_path, config_content).map_err(|e| e.to_string())?;

    Ok(())
}

#[cfg(feature = "client")]
#[tauri::command]
pub fn get_process_list() -> Result<Vec<String>, String> {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        let output = std::process::Command::new("tasklist")
            .args(&["/FO", "CSV", "/NH"])
            .creation_flags(0x08000000)
            .output()
            .map_err(|e| e.to_string())?;
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut processes = Vec::new();
        for line in stdout.lines() {
            if let Some(first_quote) = line.find('"') {
                if let Some(second_quote) = line[first_quote+1..].find('"') {
                    let name = &line[first_quote+1..first_quote+1+second_quote];
                    if !processes.contains(&name.to_string()) {
                        processes.push(name.to_string());
                    }
                }
            }
        }
        processes.sort();
        Ok(processes)
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(vec![])
    }
}

#[cfg(feature = "client")]
#[tauri::command]
pub async fn check_server_connection(ip: String) -> Result<String, String> {
    tokio::task::spawn_blocking(move || {
        let addr_str = format!("{}:22", ip);
        let socket_addr = addr_str.to_socket_addrs()
            .map_err(|e| format!("Ошибка адреса: {}", e))?
            .next()
            .ok_or("Некорректный IP")?;
        std::net::TcpStream::connect_timeout(&socket_addr, std::time::Duration::from_secs(3))
            .map_err(|e| format!("Сервер недоступен: {}", e))?;
        Ok("Сервер доступен (порт 22 открыт)".to_string())
    }).await.map_err(|e| e.to_string())?
}

#[cfg(feature = "client")]
#[tauri::command]
pub async fn ping_server(endpoint: String) -> Result<u128, String> {
    let start = std::time::Instant::now();
    let addr = if endpoint.contains(':') { endpoint.clone() } else { format!("{}:12345", endpoint) };
    
    match timeout(Duration::from_secs(2), TcpStream::connect(addr)).await {
        Ok(Ok(_)) => Ok(start.elapsed().as_millis()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("Timeout".to_string()),
    }
}

// SIMD-оптимизированная функция XOR (AVX2)
#[inline]
pub fn xor_bytes(dst: &mut [u8], src: &[u8]) {
    let len = std::cmp::min(dst.len(), src.len());
    let mut i = 0;

    #[cfg(target_arch = "x86_64")]
    if is_x86_feature_detected!("avx2") {
        unsafe {
            while i + 32 <= len {
                let d_ptr = dst.as_mut_ptr().add(i) as *mut __m256i;
                let s_ptr = src.as_ptr().add(i) as *const __m256i;
                // Используем unaligned load/store для безопасности
                let d_val = _mm256_loadu_si256(d_ptr);
                let s_val = _mm256_loadu_si256(s_ptr);
                let res = _mm256_xor_si256(d_val, s_val);
                _mm256_storeu_si256(d_ptr, res);
                i += 32;
            }
        }
    }

    while i + 8 <= len {
        let d_chunk = u64::from_ne_bytes(dst[i..i+8].try_into().unwrap());
        let s_chunk = u64::from_ne_bytes(src[i..i+8].try_into().unwrap());
        let res = d_chunk ^ s_chunk;
        dst[i..i+8].copy_from_slice(&res.to_ne_bytes());
        i += 8;
    }

    for j in i..len {
        dst[j] ^= src[j];
    }
} 
