use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct Config {
    #[serde(default)]
    pub tun: TunConfig,
    #[serde(default)]
    pub net: NetConfig,
    #[serde(default)]
    pub security: SecurityConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TunConfig {
    pub address: String,
    pub destination: String,
    #[serde(default = "default_address_v6")]
    pub address_v6: String,
    #[serde(default = "default_destination_v6")]
    pub destination_v6: String,
    pub mtu: i32,
}

fn default_address_v6() -> String { "fd00::1".to_string() }
fn default_destination_v6() -> String { "fd00::ffff".to_string() }

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            address: "10.0.0.1".to_string(),
            destination: "10.0.0.254".to_string(),
            address_v6: default_address_v6(),
            destination_v6: default_destination_v6(),
            mtu: 1420,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetConfig {
    pub endpoint: String,
    pub use_tcp: bool,
    #[serde(default)]
    pub ipv6: bool,
    #[serde(default)]
    pub split_tunnel: String,
    #[serde(default)]
    pub kill_switch: bool,
    #[serde(default)]
    pub app_list: Vec<String>,
    #[serde(default)]
    pub exclude_app_list: Vec<String>,
    #[serde(default)]
    pub ip_list: Vec<String>,
    #[serde(default)]
    pub exclude_ip_list: Vec<String>,
}

impl Default for NetConfig {
    fn default() -> Self {
        Self {
            endpoint: "".to_string(),
            use_tcp: false,
            ipv6: false,
            split_tunnel: "".to_string(),
            kill_switch: false,
            app_list: vec![],
            exclude_app_list: vec![],
            ip_list: vec![],
            exclude_ip_list: vec![],
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecurityConfig {
    pub auth_token: String,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            auth_token: "".to_string(),
        }
    }
}

pub fn load<P: AsRef<Path>>(path: P) -> anyhow::Result<Config> {
    if !path.as_ref().exists() {
        return Ok(Config::default());
    }
    let content = fs::read_to_string(path)?;
    let config: Config = toml::from_str(&content)?;
    Ok(config)
}

#[allow(dead_code)]
pub fn save<P: AsRef<Path>>(path: P, config: &Config) -> anyhow::Result<()> {
    let content = toml::to_string_pretty(config)?;
    fs::write(path, content)?;
    Ok(())
}