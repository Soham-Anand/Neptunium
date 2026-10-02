use serde::{Deserialize, Serialize};

/// 26.2 protocol targets. Single source of truth.
pub const JAVA_26_2_PROTOCOL: i32 = 776;
pub const BEDROCK_26_2_PROTOCOL: u32 = 924;
pub const DATA_PACK_26_2: &str = "107.0";
pub const RESOURCE_PACK_26_2: &str = "88.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub host: String,
    pub java_port: u16,
    pub bedrock_port: u16,
    pub motd: String,
    pub max_players: usize,
    pub online_mode: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            java_port: 25565,
            bedrock_port: 19132,
            motd: "Neptunium 26.2 — localhost reactor".into(),
            max_players: 20,
            online_mode: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WorldConfig {
    pub name: String,
    pub seed: u64,
    pub generator: String,
    pub spawn: [i32; 3],
}

impl Default for WorldConfig {
    fn default() -> Self {
        Self {
            name: "world-26-2".into(),
            seed: 262,
            generator: "flat".into(),
            spawn: [8, 65, 8],
        }
    }
}

/// Canonical tick state shared by Java + Bedrock frontends.
#[derive(Debug, Default)]
pub struct TickStats {
    pub tick: u64,
    pub tps: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protocol_constants_match_26_2() {
        assert_eq!(JAVA_26_2_PROTOCOL, 776);
        assert_eq!(BEDROCK_26_2_PROTOCOL, 924);
    }
}
