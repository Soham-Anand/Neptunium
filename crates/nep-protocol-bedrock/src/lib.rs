pub mod mcpe;
pub mod raknet;

/// RakNet unconnected ping (0x01) -> pong (0x1c) MOTD builder for Bedrock 26.2.
/// Format: MCPE;<motd>;<protocol>;<version>;<online>;<max>;<server-id>;<level>;<gamemode>
pub fn motd(
    motd: &str,
    protocol: u32,
    version: &str,
    online: usize,
    max: usize,
    server_id: u64,
    level: &str,
) -> String {
    format!(
        "MCPE;{};{};{};{};{};{};{};Survival;1;19133;19133;",
        motd, protocol, version, online, max, server_id, level
    )
}

/// True if datagram is RakNet unconnected ping (first byte 0x01).
pub fn is_unconnected_ping(d: &[u8]) -> bool {
    d.first() == Some(&0x01) && d.len() >= 33
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn motd_has_924() {
        let m = motd("Neptunium 26.2", 924, "1.26.2", 0, 20, 1, "world-26-2");
        assert!(m.starts_with("MCPE;"));
        assert!(m.contains(";924;"));
    }
}
