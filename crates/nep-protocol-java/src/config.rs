//! Vanilla 26.2 (protocol 776) configuration + play-entry packets.
//!
//! Packet IDs verified against PrismarineJS `pc_26_2` protocol data and live
//! 26.2 client hex. Registry payloads are byte-for-byte captures from the
//! official 26.2 server (mcsquared `docs/generated/registry-fallback-26.2.mcr`,
//! SHA-256 verified at fetch time); tags from `tags-26.2.mcr` in `./vendor/`.
//! See `vendor/ATTRIBUTION.md`.

use super::{write_string, write_varint};

pub fn write_bool(out: &mut Vec<u8>, v: bool) {
    out.push(if v { 1 } else { 0 });
}

pub fn write_i32(out: &mut Vec<u8>, v: i32) {
    out.extend_from_slice(&v.to_be_bytes());
}

pub fn write_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

pub fn write_i64(out: &mut Vec<u8>, v: i64) {
    out.extend_from_slice(&v.to_be_bytes());
}

pub fn write_f32(out: &mut Vec<u8>, v: f32) {
    out.extend_from_slice(&v.to_be_bytes());
}

pub fn write_f64(out: &mut Vec<u8>, v: f64) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Packed block position: ((x & 0x3FFFFFF) << 38) | ((z & 0x3FFFFFF) << 12) | (y & 0xFFF)
pub fn pack_position(x: i32, y: i32, z: i32) -> i64 {
    (((x as i64) & 0x3FFFFFF) << 38) | (((z as i64) & 0x3FFFFFF) << 12) | ((y as i64) & 0xFFF)
}

// ---- configuration ----

/// Clientbound Custom Payload 0x01, channel `minecraft:brand`.
/// Brand payload is a length-prefixed String (Fabric hard-fails otherwise).
pub fn brand_packet() -> Vec<u8> {
    let mut p = vec![];
    write_varint(0x01, &mut p);
    write_string(&mut p, "minecraft:brand");
    write_string(&mut p, "neptunium");
    p
}

/// Clientbound Feature Flags 0x0C: `minecraft:vanilla`.
pub fn feature_flags_packet() -> Vec<u8> {
    let mut p = vec![];
    write_varint(0x0C, &mut p);
    write_varint(1, &mut p);
    write_string(&mut p, "minecraft:vanilla");
    p
}

/// Clientbound Select Known Packs 0x0E: `minecraft:core:26.2`.
pub fn known_packs_packet() -> Vec<u8> {
    let mut p = vec![];
    write_varint(0x0E, &mut p);
    write_varint(1, &mut p);
    write_string(&mut p, "minecraft");
    write_string(&mut p, "core");
    write_string(&mut p, "26.2");
    p
}

/// Clientbound Finish Configuration 0x03 (empty).
pub fn finish_packet() -> Vec<u8> {
    let mut p = vec![];
    write_varint(0x03, &mut p);
    p
}

const REGISTRIES_MCR: &str = include_str!("../../../vendor/registry-fallback-26.2.mcr");
const TAGS_MCR: &str = include_str!("../../../vendor/tags-26.2.mcr");

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < b.len() {
        let h = |c: u8| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        };
        out.push((h(b[i])? << 4) | h(b[i + 1])?);
        i += 2;
    }
    Some(out)
}

/// The 29 Registry Data (0x07) packet payloads in official order.
/// Each payload already starts with the packet-ID varint.
pub fn registry_payloads() -> Vec<Vec<u8>> {
    let mut out = vec![];
    for line in REGISTRIES_MCR.lines() {
        if line.is_empty() || line.starts_with("MCREGISTRY") {
            continue;
        }
        let mut f = line.split('\t');
        if f.next() != Some("R") {
            continue;
        }
        let _registry = f.next().unwrap_or("?");
        let _sha = f.next().unwrap_or("");
        if let Some(hex) = f.next() {
            if let Some(raw) = hex_decode(hex) {
                debug_assert!(!raw.is_empty() && raw[0] == 0x07, "registry payload id");
                out.push(raw);
            }
        }
    }
    out
}

/// Clientbound Update Tags 0x0D built from `tags-26.2.mcr`
/// (`R\t<registry>\t<count>` + `T\t<tag>\t<id,id,..>`).
pub fn tags_packet() -> Vec<u8> {
    let mut regs: Vec<(String, Vec<(String, Vec<i32>)>)> = vec![];
    for line in TAGS_MCR.lines() {
        if line.is_empty() || line.starts_with("MCTAGS") {
            continue;
        }
        let mut f = line.split('\t');
        match f.next() {
            Some("R") => {
                regs.push((f.next().unwrap_or("?").to_string(), vec![]));
            }
            Some("T") => {
                let name = f.next().unwrap_or("?").to_string();
                let ids: Vec<i32> = f
                    .next()
                    .unwrap_or("")
                    .split(',')
                    .filter_map(|x| x.parse().ok())
                    .collect();
                if let Some((_, tags)) = regs.last_mut() {
                    tags.push((name, ids));
                }
            }
            _ => {}
        }
    }
    let mut p = vec![];
    write_varint(0x0D, &mut p);
    write_varint(regs.len() as i32, &mut p);
    for (reg, tags) in &regs {
        write_string(&mut p, reg);
        write_varint(tags.len() as i32, &mut p);
        for (tag, ids) in tags {
            write_string(&mut p, tag);
            write_varint(ids.len() as i32, &mut p);
            for id in ids {
                write_varint(*id, &mut p);
            }
        }
    }
    p
}

// ---- play entry ----

/// Clientbound Login (play) 0x31. Flat overworld, survival, offline mode.
pub fn play_login(seed: u64, max_players: usize) -> Vec<u8> {
    let mut p = vec![];
    write_varint(0x31, &mut p);
    write_i32(&mut p, 1); // entity id (vanilla never sends 0; 0 trips unset-ID guard)
    write_bool(&mut p, false); // hardcore
    write_varint(3, &mut p); // world count
    for w in ["minecraft:overworld", "minecraft:the_nether", "minecraft:the_end"] {
        write_string(&mut p, w);
    }
    write_varint(max_players as i32, &mut p);
    write_varint(10, &mut p); // view distance
    write_varint(10, &mut p); // sim distance
    write_bool(&mut p, false); // reduced debug
    write_bool(&mut p, true); // respawn screen
    write_bool(&mut p, false); // limited crafting
    // SpawnInfo
    write_varint(0, &mut p); // dimension registry id (overworld)
    write_string(&mut p, "minecraft:overworld");
    write_i64(&mut p, seed as i64); // hashed seed
    p.push(0); // gamemode survival
    p.push(255); // previous gamemode
    write_bool(&mut p, false); // debug
    write_bool(&mut p, true); // flat
    write_bool(&mut p, false); // death absent
    write_varint(0, &mut p); // portal cooldown
    write_varint(63, &mut p); // sea level
    write_bool(&mut p, false); // online mode
    write_bool(&mut p, false); // secure chat
    p
}

/// Clientbound Keep Alive (play/config) 0x2C.
pub fn keepalive_packet(id: i64) -> Vec<u8> {
    let mut p = vec![];
    write_varint(0x2C, &mut p);
    write_i64(&mut p, id);
    p
}

/// Clientbound Set Center Chunk 0x5E.
pub fn set_center(cx: i32, cz: i32) -> Vec<u8> {
    let mut p = vec![];
    write_varint(0x5E, &mut p);
    write_varint(cx, &mut p);
    write_varint(cz, &mut p);
    p
}

/// Clientbound Set Chunk Cache Radius 0x5F. Without this the client never
/// leaves the loading-terrain screen.
pub fn chunk_cache_radius(radius: i32) -> Vec<u8> {
    let mut p = vec![];
    write_varint(0x5F, &mut p);
    write_varint(radius, &mut p);
    p
}

/// Clientbound Set Default Spawn 0x61 (RespawnData: GlobalPos + yaw + pitch).
pub fn default_spawn(x: i32, y: i32, z: i32) -> Vec<u8> {
    let mut p = vec![];
    write_varint(0x61, &mut p);
    write_string(&mut p, "minecraft:overworld");
    write_i64(&mut p, pack_position(x, y, z));
    write_f32(&mut p, 0.0);
    write_f32(&mut p, 0.0);
    p
}

/// Clientbound Synchronize Player Position 0x48.
pub fn player_position(x: f64, y: f64, z: f64, teleport_id: i32) -> Vec<u8> {
    let mut p = vec![];
    write_varint(0x48, &mut p);
    write_varint(teleport_id, &mut p);
    write_f64(&mut p, x);
    write_f64(&mut p, y);
    write_f64(&mut p, z);
    write_f64(&mut p, 0.0);
    write_f64(&mut p, 0.0);
    write_f64(&mut p, 0.0);
    write_f32(&mut p, 0.0);
    write_f32(&mut p, 0.0);
    write_u32(&mut p, 0); // absolute
    p
}

/// Clientbound Game Event 0x26 (reason u8 + value f32).
pub fn game_event(reason: u8, value: f32) -> Vec<u8> {
    let mut p = vec![];
    write_varint(0x26, &mut p);
    p.push(reason);
    write_f32(&mut p, value);
    p
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registry_payload_count() {
        let r = registry_payloads();
        assert_eq!(r.len(), 29);
        assert!(r.iter().all(|p| p[0] == 0x07));
    }
    #[test]
    fn tags_packet_builds() {
        let t = tags_packet();
        assert!(t[0] == 0x0D);
        assert!(t.len() > 10000);
    }
    #[test]
    fn login_packet_shape() {
        let l = play_login(262, 20);
        assert_eq!(l[0], 0x31);
        assert!(l.len() > 100);
    }
    #[test]
    fn position_pack() {
        assert_eq!(pack_position(0, 0, 0), 0);
        assert_eq!(pack_position(8, 65, 8), (8 << 38) | (8 << 12) | 65);
    }
}
