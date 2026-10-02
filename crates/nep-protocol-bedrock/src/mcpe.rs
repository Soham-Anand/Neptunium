//! Bedrock game packets (inside RakNet batches) for 26.2.
//!
//! Layouts follow PrismarineJS `minecraft-data` (MIT) `data/bedrock/latest`
//! (`packet_login`, `packet_play_status`, `packet_disconnect`,
//! `packet_resource_packs_info`, `packet_resource_pack_stack`,
//! `packet_resource_pack_client_response`, `packet_network_settings`,
//! `packet_start_game`, `packet_text`). Bedrock `string` is a varint-prefixed
//! UTF-8 blob; `i32` is big-endian, `l*` types little-endian, signed ints are
//! zigzag varints unless noted.

use std::io::Read;

// ---- varints ----

pub fn write_uvarint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let mut b = (v & 0x7F) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
}

pub fn read_uvarint(d: &[u8], off: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    let mut shift = 0;
    for _ in 0..10 {
        if *off >= d.len() {
            return None;
        }
        let b = d[*off];
        *off += 1;
        v |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 == 0 {
            return Some(v);
        }
        shift += 7;
    }
    None
}

pub fn write_zigzag32(v: i32, out: &mut Vec<u8>) {
    write_uvarint(((v << 1) ^ (v >> 31)) as u64, out);
}

pub fn read_zigzag32(d: &[u8], off: &mut usize) -> Option<i32> {
    let v = read_uvarint(d, off)? as u32;
    Some(((v >> 1) as i32) ^ -((v & 1) as i32))
}

pub fn write_zigzag64(v: i64, out: &mut Vec<u8>) {
    write_uvarint(((v << 1) ^ (v >> 63)) as u64, out);
}

#[allow(dead_code)]
pub fn read_zigzag64(d: &[u8], off: &mut usize) -> Option<i64> {
    let v = read_uvarint(d, off)?;
    Some(((v >> 1) as i64) ^ -((v & 1) as i64))
}

// ---- strings / primitives ----

pub fn write_string(out: &mut Vec<u8>, s: &str) {
    write_uvarint(s.len() as u64, out);
    out.extend_from_slice(s.as_bytes());
}

pub fn read_string(d: &[u8], off: &mut usize) -> Option<String> {
    let len = read_uvarint(d, off)? as usize;
    if len > 4_000_000 || *off + len > d.len() {
        return None;
    }
    let s = std::str::from_utf8(&d[*off..*off + len]).ok()?.to_string();
    *off += len;
    Some(s)
}

/// Little-endian u16-prefixed string (LoginTokens `LittleString`).
pub fn write_little_string(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u16).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

pub fn read_little_string(d: &[u8], off: &mut usize) -> Option<String> {
    if *off + 2 > d.len() {
        return None;
    }
    let len = u16::from_le_bytes([d[*off], d[*off + 1]]) as usize;
    *off += 2;
    if *off + len > d.len() {
        return None;
    }
    let s = std::str::from_utf8(&d[*off..*off + len]).ok()?.to_string();
    *off += len;
    Some(s)
}

pub fn write_uuid16(out: &mut Vec<u8>, u: &[u8; 16]) {
    out.extend_from_slice(u);
}

// ---- batch (0xFE) ----

pub const BATCH_ID: u8 = 0xFE;

/// Wrap game packets in a compressed batch.
pub fn encode_batch(packets: &[Vec<u8>]) -> Vec<u8> {
    let mut raw = vec![];
    for p in packets {
        write_uvarint(p.len() as u64, &mut raw);
        raw.extend_from_slice(p);
    }
    let mut enc = flate2::write::ZlibEncoder::new(vec![], flate2::Compression::default());
    use std::io::Write as _;
    enc.write_all(&raw).expect("zlib encode");
    let compressed = enc.finish().expect("zlib finish");
    let mut out = vec![BATCH_ID];
    out.extend_from_slice(&compressed);
    out
}

/// Split a batch into its game packets. Handles compressed and (leniently)
/// uncompressed batches.
pub fn decode_batch(d: &[u8]) -> Option<Vec<Vec<u8>>> {
    if d.first() != Some(&BATCH_ID) {
        return None;
    }
    let body = &d[1..];
    let raw = inflate(body).unwrap_or_else(|| body.to_vec());
    let mut out = vec![];
    let mut off = 0;
    while off < raw.len() {
        let len = read_uvarint(&raw, &mut off)? as usize;
        if len > 8_000_000 || off + len > raw.len() {
            return None;
        }
        out.push(raw[off..off + len].to_vec());
        off += len;
    }
    if out.is_empty() {
        return None;
    }
    Some(out)
}

fn inflate(d: &[u8]) -> Option<Vec<u8>> {
    let dec = flate2::read::ZlibDecoder::new(d);
    let mut raw = vec![];
    dec.take(8_000_000).read_to_end(&mut raw).ok()?;
    if raw.is_empty() {
        return None;
    }
    Some(raw)
}

/// Game packet id = first varint of the packet.
pub fn packet_id(p: &[u8]) -> Option<u64> {
    let mut off = 0;
    read_uvarint(p, &mut off)
}

// ---- login ----

/// Parsed login: client protocol + display name.
#[derive(Debug, Clone)]
pub struct Login {
    pub protocol: i32,
    pub display_name: String,
}

/// Parse Login (0x01): BE protocol + varint-prefixed LoginTokens blob.
pub fn parse_login(p: &[u8]) -> Option<Login> {
    let mut off = 0;
    if read_uvarint(p, &mut off)? != 0x01 {
        return None;
    }
    if off + 4 > p.len() {
        return None;
    }
    let protocol = i32::from_be_bytes(p[off..off + 4].try_into().ok()?);
    off += 4;
    let blob_len = read_uvarint(p, &mut off)? as usize;
    if off + blob_len > p.len() {
        return None;
    }
    let end = off + blob_len;
    let identity = read_little_string(p, &mut off)?;
    let client_data = read_little_string(p, &mut off).unwrap_or_default();
    let _ = end;
    let display_name = extract_display_name(&identity, &client_data).unwrap_or_else(|| "Steve".into());
    Some(Login { protocol, display_name })
}

fn decode_jwt_payload(jwt: &str) -> Option<serde_json::Value> {
    use base64::Engine as _;
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() < 2 {
        return None;
    }
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .ok()?;
    serde_json::from_slice(&raw).ok()
}

fn display_from_jwt(jwt: &str) -> Option<String> {
    let v = decode_jwt_payload(jwt)?;
    if let Some(n) = v.get("extraData").and_then(|e| e.get("displayName")).and_then(|n| n.as_str()) {
        return Some(n.to_string());
    }
    if let Some(n) = v.get("DisplayName").and_then(|n| n.as_str()) {
        return Some(n.to_string());
    }
    None
}

/// New (1.21.90+) shape: identity JSON has `Certificate` = stringified JSON
/// with the `chain` array. Also accepts the legacy direct `chain` shape.
fn extract_display_name(identity: &str, client_data: &str) -> Option<String> {
    let id_json: serde_json::Value = serde_json::from_str(identity).ok()?;
    let mut chains: Vec<String> = vec![];
    if let Some(cert) = id_json.get("Certificate").and_then(|c| c.as_str()) {
        if let Ok(inner) = serde_json::from_str::<serde_json::Value>(cert) {
            if let Some(arr) = inner.get("chain").and_then(|a| a.as_array()) {
                for e in arr {
                    if let Some(s) = e.as_str() {
                        chains.push(s.to_string());
                    }
                }
            }
        }
    }
    if let Some(arr) = id_json.get("chain").and_then(|a| a.as_array()) {
        for e in arr {
            if let Some(s) = e.as_str() {
                chains.push(s.to_string());
            }
        }
    }
    for jwt in chains {
        if let Some(n) = display_from_jwt(&jwt) {
            return Some(n);
        }
    }
    if !client_data.is_empty() {
        if let Some(n) = display_from_jwt(client_data) {
            return Some(n);
        }
    }
    None
}

fn unsigned_jwt(payload: &serde_json::Value) -> String {
    use base64::Engine as _;
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
    let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.to_string());
    format!("{header}.{body}.")
}

/// Build a minimal offline-style Login packet (used by tests / dev tools).
pub fn build_login(protocol: i32, display_name: &str) -> Vec<u8> {
    let chain_jwt = unsigned_jwt(&serde_json::json!({
        "extraData": {"displayName": display_name, "identity": "00000000-0000-0000-0000-000000000000", "XUID": "0"}
    }));
    let identity = serde_json::json!({
        "Certificate": serde_json::json!({"chain": [chain_jwt]}).to_string()
    })
    .to_string();
    let client = unsigned_jwt(&serde_json::json!({"DisplayName": display_name}));
    let mut tokens = vec![];
    write_little_string(&mut tokens, &identity);
    write_little_string(&mut tokens, &client);
    let mut out = vec![];
    write_uvarint(0x01, &mut out);
    out.extend_from_slice(&protocol.to_be_bytes());
    write_uvarint(tokens.len() as u64, &mut out);
    out.extend_from_slice(&tokens);
    out
}

// ---- serverbound: network settings request / resource response / cache ----

/// Parse RequestNetworkSettings (0xC1). Returns client protocol (BE i32).
pub fn parse_network_settings_request(p: &[u8]) -> Option<i32> {
    let mut off = 0;
    if read_uvarint(p, &mut off)? != 0xC1 || off + 4 > p.len() {
        return None;
    }
    Some(i32::from_be_bytes(p[off..off + 4].try_into().ok()?))
}

/// NetworkSettings (0x8F): zlib batches, threshold 1.
pub fn network_settings() -> Vec<u8> {
    let mut out = vec![];
    write_uvarint(0x8F, &mut out);
    out.extend_from_slice(&1u16.to_le_bytes()); // compression threshold
    out.extend_from_slice(&0u16.to_le_bytes()); // 0 = deflate
    out.push(0x00); // no client throttle
    out.push(0x00); // throttle threshold
    out.extend_from_slice(&0f32.to_le_bytes()); // throttle scalar
    out
}

/// Parse ResourcePackClientResponse (0x08, 1.26.40+ shape). Returns status:
/// 0 refused, 1 send_packs, 2 have_all_packs, 3 completed.
pub fn parse_pack_response(p: &[u8]) -> Option<u64> {
    let mut off = 0;
    if read_uvarint(p, &mut off)? != 0x08 {
        return None;
    }
    // New shape: varint status + name string (+ ids only for send_packs).
    // Legacy shape: single u8 status. Accept both.
    let at = off;
    let status = read_uvarint(p, &mut off)?;
    if status <= 3 && off < p.len() {
        // Looks like the new shape; consume the name string if present.
        if read_string(p, &mut off).is_some() {
            return Some(status);
        }
        return Some(status);
    }
    let _ = at;
    Some(status)
}

/// True if ClientCacheStatus (0x81).
pub fn is_client_cache_status(p: &[u8]) -> bool {
    packet_id(p) == Some(0x81)
}

// ---- clientbound: play status / packs / start game / disconnect / text ----

/// PlayStatus (0x02). 0 = login_success, 3 = player_spawn.
pub fn play_status(status: i32) -> Vec<u8> {
    let mut out = vec![];
    write_uvarint(0x02, &mut out);
    out.extend_from_slice(&status.to_be_bytes());
    out
}

/// ResourcePacksInfo (0x06) with no packs.
pub fn resource_packs_info() -> Vec<u8> {
    let mut out = vec![];
    write_uvarint(0x06, &mut out);
    out.push(0x00); // must_accept = false
    out.push(0x00); // has_addons
    out.push(0x00); // has_scripts
    out.push(0x00); // disable_vibrant_visuals
    write_uuid16(&mut out, &[0u8; 16]); // world template uuid (empty)
    write_string(&mut out, ""); // world template version
    write_uvarint(0, &mut out); // texture packs count
    out
}

/// ResourcePackStack (0x07) with no packs.
pub fn resource_pack_stack(game_version: &str) -> Vec<u8> {
    let mut out = vec![];
    write_uvarint(0x07, &mut out);
    out.push(0x00); // must_accept
    write_uvarint(0, &mut out); // resource packs count
    write_string(&mut out, game_version);
    out.extend_from_slice(&0i32.to_le_bytes()); // experiments count
    out.push(0x00); // experiments_previously_used
    out.push(0x00); // has_editor_packs
    out
}

/// Parameters for StartGame (0x0B).
pub struct StartGameParams<'a> {
    pub seed: u64,
    pub spawn: [i32; 3],
    pub max_players: usize,
    pub motd: &'a str,
    pub world_name: &'a str,
    pub game_version: &'a str,
}

/// StartGame (0x0B): flat overworld, survival, offline-style. Field order
/// follows `minecraft-data` latest `packet_start_game`.
pub fn start_game(p: &StartGameParams) -> Vec<u8> {
    let mut out = vec![];
    write_uvarint(0x0B, &mut out);
    write_zigzag64(1, &mut out); // entity id
    write_uvarint(1, &mut out); // runtime entity id
    write_zigzag32(0, &mut out); // player gamemode: survival
    for v in [p.spawn[0] as f32 + 0.5, p.spawn[1] as f32 + 1.0, p.spawn[2] as f32 + 0.5] {
        out.extend_from_slice(&v.to_le_bytes()); // player position vec3f
    }
    out.extend_from_slice(&0f32.to_le_bytes()); // pitch
    out.extend_from_slice(&0f32.to_le_bytes()); // yaw
    out.extend_from_slice(&p.seed.to_le_bytes()); // seed lu64
    out.extend_from_slice(&0i16.to_le_bytes()); // biome type
    write_string(&mut out, "minecraft:plains"); // biome name
    write_zigzag32(0, &mut out); // dimension: overworld
    write_zigzag32(2, &mut out); // generator: flat
    write_zigzag32(0, &mut out); // world gamemode: survival
    out.push(0x00); // hardcore
    write_zigzag32(1, &mut out); // difficulty: easy
    for v in p.spawn {
        write_zigzag32(v, &mut out); // world spawn BlockCoordinates
    }
    out.push(0x00); // achievements disabled
    write_zigzag32(0, &mut out); // editor world type: not_editor
    out.push(0x00); // created_in_editor
    out.push(0x00); // exported_from_editor
    write_zigzag32(0, &mut out); // day cycle stop time
    write_uvarint(0, &mut out); // edu offer
    out.push(0x00); // edu features
    write_string(&mut out, ""); // edu product uuid
    out.extend_from_slice(&0f32.to_le_bytes()); // rain
    out.extend_from_slice(&0f32.to_le_bytes()); // lightning
    out.push(0x00); // confirmed platform locked content
    out.push(0x01); // multiplayer
    out.push(0x01); // broadcast to LAN
    write_uvarint(0, &mut out); // xbox broadcast mode
    write_uvarint(0, &mut out); // platform broadcast mode
    out.push(0x01); // commands enabled
    out.push(0x00); // texturepacks required
    write_uvarint(0, &mut out); // gamerules count
    out.extend_from_slice(&0i32.to_le_bytes()); // experiments count
    out.push(0x00); // experiments previously used
    out.push(0x00); // bonus chest
    out.push(0x00); // start with map
    out.push(2u8); // permission: operator
    out.extend_from_slice(&4i32.to_le_bytes()); // chunk tick range
    out.push(0x00); // locked behavior pack
    out.push(0x00); // locked resource pack
    out.push(0x00); // from locked template
    out.push(0x00); // msa gamertags only
    out.push(0x00); // from world template
    out.push(0x00); // template option locked
    out.push(0x00); // v1 villagers only
    out.push(0x00); // persona disabled
    out.push(0x00); // custom skins disabled
    out.push(0x00); // emote chat muted
    write_string(&mut out, p.game_version);
    out.extend_from_slice(&0i32.to_le_bytes()); // limited world width
    out.extend_from_slice(&0i32.to_le_bytes()); // limited world length
    out.push(0x01); // new nether
    write_string(&mut out, ""); // edu button name
    write_string(&mut out, ""); // edu link uri
    out.push(0x00); // experimental override
    out.push(0u8); // chat restriction: none
    out.push(0x00); // disable player interactions
    write_zigzag32(0, &mut out); // editor connection policy
    out.push(0x00); // anonymous block drops in editor
    write_string(&mut out, p.world_name); // level id
    write_string(&mut out, p.world_name); // world name
    write_string(&mut out, ""); // premium template id
    out.push(0x00); // trial
    write_zigzag32(0, &mut out); // rewind history
    out.push(0x00); // server-auth block breaking
    out.extend_from_slice(&0i64.to_le_bytes()); // current tick
    write_zigzag32(0, &mut out); // enchantment seed
    write_uvarint(0, &mut out); // block properties count
    write_string(&mut out, "123e4567-e89b-12d3-a456-426614174000"); // mp correlation id
    out.push(0x01); // server-auth inventory
    write_string(&mut out, "Neptunium"); // engine
    // property_data: varint-prefixed empty LE-NBT compound.
    write_uvarint(4, &mut out);
    out.extend_from_slice(&[0x0A, 0x00, 0x00, 0x00]);
    out.extend_from_slice(&0u64.to_le_bytes()); // block palette checksum
    write_uuid16(&mut out, &[0u8; 16]); // world template id
    out.push(0x00); // client-side generation
    out.push(0x00); // block network ids are hashes
    out.push(0x01); // server controlled sound
    out.push(0x00); // has server join info
    write_string(&mut out, p.motd); // server identifier
    write_string(&mut out, ""); // scenario identifier
    write_string(&mut out, ""); // world identifier
    write_string(&mut out, ""); // owner identifier
    let _ = p.max_players;
    out
}

/// Disconnect (0x05) with a visible message.
pub fn disconnect_notice(message: &str) -> Vec<u8> {
    let mut out = vec![];
    write_uvarint(0x05, &mut out);
    write_zigzag32(0, &mut out); // reason: unknown
    out.push(0x00); // show reason
    write_string(&mut out, message);
    write_string(&mut out, "");
    out
}

/// Decode a client Text packet (0x09) chat message. Returns (source, text).
pub fn parse_text(p: &[u8]) -> Option<(String, String)> {
    let mut off = 0;
    if read_uvarint(p, &mut off)? != 0x09 {
        return None;
    }
    if off + 3 > p.len() {
        return None;
    }
    let _needs_translation = p[off];
    let _category = p[off + 1];
    let typ = p[off + 2];
    off += 3;
    let (source, message) = match typ {
        1 | 7 | 8 => {
            let s = read_string(p, &mut off)?;
            let m = read_string(p, &mut off)?;
            (s, m)
        }
        _ => (String::new(), read_string(p, &mut off).unwrap_or_default()),
    };
    Some((source, message))
}

/// Server system message (Text 0x09, type system).
pub fn text_system(message: &str) -> Vec<u8> {
    let mut out = vec![];
    write_uvarint(0x09, &mut out);
    out.push(0x00); // needs_translation
    out.push(0x00); // category message_only
    out.push(6u8); // type system
    write_string(&mut out, message);
    write_string(&mut out, "");
    write_string(&mut out, "");
    out.push(0x00); // no filtered message
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() {
        for v in [0u64, 1, 127, 128, 300, 924, 0xFFFF_FFFF, 1 << 40] {
            let mut b = vec![];
            write_uvarint(v, &mut b);
            let mut off = 0;
            assert_eq!(read_uvarint(&b, &mut off).unwrap(), v);
        }
    }

    #[test]
    fn zigzag_roundtrip() {
        for v in [0, 1, -1, 776, -924, i32::MIN, i32::MAX] {
            let mut b = vec![];
            write_zigzag32(v, &mut b);
            let mut off = 0;
            assert_eq!(read_zigzag32(&b, &mut off).unwrap(), v);
        }
    }

    #[test]
    fn strings_roundtrip() {
        for s in ["", "Neptunium 26.2", "minecraft:plains", "Steve"] {
            let mut b = vec![];
            write_string(&mut b, s);
            let mut off = 0;
            assert_eq!(read_string(&b, &mut off).unwrap(), s);
            let mut l = vec![];
            write_little_string(&mut l, s);
            let mut off = 0;
            assert_eq!(read_little_string(&l, &mut off).unwrap(), s);
        }
    }

    #[test]
    fn batch_roundtrip() {
        let pkts = vec![vec![0x02, 0, 0, 0, 0], vec![0x09, 1, 2, 3, 4, 5]];
        let b = encode_batch(&pkts);
        assert_eq!(b[0], BATCH_ID);
        assert_eq!(decode_batch(&b).unwrap(), pkts);
    }

    #[test]
    fn login_roundtrip() {
        let p = build_login(924, "TestPlayer");
        let l = parse_login(&p).unwrap();
        assert_eq!(l.protocol, 924);
        assert_eq!(l.display_name, "TestPlayer");
    }

    #[test]
    fn net_settings_roundtrip() {
        let p = vec![0xC1, 0x01, 0, 0, 3, 156]; // id 193 varint + 924 BE
        assert_eq!(parse_network_settings_request(&p).unwrap(), 924);
        let r = network_settings();
        assert_eq!(packet_id(&r), Some(0x8F));
    }

    #[test]
    fn pack_response_shapes() {
        // New shape: varint status + name.
        let mut p = vec![];
        write_uvarint(0x08, &mut p);
        write_uvarint(2, &mut p);
        write_string(&mut p, "have_all_packs");
        assert_eq!(parse_pack_response(&p), Some(2));
        // completed
        let mut p = vec![];
        write_uvarint(0x08, &mut p);
        write_uvarint(3, &mut p);
        write_string(&mut p, "completed");
        assert_eq!(parse_pack_response(&p), Some(3));
    }

    #[test]
    fn server_packets_have_ids() {
        assert_eq!(packet_id(&play_status(0)), Some(0x02));
        assert_eq!(packet_id(&resource_packs_info()), Some(0x06));
        assert_eq!(packet_id(&resource_pack_stack("1.26.2")), Some(0x07));
        assert_eq!(packet_id(&disconnect_notice("x")), Some(0x05));
        let sg = start_game(&StartGameParams {
            seed: 262,
            spawn: [8, 65, 8],
            max_players: 20,
            motd: "m",
            world_name: "world-26-2",
            game_version: "1.26.2",
        });
        assert_eq!(packet_id(&sg), Some(0x0B));
        assert!(sg.len() > 200);
    }

    #[test]
    fn text_roundtrip() {
        // client chat shape: header + source + message (+ trailing fields ignored)
        let mut p = vec![];
        write_uvarint(0x09, &mut p);
        p.extend_from_slice(&[0x00, 0x00, 0x01]);
        write_string(&mut p, "Steve");
        write_string(&mut p, "hello world");
        let (s, m) = parse_text(&p).unwrap();
        assert_eq!((s.as_str(), m.as_str()), ("Steve", "hello world"));
        assert_eq!(packet_id(&text_system("hi")), Some(0x09));
    }
}
