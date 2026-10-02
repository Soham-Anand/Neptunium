use serde_json::json;

pub mod chunk;
pub mod config;

/// Read unsigned VarInt (max 5 bytes) as used by Java protocol.
pub fn read_varint(buf: &[u8]) -> Option<(i32, usize)> {
    let mut num: i32 = 0;
    let mut shift = 0;
    for (i, &b) in buf.iter().enumerate().take(5) {
        num |= ((b & 0x7F) as i32) << shift;
        if b & 0x80 == 0 {
            return Some((num, i + 1));
        }
        shift += 7;
    }
    None
}

pub fn write_varint(mut v: i32, out: &mut Vec<u8>) {
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

/// Read length-prefixed UTF-8 string. Returns (value, bytes consumed).
pub fn read_string(buf: &[u8]) -> Option<(String, usize)> {
    let (len, n) = read_varint(buf)?;
    if len < 0 || (n + len as usize) > buf.len() {
        return None;
    }
    let s = std::str::from_utf8(&buf[n..n + len as usize]).ok()?.to_string();
    Some((s, n + len as usize))
}

pub fn write_string(out: &mut Vec<u8>, v: &str) {
    let b = v.as_bytes();
    write_varint(b.len() as i32, out);
    out.extend_from_slice(b);
}

/// Offline-mode UUID (v3 MD5 of "OfflinePlayer:<name>"), matching vanilla.
pub fn offline_uuid(name: &str) -> [u8; 16] {
    // Keep the small digest implementation local: offline UUIDs are needed
    // before a client can join, and pulling a crypto dependency just for MD5
    // would add unnecessary build surface. MD5 here is an identifier hash,
    // never used for security.
    const S: [u32; 64] = [
        7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
        5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
        4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
        6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21,
    ];
    const K: [u32; 64] = [
        0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
        0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
        0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
        0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
        0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
        0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
        0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
        0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391,
    ];

    let mut input = format!("OfflinePlayer:{name}").into_bytes();
    let bit_len = (input.len() as u64).wrapping_mul(8);
    input.push(0x80);
    while input.len() % 64 != 56 { input.push(0); }
    input.extend_from_slice(&bit_len.to_le_bytes());

    let mut state = [0x67452301u32, 0xefcdab89, 0x98badcfe, 0x10325476];
    for block in input.chunks_exact(64) {
        let mut words = [0u32; 16];
        for (i, word) in words.iter_mut().enumerate() {
            *word = u32::from_le_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
        }
        let [mut a, mut b, mut c, mut d] = state;
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | (!b & d), i),
                16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let next = a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(words[g]);
            let rotated = next.rotate_left(S[i]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(rotated);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }
    let mut u = [0u8; 16];
    for (i, word) in state.iter().enumerate() {
        u[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    u[6] = (u[6] & 0x0f) | 0x30; // v3
    u[8] = (u[8] & 0x3f) | 0x80; // variant
    u
}

/// Login Success (clientbound login 0x02): UUID + username + props(0) +
/// session UUID. The trailing `sessionId` is part of the 26.2 codec
/// (see protocol-776.json LOGIN_FINISHED); a 26.2 client fails to decode
/// the packet without it, while older clients reject the extra 16 bytes
/// (those are turned away at handshake by the protocol check instead).
pub fn login_success(username: &str, uuid: &[u8; 16], session_id: &[u8; 16]) -> Vec<u8> {
    let mut p = vec![];
    write_varint(0x02, &mut p);
    p.extend_from_slice(uuid);
    write_string(&mut p, username);
    write_varint(0, &mut p); // properties count
    p.extend_from_slice(session_id);
    p
}

/// Cheap random session UUID (xorshift over system time, variant/version bits set).
pub fn random_session_id() -> [u8; 16] {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| {
            let mut x = d.as_nanos() as u64 | 1;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        })
        .unwrap_or(0x9E37_79B9_7F4A_7C15);
    let mut u = [0u8; 16];
    let mut x = t;
    for chunk in u.chunks_mut(8) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        chunk.copy_from_slice(&x.to_be_bytes());
    }
    u[6] = (u[6] & 0x0f) | 0x40; // v4
    u[8] = (u[8] & 0x3f) | 0x80; // variant
    u
}

/// Login disconnect (clientbound login 0x00) with JSON chat.
pub fn login_disconnect_json(json: &str) -> Vec<u8> {
    let mut p = vec![];
    write_varint(0x00, &mut p);
    write_string(&mut p, json);
    p
}
pub fn status_json(motd: &str, online: usize, max: usize, protocol: i32) -> String {
    json!({
        "version": { "name": "Neptunium 26.2", "protocol": protocol },
        "players": { "max": max, "online": online, "sample": [] },
        "description": { "text": motd },
        "enforcesSecureChat": false,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn varint_roundtrip() {
        for v in [0, 1, 127, 128, 255, 776, 2147483647] {
            let mut b = vec![];
            write_varint(v, &mut b);
            let (r, _) = read_varint(&b).unwrap();
            assert_eq!(r, v);
        }
    }
    #[test]
    fn status_has_776() {
        let s = status_json("x", 0, 20, 776);
        assert!(s.contains("776"));
        assert!(s.contains("Neptunium 26.2"));
    }
}
