//! Minimal RakNet server-side implementation for Bedrock 26.2.
//!
//! Covers exactly what a localhost dev server needs:
//! unconnected Open-Connection handshake (0x05-0x08), connected FrameSets
//! (0x80-0x8F) with ReliableOrdered frames, split reassembly, ACKs, and the
//! connected handshake (ConnectionRequest 0x09 / Accepted 0x10 /
//! NewIncomingConnection 0x13, ConnectedPing 0x00 / Pong 0x03).
//!
//! Field layouts follow the de-facto RakNet wire format used by the vanilla
//! client (triads are little-endian, split headers big-endian).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

/// RakNet magic shared by every unconnected packet.
pub const MAGIC: [u8; 16] = [
    0x00, 0xFF, 0xFF, 0x00, 0xFE, 0xFE, 0xFE, 0xFE, 0xFD, 0xFD, 0xFD, 0xFD, 0x12, 0x34, 0x56,
    0x78,
];

/// RakNet protocol version the vanilla client speaks.
pub const RAKNET_PROTOCOL_VERSION: u8 = 11;

/// Server GUID advertised in Open Connection Reply 1/2 ("NEPTUNIU").
pub const SERVER_GUID: u64 = 0x4E45_5054_554E_4955;

/// Cap on negotiated MTU so oversized datagrams never hit the loopback path.
pub const MAX_MTU: usize = 1400;
/// Floor below which we refuse to play (client would fragment anyway).
pub const MIN_MTU: usize = 400;

fn has_magic(d: &[u8], at: usize) -> bool {
    d.len() >= at + 16 && d[at..at + 16] == MAGIC
}

fn put_triad_le(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&[(v & 0xFF) as u8, ((v >> 8) & 0xFF) as u8, ((v >> 16) & 0xFF) as u8]);
}

fn get_triad_le(d: &[u8]) -> u32 {
    d[0] as u32 | ((d[1] as u32) << 8) | ((d[2] as u32) << 16)
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---- RakNet SystemAddress encode ----

/// Encode a socket address RakNet-style: family(4/6) + ip bytes + port BE.
pub fn write_address(out: &mut Vec<u8>, addr: &SocketAddr) {
    match addr.ip() {
        IpAddr::V4(v4) => {
            out.push(4);
            out.extend_from_slice(&v4.octets());
            out.extend_from_slice(&addr.port().to_be_bytes());
        }
        IpAddr::V6(v6) => {
            out.push(6);
            out.extend_from_slice(&16u16.to_be_bytes()); // AF family marker used on wire
            out.extend_from_slice(&addr.port().to_be_bytes());
            out.extend_from_slice(&v6.octets());
        }
    }
}

/// Placeholder internal address (255.255.255.255:0), as vanilla sends.
pub fn write_internal_address(out: &mut Vec<u8>) {
    out.push(4);
    out.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
    out.extend_from_slice(&[0x00, 0x00]);
}

// ---- Unconnected handshake ----

/// Parse Open Connection Request 1 (0x05). Returns negotiated MTU.
pub fn parse_open_conn_req1(d: &[u8]) -> Option<usize> {
    if d.first() != Some(&0x05) || !has_magic(d, 1) {
        return None;
    }
    if d.get(17) != Some(&RAKNET_PROTOCOL_VERSION) {
        return None;
    }
    // MTU = whole datagram + IP/UDP overhead.
    let mtu = (d.len() + 28).clamp(MIN_MTU, MAX_MTU);
    Some(mtu)
}

/// Open Connection Reply 1 (0x06).
pub fn open_conn_reply1(mtu: usize) -> Vec<u8> {
    let mut out = vec![0x06];
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&SERVER_GUID.to_be_bytes());
    out.push(0x00); // no security
    out.extend_from_slice(&(mtu as u16).to_be_bytes());
    out
}

/// Parse Open Connection Request 2 (0x07). Returns (mtu, client guid).
/// The server address field is variable length, so mtu/guid are read from
/// the tail: [...][mtu u16 BE][client guid u64 BE].
pub fn parse_open_conn_req2(d: &[u8]) -> Option<(usize, u64)> {
    if d.first() != Some(&0x07) || !has_magic(d, 1) || d.len() < 34 {
        return None;
    }
    let n = d.len();
    let mtu =
        u16::from_be_bytes([d[n - 10], d[n - 9]]) as usize;
    let guid = u64::from_be_bytes(d[n - 8..n].try_into().ok()?);
    if !(MIN_MTU..=MAX_MTU + 100).contains(&mtu) {
        return None;
    }
    Some((mtu.min(MAX_MTU), guid))
}

/// Open Connection Reply 2 (0x08).
pub fn open_conn_reply2(peer: &SocketAddr, mtu: usize) -> Vec<u8> {
    let mut out = vec![0x08];
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&SERVER_GUID.to_be_bytes());
    write_address(&mut out, peer);
    out.extend_from_slice(&(mtu as u16).to_be_bytes());
    out.push(0x00); // no encryption
    out
}

// ---- Connected frames ----

/// Reliability classes (upper 3 bits of the frame flags byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reliability {
    Unreliable = 0,
    UnreliableSequenced = 1,
    Reliable = 2,
    ReliableOrdered = 3,
    ReliableSequenced = 4,
}

impl Reliability {
    fn from_flags(flags: u8) -> Option<Self> {
        match (flags >> 5) & 0x07 {
            0 => Some(Self::Unreliable),
            1 => Some(Self::UnreliableSequenced),
            2 => Some(Self::Reliable),
            3 => Some(Self::ReliableOrdered),
            4 => Some(Self::ReliableSequenced),
            _ => None,
        }
    }
}

/// One decapsulated frame payload with its reliability.
#[derive(Debug, Clone)]
pub struct Frame {
    pub reliability: Reliability,
    pub payload: Vec<u8>,
}

/// Decode a connected FrameSet (0x80-0x8F) into frames.
/// Returns (datagram sequence, frames).
pub fn decode_frameset(d: &[u8]) -> Option<(u32, Vec<Frame>)> {
    if d.len() < 4 || d[0] & 0x80 == 0 {
        return None;
    }
    let seq = get_triad_le(&d[1..4]);
    let mut frames = vec![];
    let mut off = 4;
    while off < d.len() {
        if off + 3 > d.len() {
            return None;
        }
        let flags = d[off];
        let rel = Reliability::from_flags(flags)?;
        let split = flags & 0x10 != 0;
        let bitlen = u16::from_be_bytes([d[off + 1], d[off + 2]]) as usize;
        let bytelen = bitlen.div_ceil(8);
        off += 3;
        // Reliable indices.
        if rel as u8 >= 2 {
            if off + 3 > d.len() {
                return None;
            }
            off += 3; // message index
        }
        // Sequenced / ordered indices.
        match rel {
            Reliability::UnreliableSequenced | Reliability::ReliableSequenced => {
                if off + 3 > d.len() {
                    return None;
                }
                off += 3;
            }
            Reliability::ReliableOrdered => {
                if off + 4 > d.len() {
                    return None;
                }
                off += 4; // order index (3) + order channel (1)
            }
            _ => {}
        }
        // Split header (handled by the assembler, not here).
        let (split_count, split_id, split_index) = if split {
            if off + 10 > d.len() {
                return None;
            }
            let c = u32::from_be_bytes(d[off..off + 4].try_into().ok()?);
            let id = u16::from_be_bytes([d[off + 4], d[off + 5]]);
            let idx = u32::from_be_bytes(d[off + 6..off + 10].try_into().ok()?);
            off += 10;
            (c, id, idx)
        } else {
            (1, 0, 0)
        };
        if off + bytelen > d.len() {
            return None;
        }
        let mut payload = d[off..off + bytelen].to_vec();
        off += bytelen;
        if split {
            // Tag split fragments so the assembler can pick them up. The
            // payload keeps a small header the assembler strips.
            let mut tagged = vec![0xFF, 0x53, 0x50, 0x4C]; // "SPL"
            tagged.extend_from_slice(&split_count.to_be_bytes());
            tagged.extend_from_slice(&split_id.to_be_bytes());
            tagged.extend_from_slice(&split_index.to_be_bytes());
            tagged.append(&mut payload);
            payload = tagged;
        }
        frames.push(Frame { reliability: rel, payload });
    }
    Some((seq, frames))
}

pub fn is_split_fragment(payload: &[u8]) -> bool {
    payload.len() > 12 && payload[0..4] == [0xFF, 0x53, 0x50, 0x4C]
}

/// Reassembles split frame payloads. Feed each frame payload; returns the
/// complete payload once all fragments arrived.
#[derive(Debug, Default)]
pub struct SplitAssembler {
    pending: HashMap<u16, Vec<Option<Vec<u8>>>>,
}

impl SplitAssembler {
    /// Returns Some(complete) when the fragment completes a datagram.
    pub fn feed(&mut self, tagged: &[u8]) -> Option<Vec<u8>> {
        if !is_split_fragment(tagged) {
            return Some(tagged.to_vec());
        }
        let count = u32::from_be_bytes(tagged[4..8].try_into().ok()?) as usize;
        let id = u16::from_be_bytes([tagged[8], tagged[9]]);
        let index = u32::from_be_bytes(tagged[10..14].try_into().ok()?) as usize;
        if count == 0 || count > 128 || index >= count {
            return None;
        }
        let entry = self.pending.entry(id).or_insert_with(|| vec![None; count]);
        if entry.len() != count {
            return None;
        }
        entry[index] = Some(tagged[14..].to_vec());
        if entry.iter().all(|s| s.is_some()) {
            let mut out = vec![];
            for s in entry.iter().flatten() {
                out.extend_from_slice(s);
            }
            self.pending.remove(&id);
            Some(out)
        } else {
            None
        }
    }
}

/// Encode one connected FrameSet with ReliableOrdered frames (channel 0).
/// `msg_index` is the running reliable index; `seq` the datagram sequence.
pub fn encode_frameset(seq: u32, msg_index: &mut u32, order_index: &mut u32, payloads: &[Vec<u8>]) -> Vec<u8> {
    let mut out = vec![0x80];
    put_triad_le(&mut out, seq);
    for p in payloads {
        out.push(0x60); // ReliableOrdered, no split
        out.extend_from_slice(&((p.len() * 8) as u16).to_be_bytes());
        put_triad_le(&mut out, *msg_index);
        *msg_index = msg_index.wrapping_add(1);
        put_triad_le(&mut out, *order_index);
        *order_index = order_index.wrapping_add(1);
        out.push(0x00); // order channel
        out.extend_from_slice(p);
    }
    out
}

/// Encode a FrameSet whose single payload is split across fragments.
pub fn encode_split_frameset(
    seq_start: u32,
    msg_index: &mut u32,
    order_index: &mut u32,
    split_id: u16,
    mtu: usize,
    payload: &[u8],
) -> Vec<(u32, Vec<u8>)> {
    let budget = mtu.saturating_sub(120).max(200);
    let count = payload.len().div_ceil(budget).max(1) as u32;
    let mut datagrams = vec![];
    for (i, chunk) in payload.chunks(budget).enumerate() {
        let mut out = vec![0x80];
        let seq = seq_start.wrapping_add(i as u32);
        put_triad_le(&mut out, seq);
        out.push(0x70); // ReliableOrdered + split
        out.extend_from_slice(&((chunk.len() * 8) as u16).to_be_bytes());
        put_triad_le(&mut out, *msg_index);
        *msg_index = msg_index.wrapping_add(1);
        put_triad_le(&mut out, *order_index);
        *order_index = order_index.wrapping_add(1);
        out.push(0x00);
        out.extend_from_slice(&count.to_be_bytes());
        out.extend_from_slice(&split_id.to_be_bytes());
        out.extend_from_slice(&(i as u32).to_be_bytes());
        out.extend_from_slice(chunk);
        datagrams.push((seq, out));
    }
    datagrams
}

/// Encode an ACK (0xC0) for the given datagram sequences (single entries).
pub fn encode_ack(seqs: &[u32]) -> Vec<u8> {
    let mut out = vec![0xC0];
    out.extend_from_slice(&(seqs.len() as u16).to_be_bytes());
    for s in seqs {
        out.push(0x01); // single sequence (not a range)
        put_triad_le(&mut out, *s);
    }
    out
}

/// Decode ACK/NACK record counts (payloads are only logged, not processed).
pub fn is_ack(d: &[u8]) -> bool {
    d.first() == Some(&0xC0) || d.first() == Some(&0xA0)
}

// ---- Connected handshake packets (inside frames) ----

/// Parse Connection Request (0x09). Returns (client guid, request time).
pub fn parse_connection_request(p: &[u8]) -> Option<(u64, u64)> {
    if p.first() != Some(&0x09) || p.len() < 1 + 8 + 8 + 1 {
        return None;
    }
    let guid = u64::from_be_bytes(p[1..9].try_into().ok()?);
    let time = u64::from_be_bytes(p[9..17].try_into().ok()?);
    Some((guid, time))
}

/// Connection Request Accepted (0x10).
pub fn connection_accepted(peer: &SocketAddr, request_time: u64) -> Vec<u8> {
    let mut out = vec![0x10];
    write_address(&mut out, peer);
    out.extend_from_slice(&0u16.to_be_bytes()); // system index
    for _ in 0..10 {
        write_internal_address(&mut out);
    }
    out.extend_from_slice(&request_time.to_be_bytes());
    out.extend_from_slice(&now_ms().to_be_bytes());
    out
}

/// True if the frame payload is New Incoming Connection (0x13).
pub fn is_new_incoming(p: &[u8]) -> bool {
    p.first() == Some(&0x13)
}

/// Parse Connected Ping (0x00). Returns client send time.
pub fn parse_connected_ping(p: &[u8]) -> Option<u64> {
    if p.first() != Some(&0x00) || p.len() < 9 {
        return None;
    }
    Some(u64::from_be_bytes(p[1..9].try_into().ok()?))
}

/// Connected Pong (0x03).
pub fn connected_pong(client_time: u64) -> Vec<u8> {
    let mut out = vec![0x03];
    out.extend_from_slice(&client_time.to_be_bytes());
    out.extend_from_slice(&now_ms().to_be_bytes());
    out
}

/// True if the frame payload is a Disconnect notification (0x15).
pub fn is_disconnect(p: &[u8]) -> bool {
    p.first() == Some(&0x15)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn peer() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 55055)
    }

    #[test]
    fn open_conn_req1_roundtrip() {
        let mut req = vec![0x05];
        req.extend_from_slice(&MAGIC);
        req.push(RAKNET_PROTOCOL_VERSION);
        req.extend(vec![0u8; 1400 - req.len()]);
        let mtu = parse_open_conn_req1(&req).unwrap();
        assert!(mtu >= MIN_MTU);
        let rep = open_conn_reply1(mtu);
        assert_eq!(rep[0], 0x06);
        assert_eq!(&rep[1..17], &MAGIC);
    }

    #[test]
    fn open_conn_req2_roundtrip() {
        let mut req = vec![0x07];
        req.extend_from_slice(&MAGIC);
        req.push(4);
        req.extend_from_slice(&[127, 0, 0, 1]);
        req.extend_from_slice(&55055u16.to_be_bytes());
        req.extend_from_slice(&1400u16.to_be_bytes());
        req.extend_from_slice(&12345u64.to_be_bytes());
        let (mtu, guid) = parse_open_conn_req2(&req).unwrap();
        assert_eq!(mtu, 1400);
        assert_eq!(guid, 12345);
        let rep = open_conn_reply2(&peer(), mtu);
        assert_eq!(rep[0], 0x08);
    }

    #[test]
    fn frameset_roundtrip() {
        let mut mi = 0;
        let mut oi = 0;
        let payloads = vec![vec![0xFE, 1, 2, 3], vec![0x00, 9, 8, 7]];
        let d = encode_frameset(7, &mut mi, &mut oi, &payloads);
        let (seq, frames) = decode_frameset(&d).unwrap();
        assert_eq!(seq, 7);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].payload, payloads[0]);
        assert_eq!(frames[0].reliability, Reliability::ReliableOrdered);
    }

    #[test]
    fn split_roundtrip() {
        let big = vec![0xABu8; 5000];
        let mut mi = 0;
        let mut oi = 0;
        let parts = encode_split_frameset(0, &mut mi, &mut oi, 42, 1400, &big);
        assert!(parts.len() > 1);
        let mut asm = SplitAssembler::default();
        let mut done = None;
        for (_, d) in &parts {
            let (_, frames) = decode_frameset(d).unwrap();
            assert_eq!(frames.len(), 1);
            if let Some(whole) = asm.feed(&frames[0].payload) {
                done = Some(whole);
            }
        }
        assert_eq!(done.unwrap(), big);
    }

    #[test]
    fn conn_handshake_roundtrip() {
        let mut req = vec![0x09];
        req.extend_from_slice(&999u64.to_be_bytes());
        req.extend_from_slice(&1111u64.to_be_bytes());
        req.push(0x00);
        let (guid, t) = parse_connection_request(&req).unwrap();
        assert_eq!((guid, t), (999, 1111));
        let acc = connection_accepted(&peer(), t);
        assert_eq!(acc[0], 0x10);
        assert_eq!(parse_connected_ping(&[0x00, 1, 2, 3, 4, 5, 6, 7, 8]).unwrap(), 0x0102030405060708);
        assert!(is_new_incoming(&[0x13, 0, 0]));
        assert!(is_ack(&[0xC0, 0, 1, 1, 0, 0, 0]));
    }
}
