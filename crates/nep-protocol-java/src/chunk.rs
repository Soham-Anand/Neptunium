//! Level Chunk With Light (play 0x2D) for Neptunium's flat 26.2 world.
//!
//! Block states (26.2): air 0, grass_block 9, dirt 10, bedrock 85.
//! Biome: plains registry id 40. Sections cover Y -64..319 (24 sections).

use super::config::{write_f32, write_i32, write_i64};
use super::write_varint;

pub const AIR: u32 = 0;
pub const GRASS: u32 = 9;
pub const DIRT: u32 = 10;
pub const BEDROCK: u32 = 85;
pub const PLAINS: u32 = 40;
pub const SECTIONS: usize = 24;
pub const MIN_Y: i32 = -64;

fn state_at(seed: u64, cx: i32, cz: i32, x: u8, y: i32, z: u8) -> u32 {
    let _ = (cx, cz, x, z);
    if y == 0 {
        BEDROCK
    } else if (1..=60).contains(&y) {
        DIRT
    } else if y == 61 {
        let h = seed as i64 + cx as i64 * 31 + cz as i64 * 17;
        if h.rem_euclid(7) == 0 {
            DIRT
        } else {
            GRASS
        }
    } else {
        AIR
    }
}

fn write_palette_single(out: &mut Vec<u8>, value: u32) {
    out.push(0); // bits per entry
    write_varint(value as i32, out);
}

/// Indirect block palette: 26.x maps bpe 1..=4 to FOUR_BITS_LINEAR, so data
/// is always 256 longs (4096 entries x 4 bits, LSB-first nibbles).
fn write_palette_block_indirect(
    out: &mut Vec<u8>,
    palette: &[u32],
    index_of: impl Fn(usize) -> usize,
) {
    out.push(4); // bits per entry (vanilla floor for blocks)
    write_varint(palette.len() as i32, out);
    for v in palette {
        write_varint(*v as i32, out);
    }
    for li in 0..256 {
        let mut w: u64 = 0;
        for b in 0..16 {
            let idx = index_of(li * 16 + b) as u64;
            debug_assert!(idx < 16);
            w |= idx << (b * 4);
        }
        out.extend_from_slice(&w.to_be_bytes());
    }
}

/// Bisect flag: force every section to single-value palettes (debug only).
const SINGLE_VALUE_TEST: bool = false;

fn encode_section(out: &mut Vec<u8>, seed: u64, cx: i32, cz: i32, section: usize) {
    let y0 = MIN_Y + section as i32 * 16;
    let mut count: i32 = 0;
    for ly in 0..16 {
        for x in 0..16 {
            for z in 0..16 {
                if state_at(seed, cx, cz, x, y0 + ly as i32, z) != AIR {
                    count += 1;
                }
            }
        }
    }
    out.extend_from_slice(&(count as i16).to_be_bytes());
    // 26.x LevelChunkSection: nonEmptyBlockCount + fluidCount (both i16).
    // Our flat world has no fluids.
    out.extend_from_slice(&0i16.to_be_bytes());
    if SINGLE_VALUE_TEST {
        // Debug bisect: collapse to one value per section.
        write_palette_single(out, if count == 0 { AIR } else { DIRT });
    } else     if section == 4 {
        // y=0 bedrock (index 0), y=1..15 dirt (index 1).
        write_palette_block_indirect(out, &[BEDROCK, DIRT], |k| usize::from(k / 256 >= 1));
    } else if y0 + 15 < 1 || y0 > 61 {
        write_palette_single(out, AIR);
    } else if y0 >= 1 && y0 + 15 <= 60 {
        write_palette_single(out, DIRT);
    } else {
        // Section 7 (y 48..63): dirt 48..60, grass/dirt 61, air above.
        let h = seed as i64 + cx as i64 * 31 + cz as i64 * 17;
        let top_is_dirt = h.rem_euclid(7) == 0;
        write_palette_block_indirect(out, &[DIRT, GRASS, AIR], |k| {
            let y = y0 + (k / 256) as i32;
            if y <= 60 {
                0
            } else if y == 61 {
                usize::from(!top_is_dirt)
            } else {
                2
            }
        });
    }
    // Biome: single plains everywhere.
    write_palette_single(out, PLAINS);
}

fn heightmap_longs(value: i32) -> Vec<u8> {
    // 256 entries x 9 bits, LSB-first across 36 longs.
    let mut bits = [false; 256 * 9];
    for k in 0..256 {
        for bit in 0..9 {
            bits[k * 9 + bit] = ((value >> bit) & 1) != 0;
        }
    }
    let mut out = vec![];
    for li in 0..36 {
        let mut w: u64 = 0;
        for b in 0..64 {
            if bits[li * 64 + b] {
                w |= 1 << b;
            }
        }
        out.extend_from_slice(&w.to_be_bytes());
    }
    out
}

/// Full clientbound Level Chunk With Light (0x2D) packet.
pub fn chunk_packet(cx: i32, cz: i32, seed: u64) -> Vec<u8> {
    let mut p = vec![];
    write_varint(0x2D, &mut p);
    write_i32(&mut p, cx);
    write_i32(&mut p, cz);
    // Heightmaps: WORLD_SURFACE(1) + MOTION_BLOCKING(4), top = 62.
    write_varint(2, &mut p);
    for t in [1, 4] {
        write_varint(t, &mut p);
        let h = heightmap_longs(62);
        write_varint((h.len() / 8) as i32, &mut p);
        p.extend_from_slice(&h);
    }
    // Sections.
    let mut data = vec![];
    for s in 0..SECTIONS {
        encode_section(&mut data, seed, cx, cz, s);
    }
    write_varint(data.len() as i32, &mut p);
    p.extend_from_slice(&data);
    // No block entities.
    write_varint(0, &mut p);
    // Light: full skylight, no block light.
    write_varint(1, &mut p); // sky mask longs
    write_i64(&mut p, 0x3FFFFFF); // 26 sections
    write_varint(0, &mut p); // block mask
    write_varint(0, &mut p); // empty sky mask
    write_varint(1, &mut p); // empty block mask longs
    write_i64(&mut p, 0x3FFFFFF);
    write_varint(26, &mut p); // 26 sky arrays
    for _ in 0..26 {
        write_varint(2048, &mut p);
        p.extend_from_slice(&[0xFF; 2048]);
    }
    write_varint(0, &mut p); // no block arrays
    p
}

/// Chunk Batch Start 0x0C (empty) / Finished 0x0B (count).
pub fn batch_start() -> Vec<u8> {
    vec![0x0C]
}

pub fn batch_finished(n: i32) -> Vec<u8> {
    let mut p = vec![];
    write_varint(0x0B, &mut p);
    write_varint(n, &mut p);
    p
}

/// Game Event 0x26 reason 13 = LEVEL_CHUNKS_LOAD_START.
pub fn load_start() -> Vec<u8> {
    let mut p = vec![];
    write_varint(0x26, &mut p);
    p.push(13);
    write_f32(&mut p, 0.0);
    p
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Strict reader replicating vanilla PalettedContainer/section decoding.
    /// Returns bytes consumed or error position.
    struct Reader<'a> {
        b: &'a [u8],
        pos: usize,
    }
    impl<'a> Reader<'a> {
        fn byte(&mut self) -> u8 {
            let v = self.b[self.pos];
            self.pos += 1;
            v
        }
        fn varint(&mut self) -> i32 {
            let mut n = 0;
            let mut s = 0;
            loop {
                let x = self.byte();
                n |= ((x & 0x7F) as i32) << s;
                if x & 0x80 == 0 {
                    return n;
                }
                s += 7;
            }
        }
        fn bytes(&mut self, n: usize) {
            self.pos += n;
        }
        fn container(&mut self, is_block: bool) {
            let bpe = self.byte();
            if bpe == 0 {
                self.varint(); // single value, no data
            } else {
                let len = self.varint();
                for _ in 0..len {
                    self.varint();
                }
                // vanilla data longs = ceil(4096 * bpe / 64)
                let longs = (4096 * bpe as usize + 63) / 64;
                self.bytes(longs * 8);
            }
            let _ = is_block;
        }
    }
    #[test]
    fn chunk_packet_shape() {
        let c = chunk_packet(0, 0, 262);
        assert_eq!(c[0], 0x2D);
        assert!(c.len() > 50000); // skylight dominates
    }
    #[test]
    fn debug_sizes() {
        let mut total = 0;
        for s in 0..SECTIONS {
            let mut v = vec![];
            encode_section(&mut v, 262, 0, 0, s);
            total += v.len();
        }
        // print full hex of the two indirect sections for the Java harness
        for s in [4usize, 7usize] {
            let mut v = vec![];
            encode_section(&mut v, 262, 0, 0, s);
            let h: String = v.iter().map(|x| format!("{x:02x}")).collect();
            println!("SEC{s} len={} hex={h}", v.len());
        }
        println!("sections total: {total}");
    }
    #[test]
    fn strict_decode_sections() {
        let c = chunk_packet(0, 0, 262);
        let mut r = Reader { b: &c, pos: 0 };
        assert_eq!(r.varint(), 0x2D);
        assert_eq!(i32::from_be_bytes([r.b[r.pos], r.b[r.pos + 1], r.b[r.pos + 2], r.b[r.pos + 3]]), 0);
        r.bytes(4);
        r.bytes(4);
        let maps = r.varint();
        assert_eq!(maps, 2);
        for _ in 0..maps {
            r.varint();
            let n = r.varint();
            r.bytes(n as usize * 8);
        }
        let dlen = r.varint() as usize;
        let end = r.pos + dlen;
        for s in 0..SECTIONS {
            r.bytes(2); // block count
            r.bytes(2); // fluid count (26.x)
            let before = r.pos;
            r.container(true);
            r.container(false);
            let _ = (s, before);
        }
        assert_eq!(r.pos, end, "section bytes must exactly fill chunkData");
    }
    #[test]
    fn section4_counts() {
        let mut s = vec![];
        encode_section(&mut s, 262, 0, 0, 4);
        let count = i16::from_be_bytes([s[0], s[1]]);
        assert_eq!(count, 4096);
    }
    #[test]
    fn air_section_counts() {
        let mut s = vec![];
        encode_section(&mut s, 262, 0, 0, 0);
        let count = i16::from_be_bytes([s[0], s[1]]);
        assert_eq!(count, 0);
    }
    #[test]
    fn top_section_counts() {
        let mut s = vec![];
        encode_section(&mut s, 262, 0, 0, 7);
        let count = i16::from_be_bytes([s[0], s[1]]);
        assert_eq!(count, 3584);
    }
}
