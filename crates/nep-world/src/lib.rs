use nep_core::WorldConfig;

/// Minimal block id for M0 flat world.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Block {
    Air,
    Bedrock,
    Dirt,
    Grass,
}

impl Block {
    pub fn java_state_id(&self) -> u32 {
        match self {
            Block::Air => 0,
            Block::Bedrock => 1,
            Block::Dirt => 2,
            Block::Grass => 3,
        }
    }
}

/// 16x16 chunk section stub, y=0..=79 flat: bedrock, dirt, grass.
#[derive(Debug, Clone)]
pub struct FlatChunk {
    pub x: i32,
    pub z: i32,
    pub seed: u64,
}

impl FlatChunk {
    pub fn block_at(&self, x: u8, y: i32, z: u8) -> Block {
        let _ = (x, z);
        if y == 0 {
            Block::Bedrock
        } else if (1..=60).contains(&y) {
            Block::Dirt
        } else if y == 61 {
            // slight variation by seed so "26.2 world generates" visibly
            let h = self.seed as i64 + self.x as i64 * 31 + self.z as i64 * 17;
            if h.rem_euclid(7) == 0 {
                Block::Dirt
            } else {
                Block::Grass
            }
        } else {
            Block::Air
        }
    }

    /// Count non-air for smoke test.
    pub fn solid_count(&self) -> usize {
        let mut n = 0;
        for y in 0..=79 {
            for x in 0..16 {
                for z in 0..16 {
                    if self.block_at(x, y, z) != Block::Air {
                        n += 1;
                    }
                }
            }
        }
        n
    }
}

pub fn chunk_for(cfg: &WorldConfig, x: i32, z: i32) -> FlatChunk {
    FlatChunk { x, z, seed: cfg.seed }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn flat_world_generates_spawn_layer() {
        let cfg = WorldConfig::default();
        let c = chunk_for(&cfg, 0, 0);
        assert_eq!(c.block_at(8, 0, 8), Block::Bedrock);
        assert_eq!(c.block_at(8, 61, 8,).java_state_id() >= 2, true);
        assert_eq!(c.block_at(8, 70, 8), Block::Air);
        assert!(c.solid_count() > 15000);
    }
}
