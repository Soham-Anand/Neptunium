/// Purely native Neptunium plugin API. No Bukkit shim.
/// More exposing than Paper: tick, world, packets (java+bedrock), registry, scheduler.
#[derive(Debug, Clone)]
pub enum Event {
    Tick { tick: u64 },
    PlayerChat { player: String, text: String },
    BlockPlace { player: String, x: i32, y: i32, z: i32 },
}

#[derive(Debug, Default)]
pub struct Context {
    pub tick: u64,
    pub log: Vec<String>,
}

impl Context {
    pub fn push(&mut self, s: impl Into<String>) {
        self.log.push(s.into());
    }
}

pub trait Plugin: Send {
    fn id(&self) -> &'static str;
    fn on_event(&mut self, ctx: &mut Context, ev: &Event);
}

/// Capability manifest — deep access must be declared.
#[derive(Debug, Clone)]
pub struct Manifest {
    pub id: String,
    pub world_write: bool,
    pub packets_raw: Vec<String>,
    pub tick_hook: bool,
}
