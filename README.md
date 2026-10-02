# Neptunium

A fully new Minecraft server architecture in **Rust** — smooth ticking, native cross-play, deep native plugin API.

> Status: early prototype. Boots on localhost, serves Java + Bedrock status, and has a Java login/play path. Multiple Java sessions can connect up to `max_players`; player/world replication is still in progress.

## Why

* **Paper smooth-but-not-smooth:** single-thread tick (20 TPS / 50ms), Java GC pauses. Neptunium: multithreaded Rust core from day one.
* **Geyser ping/instability:** external TCP<->UDP translation + extra hop. Neptunium: native dual-protocol, one canonical world state, no proxy.
* **Inter-mod compat:** Paper API is shallow. Neptunium: purely native, versioned, capability-gated API (Rust + WASM), namespaced registry.

## Targets (26.2)

* Java 26.2 — protocol `776`, data pack `107.0`, resource `88.0`
* Bedrock 26.2 — protocol `924`, server `1.26.2.1`

M1 cross-play proof: Java + Bedrock on same localhost world, move/chat/break-place with equal ping.

## Layout

```
crates/
  nep-core/             canonical state, tick, config, TPS
  nep-world/            flat 26.2 generator stub (Anvil later)
  nep-protocol-java/    varint, status response (776)
  nep-protocol-bedrock/ RakNet handshake + login pipeline (924)
  nep-net/              tokio TCP 25565 + UDP 19132 frontends
  nep-plugin-api/       purely native Plugin trait, EventBus, Registry
  nep-server/           `nep-server` binary, neptunium.toml
```

## Run (localhost)

```bash
cargo run -p nep-server
# or select a config explicitly
cargo run -p nep-server -- run --config ./neptunium.toml
# validate config without starting listeners
cargo run -p nep-server -- validate-config --config ./neptunium.toml
# CLI help
cargo run -p nep-server -- --help
# Java status:  127.0.0.1:25565  (protocol 776)
# Bedrock ping: 127.0.0.1:19132 (protocol 924)
```

Config: `neptunium.toml`

`nep-server` also accepts `-c <path>` and the legacy positional config path. Press Ctrl-C to stop both listeners cleanly.

`server.max_players` limits concurrent Java logins and is reflected in Java server status. Missing configuration files use defaults; malformed TOML or invalid values stop startup with an error.

## Plugin (native, more exposing than Paper)

```rust
use nep_plugin_api::{Plugin, Context, Event};
pub struct PingHud;
impl Plugin for PingHud {
  fn id(&self) -> &'static str { "neptunium:ping-hud" }
  fn on_event(&mut self, ctx: &mut Context, ev: &Event) { /* tick, world, packets */ }
}
```

No Bukkit shim in v1 — purely native by decision.
