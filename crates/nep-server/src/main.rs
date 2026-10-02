use nep_core::{ServerConfig, WorldConfig};
use std::path::PathBuf;

#[derive(Debug)]
struct Args {
    config: PathBuf,
    command: Command,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Command {
    Run,
    ValidateConfig,
    Help,
    Version,
}

fn print_help() {
    println!("Neptunium 0.1.0 — Minecraft Java + Bedrock server\n\nUSAGE:\n    nep-server [run] [OPTIONS]\n    nep-server validate-config [OPTIONS]\n\nOPTIONS:\n    -c, --config <PATH>  Config file [default: neptunium.toml]\n    -h, --help           Print this help\n    -V, --version        Print version\n\nA config path may also be supplied positionally for compatibility.");
}

fn parse_args() -> anyhow::Result<Args> {
    let mut args = std::env::args().skip(1).peekable();
    let mut command = Command::Run;
    let mut config = None;
    let mut first = true;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => command = Command::Help,
            "-V" | "--version" => command = Command::Version,
            "run" if first => command = Command::Run,
            "validate-config" if first => command = Command::ValidateConfig,
            "-c" | "--config" => {
                let value = args.next().ok_or_else(|| anyhow::anyhow!("{arg} requires a path"))?;
                config = Some(PathBuf::from(value));
            }
            _ if arg.starts_with("--config=") => {
                let value = arg.trim_start_matches("--config=");
                anyhow::ensure!(!value.is_empty(), "--config requires a path");
                config = Some(PathBuf::from(value));
            }
            _ if !arg.starts_with('-') && config.is_none() => config = Some(PathBuf::from(arg)),
            _ => anyhow::bail!("unknown or unexpected argument: {arg}"),
        }
        first = false;
    }

    Ok(Args {
        config: config.unwrap_or_else(|| PathBuf::from("neptunium.toml")),
        command,
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = parse_args()?;
    match args.command {
        Command::Help => {
            print_help();
            return Ok(());
        }
        Command::Version => {
            println!("nep-server {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Command::ValidateConfig => {
            anyhow::ensure!(args.config.is_file(), "config file does not exist: {}", args.config.display());
            let (server, world) = load_or_default(&args.config)?;
            println!(
                "Config valid: {} (Java {}, Bedrock {}, max players {}, world '{}')",
                args.config.display(), server.java_port, server.bedrock_port,
                server.max_players, world.name
            );
            return Ok(());
        }
        Command::Run => {}
    }

    tracing_subscriber::fmt().with_target(false).compact().init();
    let (server, world) = load_or_default(&args.config)?;
    tracing::info!(
        "Neptunium 0.1.0 — java 776 / bedrock 924 — {}:{} + udp {}:{} — world '{}' seed {} gen={}",
        server.host,
        server.java_port,
        server.host,
        server.bedrock_port,
        world.name,
        world.seed,
        world.generator,
    );

    // M0 world-gen proof: generate spawn chunks synchronously at boot.
    let spawn_chunks = pregenerate(&world);
    tracing::info!(
        "generated {} spawn chunks, spawn={:?} solid/sample={}",
        spawn_chunks,
        world.spawn,
        sample_solids(&world),
    );

    let j = server.clone();
    let w = world.clone();
    let b = server.clone();
    let bw = world.clone();
    let mut java = tokio::spawn(async move { nep_net::serve_java(j, w).await });
    let mut bedrock = tokio::spawn(async move { nep_net::serve_bedrock(b, bw).await });

    // 20 TPS heartbeat (canonical tick shared by both frontends later).
    let tick = tokio::spawn(async move {
        let mut t: u64 = 0;
        let mut iv = tokio::time::interval(std::time::Duration::from_millis(50));
        loop {
            iv.tick().await;
            t += 1;
            if t % 100 == 0 {
                tracing::info!("tick {t} @20 TPS");
            }
        }
    });

    tokio::select! {
        r = &mut java => {
            r??;
            anyhow::bail!("Java listener stopped unexpectedly");
        }
        r = &mut bedrock => {
            r??;
            anyhow::bail!("Bedrock listener stopped unexpectedly");
        }
        r = tokio::signal::ctrl_c() => {
            r?;
            tracing::info!("shutdown requested; stopping listeners");
            java.abort();
            bedrock.abort();
            tick.abort();
        }
    }
    Ok(())
}

fn pregenerate(world: &WorldConfig) -> usize {
    let mut n = 0;
    for x in -2..=2 {
        for z in -2..=2 {
            let c = nep_world::chunk_for(world, x, z);
            n += 1;
            let _ = c.solid_count();
        }
    }
    n
}

fn sample_solids(world: &WorldConfig) -> usize {
    nep_world::chunk_for(world, 0, 0).solid_count()
}

fn load_or_default(path: &PathBuf) -> anyhow::Result<(ServerConfig, WorldConfig)> {
    #[derive(serde::Deserialize, Default)]
    struct FileConfig {
        #[serde(default)]
        server: ServerConfig,
        #[serde(default)]
        world: WorldConfig,
    }

    let config = match std::fs::read_to_string(path) {
        Ok(text) => toml::from_str::<FileConfig>(&text)
            .map_err(|e| anyhow::anyhow!("invalid config {}: {e}", path.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => FileConfig::default(),
        Err(e) => return Err(e.into()),
    };
    let server = config.server;
    let world = config.world;

    anyhow::ensure!(!server.host.trim().is_empty(), "server.host must not be empty");
    anyhow::ensure!(server.java_port != 0, "server.java_port must be between 1 and 65535");
    anyhow::ensure!(server.bedrock_port != 0, "server.bedrock_port must be between 1 and 65535");
    anyhow::ensure!(server.max_players > 0, "server.max_players must be at least 1");
    anyhow::ensure!(server.max_players <= 100_000, "server.max_players must not exceed 100000");
    anyhow::ensure!(!world.name.trim().is_empty(), "world.name must not be empty");
    anyhow::ensure!(world.generator == "flat", "unsupported world.generator {:?}; currently only 'flat' is available", world.generator);
    Ok((server, world))
}
