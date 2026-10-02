use nep_core::{ServerConfig, WorldConfig, JAVA_26_2_PROTOCOL};
use nep_protocol_bedrock as bedrock;
use nep_protocol_java as java;
use nep_protocol_java::chunk as chunk26;
use nep_protocol_java::config as cfg26;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

/// Serve Java status + login on TCP (26.2 / 776).
pub async fn serve_java(cfg: ServerConfig, world: WorldConfig) -> anyhow::Result<()> {
    let port = cfg.java_port;
    // A permit represents one in-progress or active Java login. Keeping the
    // permit for the lifetime of the connection makes max_players real and
    // gives status pings an accurate online count.
    let players = std::sync::Arc::new(tokio::sync::Semaphore::new(cfg.max_players));
    // Status probes do not use player slots, so cap total open TCP tasks too.
    let connections = std::sync::Arc::new(tokio::sync::Semaphore::new(512));
    // Bind all-local so both `localhost` (-> ::1) and `127.0.0.1` work.
    let listener = bind_tcp(port).await?;
    tracing::info!("java 26.2 status on 0.0.0.0:{port} + [::]:{port} (proto 776)");
    loop {
        let (s, peer) = listener.accept().await?;
        let cfg = cfg.clone();
        let world = world.clone();
        let players = players.clone();
        let Ok(connection_slot) = connections.clone().try_acquire_owned() else {
            tracing::warn!("java {peer}: connection limit reached");
            drop(s);
            continue;
        };
        tokio::spawn(async move {
            let _connection_slot = connection_slot;
            if let Err(e) = handle_java(s, &cfg, &world, players).await {
                tracing::debug!("java {peer}: {e:#}");
            }
        });
    }
}

async fn bind_tcp(port: u16) -> anyhow::Result<TcpListener> {
    // Prefer dual-stack [::]:port (covers 127.0.0.1 + ::1 localhost).
    match TcpListener::bind(format!("[::]:{port}")).await {
        Ok(l) => Ok(l),
        Err(_) => Ok(TcpListener::bind(format!("0.0.0.0:{port}")).await?),
    }
}

async fn handle_java(
    mut s: tokio::net::TcpStream,
    cfg: &ServerConfig,
    world: &WorldConfig,
    players: std::sync::Arc<tokio::sync::Semaphore>,
) -> anyhow::Result<()> {
    // Real client flow:
    // 1. Handshake (id 0x00, next_state 1=status / 2=login)
    // 2a. Status request (id 0x00) -> Status response (id 0x00 + JSON)
    // 2b. Ping (id 0x01 + i64) -> echo, close
    // 3. Login -> disconnect with clear M0 message (join lands in M1)
    let mut next_state: i32 = -1;
    let mut handshake_proto: i32 = 0;
    for _ in 0..6 {
        let payload = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            read_packet(&mut s),
        )
        .await??;
        let Some((pid, mut off)) = java::read_varint(&payload) else {
            anyhow::bail!("bad packet id");
        };
        if next_state == -1 && pid == 0x00 {
            // Handshake: proto varint, host string, port u16, next_state varint
            let Some((proto, n)) = java::read_varint(&payload[off..]) else {
                anyhow::bail!("bad handshake proto");
            };
            off += n;
            handshake_proto = proto;
            let Some((host, n)) = java::read_string(&payload[off..]) else {
                anyhow::bail!("bad handshake host");
            };
            let _ = host;
            off += n;
            let after_port = off.checked_add(2).ok_or_else(|| anyhow::anyhow!("bad handshake length"))?;
            if after_port > payload.len() {
                anyhow::bail!("truncated handshake port");
            }
            off = after_port;
            let Some((ns, _)) = java::read_varint(&payload[off..]) else {
                anyhow::bail!("bad handshake next_state");
            };
            if ns != 1 && ns != 2 {
                anyhow::bail!("unsupported handshake next_state {ns}");
            }
            next_state = ns;
            continue;
        }
        if (next_state == 1 || next_state == -1) && pid == 0x00 {
            // Status request -> response
            let online = cfg.max_players.saturating_sub(players.available_permits());
            let body = java::status_json(&cfg.motd, online, cfg.max_players, JAVA_26_2_PROTOCOL);
            let mut p = vec![];
            java::write_varint(0x00, &mut p);
            write_string(&mut p, &body);
            write_packet(&mut s, &p).await?;
            continue;
        }
        if (next_state == 1 || next_state == -1) && pid == 0x01 {
            // Ping -> echo verbatim, then done
            let mut p = vec![];
            java::write_varint(0x01, &mut p);
            p.extend_from_slice(&payload[off..]);
            write_packet(&mut s, &p).await?;
            return Ok(());
        }
        if next_state == 2 {
            // Reject version-mismatched clients with a readable message
            // instead of letting them die on later packet changes.
            if handshake_proto != JAVA_26_2_PROTOCOL {
                let msg = if handshake_proto < JAVA_26_2_PROTOCOL {
                    "Outdated client! Neptunium needs 26.2 (protocol 776)."
                } else {
                    "Outdated server! Neptunium is 26.2 (protocol 776)."
                };
                let disc = java::login_disconnect_json(&serde_json::json!({"text": msg}).to_string());
                write_packet(&mut s, &disc).await?;
                tracing::info!("login: refused proto {handshake_proto} ({msg})");
                return Ok(());
            }
            // M1a: real login path (offline mode, no encryption).
            // Login Start (serverbound 0x00): name + uuid. Then Login Success,
            // wait for Login Acknowledged (serverbound 0x03), then Configuration.
            let (pid2, off2) = (pid, off);
            if pid2 != 0x00 {
                tracing::info!("login: expected Login Start, got {pid2:#04x}");
                return Ok(());
            }
            let Some((name, _n)) = java::read_string(&payload[off2..]) else {
                tracing::info!("login: bad Login Start name");
                return Ok(());
            };
            if name.is_empty()
                || name.len() > 16
                || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                let disc = java::login_disconnect_json(
                    &serde_json::json!({"text": "Invalid player name"}).to_string(),
                );
                write_packet(&mut s, &disc).await?;
                return Ok(());
            }
            // Reserve only after validating the protocol and name. The owned
            // permit stays alive through configuration and play, and prevents
            // simultaneous logins from exceeding the configured capacity.
            let _player_slot = match players.clone().try_acquire_owned() {
                Ok(slot) => slot,
                Err(_) => {
                    let disc = java::login_disconnect_json(
                        &serde_json::json!({"text": "Server is full"}).to_string(),
                    );
                    write_packet(&mut s, &disc).await?;
                    return Ok(());
                }
            };
            let uuid = java::offline_uuid(&name);
            tracing::info!("login start: name={name} (offline uuid)");
            let success = java::login_success(&name, &uuid, &java::random_session_id());
            write_packet(&mut s, &success).await?;
            // Wait for Login Acknowledged (0x03, empty)
            let ack = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                read_packet(&mut s),
            )
            .await??;
            let Some((ack_id, _)) = java::read_varint(&ack) else {
                return Ok(());
            };
            tracing::info!("login ack: id={ack_id:#04x}");
            if ack_id != 0x03 {
                return Ok(());
            }
            tracing::info!("login: {name} -> configuration (M1a stub)");
            if let Err(e) = handle_configuration(s, cfg, world, &name).await {
                tracing::info!("configuration: {e:#}");
            }
            return Ok(());
        }
        // Unknown single-packet probe (old smoke test): answer status once.
        if next_state == -1 {
            let online = cfg.max_players.saturating_sub(players.available_permits());
            let body = java::status_json(&cfg.motd, online, cfg.max_players, JAVA_26_2_PROTOCOL);
            let mut p = vec![];
            java::write_varint(0x00, &mut p);
            write_string(&mut p, &body);
            write_packet(&mut s, &p).await?;
            return Ok(());
        }
    }
    Ok(())
}

async fn read_byte<R: tokio::io::AsyncRead + Unpin>(s: &mut R) -> anyhow::Result<u8> {
    let mut b = [0u8; 1];
    s.read_exact(&mut b).await?;
    Ok(b[0])
}

async fn read_varint_async<R: tokio::io::AsyncRead + Unpin>(s: &mut R) -> anyhow::Result<i32> {
    let mut num: i32 = 0;
    let mut shift = 0;
    for _ in 0..5 {
        let b = read_byte(s).await?;
        num |= ((b & 0x7F) as i32) << shift;
        if b & 0x80 == 0 {
            return Ok(num);
        }
        shift += 7;
    }
    anyhow::bail!("varint too long")
}

async fn read_packet<R: tokio::io::AsyncRead + Unpin>(s: &mut R) -> anyhow::Result<Vec<u8>> {
    let len = read_varint_async(s).await?;
    if !(0..=1_000_000).contains(&len) {
        anyhow::bail!("bad packet length {len}");
    }
    let mut buf = vec![0u8; len as usize];
    s.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_packet<W: tokio::io::AsyncWrite + Unpin>(s: &mut W, payload: &[u8]) -> anyhow::Result<()> {
    let mut out = vec![];
    java::write_varint(payload.len() as i32, &mut out);
    out.extend_from_slice(payload);
    s.write_all(&out).await?;
    Ok(())
}

fn write_string(out: &mut Vec<u8>, v: &str) {
    let b = v.as_bytes();
    java::write_varint(b.len() as i32, out);
    out.extend_from_slice(b);
}

fn hex(b: &[u8]) -> String {
    b.iter().take(48).map(|x| format!("{x:02x}")).collect::<Vec<_>>().join("")
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// 26.2 configuration in vanilla order: brand -> feature flags -> known
/// packs -> (read client) -> 29 registries -> tags -> finish -> ack -> play.
async fn handle_configuration(
    mut s: tokio::net::TcpStream,
    cfg: &ServerConfig,
    world: &WorldConfig,
    name: &str,
) -> anyhow::Result<()> {
    write_packet(&mut s, &cfg26::brand_packet()).await?;
    write_packet(&mut s, &cfg26::feature_flags_packet()).await?;
    write_packet(&mut s, &cfg26::known_packs_packet()).await?;
    tracing::info!("config {name}: sent brand + features + known packs");

    // Read client pre-finish packets (776): 0x02 brand, 0x00 settings,
    // 0x07 serverbound known packs. Wait for 0x07.
    let mut saw_packs = false;
    for _ in 0..6 {
        let rsp =
            tokio::time::timeout(std::time::Duration::from_secs(10), read_packet(&mut s)).await??;
        let (rid, _) = java::read_varint(&rsp).unwrap_or((-99, 0));
        tracing::info!(
            "config {name}: client -> id={rid:#04x} len={} hex={}",
            rsp.len(),
            hex(&rsp)
        );
        if rid == 0x07 {
            saw_packs = true;
            break;
        }
    }
    if !saw_packs {
        tracing::info!("config {name}: no Known Packs from client, aborting");
        return Ok(());
    }

    // 29 Registry Data packets (vanilla 26.2 bytes, full NBT).
    let regs = cfg26::registry_payloads();
    tracing::info!("config {name}: sending {} registries", regs.len());
    for payload in &regs {
        write_packet(&mut s, payload).await?;
    }

    // Tags, then Finish.
    let tags = cfg26::tags_packet();
    tracing::info!("config {name}: sending tags ({} bytes)", tags.len());
    write_packet(&mut s, &tags).await?;
    write_packet(&mut s, &cfg26::finish_packet()).await?;
    tracing::info!("config {name}: sent Finish Configuration");

    // Wait for Finish Ack (0x03) -> Play.
    match tokio::time::timeout(std::time::Duration::from_secs(15), read_packet(&mut s)).await {
        Ok(Ok(pkt)) => {
            let id = java::read_varint(&pkt).map(|(i, _)| i).unwrap_or(-99);
            tracing::info!(
                "config {name}: post-finish id={id:#04x} len={} hex={}",
                pkt.len(),
                hex(&pkt)
            );
            if id == 0x03 {
                return handle_play(s, cfg, world, name).await;
            }
        }
        Ok(Err(e)) => tracing::info!("config {name}: read end {e:#}"),
        Err(_) => tracing::info!("config {name}: no finish ack"),
    }
    Ok(())
}

/// Radius (in chunks) streamed around the player. 4 => 9x9 on join.
const CHUNK_RADIUS: i32 = 4;

/// Play entry: login -> center + radius -> spawn -> teleport, then stream
/// chunks as the player crosses chunk borders. Packet framing runs in its own
/// task so timer ticks can never cancel a partially received TCP frame.
async fn handle_play(
    s: tokio::net::TcpStream,
    cfg: &ServerConfig,
    world: &WorldConfig,
    name: &str,
) -> anyhow::Result<()> {
    let mut s = s;
    write_packet(&mut s, &cfg26::play_login(world.seed, cfg.max_players)).await?;
    write_packet(&mut s, &cfg26::set_center(0, 0)).await?;
    write_packet(&mut s, &cfg26::chunk_cache_radius(CHUNK_RADIUS)).await?;
    let sp = world.spawn;
    write_packet(&mut s, &cfg26::default_spawn(sp[0], sp[1], sp[2])).await?;
    write_packet(
        &mut s,
        &cfg26::player_position(sp[0] as f64 + 0.5, sp[1] as f64 + 1.0, sp[2] as f64 + 0.5, 1),
    )
    .await?;
    tracing::info!("play {name}: sent login + spawn, teleport id=1");

    // A dedicated reader owns frame assembly, so keepalive timers and chunk
    // writes cannot cancel a partial TCP packet read.
    let (mut reader, mut writer) = s.into_split();
    let (packet_tx, mut packet_rx) = tokio::sync::mpsc::channel::<Result<Vec<u8>, String>>(32);
    let _reader_task = AbortOnDrop(tokio::spawn(async move {
        loop {
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(120),
                read_packet(&mut reader),
            )
            .await
            .map_err(|_| "packet read timed out".to_string())
            .and_then(|r| r.map_err(|e| format!("{e:#}")));
            let done = result.is_err();
            if packet_tx.send(result).await.is_err() || done {
                break;
            }
        }
    }));

    let mut keep_id: i64 = 1;
    let mut pending_keepalives = std::collections::HashMap::<i64, std::time::Instant>::new();
    let mut keep_timer = tokio::time::interval(std::time::Duration::from_secs(10));
    keep_timer.tick().await; // skip the immediate first tick
    let mut sent: std::collections::HashSet<(i32, i32)> = std::collections::HashSet::new();
    let mut center = (sp[0].div_euclid(16), sp[2].div_euclid(16));
    let mut spawned = false;

    loop {
        tokio::select! {
            _ = keep_timer.tick() => {
                let now = std::time::Instant::now();
                if pending_keepalives.values().any(|sent| now.duration_since(*sent) > std::time::Duration::from_secs(30)) {
                    tracing::info!("play {name}: keepalive deadline expired");
                    return Ok(());
                }
                write_packet(&mut writer, &cfg26::keepalive_packet(keep_id)).await?;
                pending_keepalives.insert(keep_id, now);
                tracing::debug!("play {name}: keepalive {keep_id}");
                keep_id += 1;
            }
            received = packet_rx.recv() => {
                match received {
                    Some(Ok(pkt)) => {
                        let id = java::read_varint(&pkt).map(|(i, _)| i).unwrap_or(-99);
                        match id {
                            0x00 => {
                                tracing::info!("play {name}: teleport acked");
                                if !spawned {
                                    spawned = true;
                                    let n = stream_chunks(&mut writer, world.seed, center.0, center.1, true, &mut sent).await?;
                                    tracing::info!("play {name}: streamed {n} spawn chunks");
                                }
                            }
                            0x1c => {
                                let Some(bytes) = pkt.get(1..9) else {
                                    anyhow::bail!("play {name}: malformed keepalive response");
                                };
                                let response = i64::from_be_bytes(bytes.try_into()?);
                                if pending_keepalives.remove(&response).is_some() {
                                    tracing::debug!("play {name}: keepalive {response} answered");
                                } else {
                                    tracing::debug!("play {name}: stale/unknown keepalive response {response}");
                                }
                            }
                            0x0b => {
                                tracing::debug!("play {name}: chunk batch received");
                            }
                            0x1e | 0x1f => {
                                // Movement: follow chunk crossings with fresh chunks.
                                if let Some((cx, cz)) = chunk_of(&pkt) {
                                    if spawned && (cx, cz) != center {
                                        center = (cx, cz);
                                        write_packet(&mut writer, &cfg26::set_center(cx, cz)).await?;
                                        let n = stream_chunks(&mut writer, world.seed, cx, cz, false, &mut sent).await?;
                                        if n > 0 {
                                            tracing::info!("play {name}: streamed {n} chunks at {cx},{cz}");
                                        }
                                    }
                                }
                            }
                            0x0d | 0x20 | 0x21 | 0x3f => {
                                // Tick-end / look-only / swing: routine, stay quiet.
                                tracing::debug!("play {name}: client -> id={id:#04x}");
                            }
                            _ => {
                                tracing::info!(
                                    "play {name}: client -> id={id:#04x} len={} hex={}",
                                    pkt.len(),
                                    hex(&pkt)
                                );
                            }
                        }
                    }
                    Some(Err(e)) => {
                        tracing::info!("play {name}: read failed: {e}");
                        return Ok(());
                    }
                    None => {
                        tracing::info!("play {name}: packet reader stopped");
                        return Ok(());
                    }
                }
            }
        }
    }
}

/// Stream every not-yet-sent chunk in radius around (ccx, ccz).
/// First call also opens with load-start; always framed by batch start/finish.
async fn stream_chunks<W: tokio::io::AsyncWrite + Unpin>(
    s: &mut W,
    seed: u64,
    ccx: i32,
    ccz: i32,
    first: bool,
    sent: &mut std::collections::HashSet<(i32, i32)>,
) -> anyhow::Result<usize> {
    let mut fresh = vec![];
    for dx in -CHUNK_RADIUS..=CHUNK_RADIUS {
        for dz in -CHUNK_RADIUS..=CHUNK_RADIUS {
            let (cx, cz) = (ccx + dx, ccz + dz);
            if sent.insert((cx, cz)) {
                fresh.push((cx, cz));
            }
        }
    }
    if fresh.is_empty() {
        return Ok(0);
    }
    if first {
        write_packet(s, &chunk26::load_start()).await?;
    }
    write_packet(s, &chunk26::batch_start()).await?;
    for (cx, cz) in &fresh {
        write_packet(s, &chunk26::chunk_packet(*cx, *cz, seed)).await?;
    }
    write_packet(s, &chunk26::batch_finished(fresh.len() as i32)).await?;
    Ok(fresh.len())
}

/// Chunk column containing the player, from a 0x1e/0x1f movement packet
/// (x f64 BE at [1..9], z f64 BE at [17..25]).
fn chunk_of(pkt: &[u8]) -> Option<(i32, i32)> {
    if pkt.len() < 25 {
        return None;
    }
    let x = f64::from_be_bytes(pkt[1..9].try_into().ok()?);
    let z = f64::from_be_bytes(pkt[17..25].try_into().ok()?);
    if !x.is_finite() || !z.is_finite() {
        return None;
    }
    Some(( (x.floor() as i32).div_euclid(16), (z.floor() as i32).div_euclid(16) ))
}

/// Serve Bedrock on UDP: unconnected ping + RakNet login pipeline (M1).
/// Offline-style (matches `online_mode = false`): no encryption handshake,
/// Login -> PlayStatus -> empty packs handshake -> StartGame -> spawn.
pub async fn serve_bedrock(cfg: ServerConfig, world: WorldConfig) -> anyhow::Result<()> {
    let port = cfg.bedrock_port;
    let sock = match UdpSocket::bind(format!("[::]:{port}")).await {
        Ok(s) => s,
        Err(_) => UdpSocket::bind(format!("0.0.0.0:{port}")).await?,
    };
    tracing::info!("bedrock 26.2 ping on 0.0.0.0:{port} (proto 924)");
    let mut buf = vec![0u8; 4096];
    let mut sessions: std::collections::HashMap<std::net::SocketAddr, BedrockSession> =
        std::collections::HashMap::new();
    loop {
        let recv = tokio::time::timeout(std::time::Duration::from_secs(5), sock.recv_from(&mut buf)).await;
        let now = std::time::Instant::now();
        if let Ok(Ok((n, peer))) = recv {
            let d = &buf[..n];
            handle_bedrock_datagram(&sock, &cfg, &world, &mut sessions, peer, d).await;
        }
        // Drop stale sessions (client went away mid-login).
        sessions.retain(|peer, s| {
            let alive = now.duration_since(s.last_active) < std::time::Duration::from_secs(20);
            if !alive {
                tracing::info!("bedrock {peer}: session timeout ({})", s.describe());
            }
            alive
        });
    }
}

/// One Bedrock peer's RakNet + login state.
struct BedrockSession {
    mtu: usize,
    client_guid: u64,
    send_seq: u32,
    msg_index: u32,
    order_index: u32,
    split_id: u16,
    splitter: bedrock::raknet::SplitAssembler,
    stage: BedrockStage,
    username: String,
    last_active: std::time::Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BedrockStage {
    Connecting,   // sent reply2, awaiting ConnectionRequest
    Handshaking,  // sent accepted, awaiting NewIncomingConnection
    NetSettings,  // connected, awaiting RequestNetworkSettings
    Login,        // awaiting Login
    PacksInfo,    // sent info, awaiting have_all_packs
    PacksStack,   // sent stack, awaiting completed
    Playing,      // spawned
}

impl BedrockSession {
    fn new(mtu: usize, client_guid: u64) -> Self {
        Self {
            mtu,
            client_guid,
            send_seq: 0,
            msg_index: 0,
            order_index: 0,
            split_id: 0,
            splitter: bedrock::raknet::SplitAssembler::default(),
            stage: BedrockStage::Connecting,
            username: String::new(),
            last_active: std::time::Instant::now(),
        }
    }

    fn describe(&self) -> String {
        if self.username.is_empty() {
            format!("{:?}", self.stage)
        } else {
            format!("{:?} {}", self.stage, self.username)
        }
    }
}

/// Send game packets as one batch (splitting across datagrams if needed).
async fn bedrock_send(
    sock: &UdpSocket,
    peer: &std::net::SocketAddr,
    s: &mut BedrockSession,
    packets: &[Vec<u8>],
) {
    let batch = bedrock::mcpe::encode_batch(packets);
    if batch.len() + 100 < s.mtu {
        let d = bedrock::raknet::encode_frameset(s.send_seq, &mut s.msg_index, &mut s.order_index, &[batch]);
        s.send_seq = s.send_seq.wrapping_add(1);
        let _ = sock.send_to(&d, peer).await;
    } else {
        let parts = bedrock::raknet::encode_split_frameset(
            s.send_seq,
            &mut s.msg_index,
            &mut s.order_index,
            s.split_id,
            s.mtu,
            &batch,
        );
        s.split_id = s.split_id.wrapping_add(1);
        for (seq, d) in parts {
            s.send_seq = s.send_seq.wrapping_add(1);
            let _ = sock.send_to(&d, peer).await;
            let _ = seq;
        }
    }
}

/// Send a single connected control frame (not a batch).
async fn bedrock_send_raw(
    sock: &UdpSocket,
    peer: &std::net::SocketAddr,
    s: &mut BedrockSession,
    payload: Vec<u8>,
) {
    let d = bedrock::raknet::encode_frameset(s.send_seq, &mut s.msg_index, &mut s.order_index, &[payload]);
    s.send_seq = s.send_seq.wrapping_add(1);
    let _ = sock.send_to(&d, peer).await;
}

async fn handle_bedrock_datagram(
    sock: &UdpSocket,
    cfg: &ServerConfig,
    world: &WorldConfig,
    sessions: &mut std::collections::HashMap<std::net::SocketAddr, BedrockSession>,
    peer: std::net::SocketAddr,
    d: &[u8],
) {
    if d.is_empty() {
        return;
    }
    match d[0] {
        0x01 => {
            // Unconnected ping -> pong (server list).
            if !bedrock::is_unconnected_ping(d) {
                return;
            }
            let mote = bedrock::motd(
                &cfg.motd,
                nep_core::BEDROCK_26_2_PROTOCOL,
                "1.26.2",
                sessions.values().filter(|s| s.stage == BedrockStage::Playing).count(),
                cfg.max_players,
                bedrock::raknet::SERVER_GUID,
                "world-26-2",
            );
            let mut out = vec![0x1cu8];
            out.extend_from_slice(&d[1..9]); // echo ping time
            out.extend_from_slice(&bedrock::raknet::SERVER_GUID.to_be_bytes());
            out.extend_from_slice(&bedrock::raknet::MAGIC);
            let mb = mote.as_bytes();
            out.extend_from_slice(&(mb.len() as u16).to_be_bytes());
            out.extend_from_slice(mb);
            let _ = sock.send_to(&out, peer).await;
        }
        0x05 => {
            // Open Connection Request 1 -> Reply 1 (stateless).
            if let Some(mtu) = bedrock::raknet::parse_open_conn_req1(d) {
                let rep = bedrock::raknet::open_conn_reply1(mtu);
                let _ = sock.send_to(&rep, peer).await;
            }
        }
        0x07 => {
            // Open Connection Request 2 -> Reply 2 + create session.
            if let Some((mtu, guid)) = bedrock::raknet::parse_open_conn_req2(d) {
                let rep = bedrock::raknet::open_conn_reply2(&peer, mtu);
                let _ = sock.send_to(&rep, peer).await;
                sessions.insert(peer, BedrockSession::new(mtu, guid));
                tracing::info!("bedrock {peer}: open connection (mtu {mtu})");
            }
        }
        0xC0 | 0xA0 => {
            // ACK/NACK: client confirms our datagrams; nothing to do.
            if let Some(s) = sessions.get_mut(&peer) {
                s.last_active = std::time::Instant::now();
            }
        }
        b if b & 0x80 != 0 => {
            // Connected FrameSet.
            let Some(s) = sessions.get_mut(&peer) else { return };
            s.last_active = std::time::Instant::now();
            let Ok((seq, frames)) = bedrock::raknet::decode_frameset(d).ok_or(()) else { return };
            // ACK immediately (stop-and-wait friendly).
            let ack = bedrock::raknet::encode_ack(&[seq]);
            let _ = sock.send_to(&ack, peer).await;
            // Collect to avoid borrow issues.
            let payloads: Vec<Vec<u8>> = frames.into_iter().map(|f| f.payload).collect();
            for payload in payloads {
                // Split reassembly.
                let whole = match sessions.get_mut(&peer) {
                    Some(s) => s.splitter.feed(&payload),
                    None => return,
                };
                let Some(data) = whole else { continue };
                handle_bedrock_frame(sock, cfg, world, sessions, peer, &data).await;
                if !sessions.contains_key(&peer) {
                    return;
                }
            }
        }
        _ => {}
    }
}

async fn handle_bedrock_frame(
    sock: &UdpSocket,
    cfg: &ServerConfig,
    world: &WorldConfig,
    sessions: &mut std::collections::HashMap<std::net::SocketAddr, BedrockSession>,
    peer: std::net::SocketAddr,
    data: &[u8],
) {
    if data.is_empty() {
        return;
    }
    // Connected handshake packets (raw, not batched).
    if data[0] == 0x09 {
        // ConnectionRequest -> Accepted.
        let Some((guid, req_time)) = bedrock::raknet::parse_connection_request(data) else { return };
        let Some(s) = sessions.get_mut(&peer) else { return };
        if s.stage != BedrockStage::Connecting {
            return;
        }
        s.client_guid = guid;
        s.stage = BedrockStage::Handshaking;
        let acc = bedrock::raknet::connection_accepted(&peer, req_time);
        bedrock_send_raw(sock, &peer, sessions.get_mut(&peer).unwrap(), acc).await;
        tracing::info!("bedrock {peer}: raknet connected");
        return;
    }
    if bedrock::raknet::is_new_incoming(data) {
        if let Some(s) = sessions.get_mut(&peer) {
            if s.stage == BedrockStage::Handshaking {
                s.stage = BedrockStage::NetSettings;
            }
        }
        return;
    }
    if let Some(t) = bedrock::raknet::parse_connected_ping(data) {
        let pong = bedrock::raknet::connected_pong(t);
        if let Some(s) = sessions.get_mut(&peer) {
            bedrock_send_raw(sock, &peer, s, pong).await;
        }
        return;
    }
    if bedrock::raknet::is_disconnect(data) {
        tracing::info!("bedrock {peer}: client disconnected");
        sessions.remove(&peer);
        return;
    }
    // Everything else must be an MCPE batch.
    if data[0] != bedrock::mcpe::BATCH_ID {
        tracing::debug!("bedrock {peer}: unknown frame id={:#04x}", data[0]);
        return;
    }
    let Some(packets) = bedrock::mcpe::decode_batch(data) else {
        tracing::debug!("bedrock {peer}: bad batch ({} bytes)", data.len());
        return;
    };
    for p in packets {
        handle_bedrock_game(sock, cfg, world, sessions, peer, &p).await;
        if !sessions.contains_key(&peer) {
            return;
        }
    }
}

async fn handle_bedrock_game(
    sock: &UdpSocket,
    cfg: &ServerConfig,
    world: &WorldConfig,
    sessions: &mut std::collections::HashMap<std::net::SocketAddr, BedrockSession>,
    peer: std::net::SocketAddr,
    p: &[u8],
) {
    let id = bedrock::mcpe::packet_id(p);
    match id {
        Some(0xC1) => {
            // RequestNetworkSettings -> NetworkSettings.
            if sessions.get(&peer).map(|s| s.stage) != Some(BedrockStage::NetSettings) {
                return;
            }
            if let Some(s) = sessions.get_mut(&peer) {
                s.stage = BedrockStage::Login;
                bedrock_send(sock, &peer, s, &[bedrock::mcpe::network_settings()]).await;
            }
            tracing::info!("bedrock {peer}: network settings sent");
        }
        Some(0x01) => {
            // Login.
            if sessions.get(&peer).map(|s| s.stage) != Some(BedrockStage::Login) {
                return;
            }
            let Some(login) = bedrock::mcpe::parse_login(p) else {
                tracing::info!("bedrock {peer}: malformed login");
                return;
            };
            if login.protocol != nep_core::BEDROCK_26_2_PROTOCOL as i32 {
                tracing::info!(
                    "bedrock {peer}: protocol mismatch (client {} vs {})",
                    login.protocol,
                    nep_core::BEDROCK_26_2_PROTOCOL
                );
                let status = if login.protocol < nep_core::BEDROCK_26_2_PROTOCOL as i32 { 1 } else { 2 };
                if let Some(s) = sessions.get_mut(&peer) {
                    bedrock_send(
                        sock,
                        &peer,
                        s,
                        &[
                            bedrock::mcpe::play_status(status),
                            bedrock::mcpe::disconnect_notice("Outdated client or server (Neptunium 26.2, protocol 924)"),
                        ],
                    )
                    .await;
                }
                sessions.remove(&peer);
                return;
            }
            if let Some(s) = sessions.get_mut(&peer) {
                s.username = login.display_name.clone();
                s.stage = BedrockStage::PacksInfo;
                bedrock_send(
                    sock,
                    &peer,
                    s,
                    &[bedrock::mcpe::play_status(0), bedrock::mcpe::resource_packs_info()],
                )
                .await;
            }
            let name = sessions.get(&peer).map(|s| s.username.clone()).unwrap_or_default();
            tracing::info!("bedrock {peer}: login as {name}");
        }
        Some(0x08) => {
            // ResourcePackClientResponse.
            let stage = sessions.get(&peer).map(|s| s.stage);
            let status = bedrock::mcpe::parse_pack_response(p).unwrap_or(99);
            match (stage, status) {
                (Some(BedrockStage::PacksInfo), 2) | (Some(BedrockStage::PacksInfo), 99) => {
                    if let Some(s) = sessions.get_mut(&peer) {
                        s.stage = BedrockStage::PacksStack;
                        bedrock_send(sock, &peer, s, &[bedrock::mcpe::resource_pack_stack("1.26.2")]).await;
                    }
                }
                (Some(BedrockStage::PacksStack), 3) | (Some(BedrockStage::PacksStack), 99) => {
                    spawn_bedrock_player(sock, cfg, world, sessions, peer).await;
                }
                _ => {
                    tracing::debug!("bedrock {peer}: pack response {status} in {stage:?}");
                }
            }
        }
        Some(0x81) => {
            // ClientCacheStatus: optional blob-cache flag, nothing to do.
        }
        Some(0x09) => {
            // Text (chat from client).
            if let Some((from, text)) = bedrock::mcpe::parse_text(p) {
                let who = if from.is_empty() {
                    sessions.get(&peer).map(|s| s.username.clone()).unwrap_or_default()
                } else {
                    from
                };
                tracing::info!("bedrock chat <{who}> {text}");
            }
        }
        Some(0x90) => {
            // PlayerAuthInput (movement): M1 tracks, full reconcile later.
            tracing::debug!("bedrock {peer}: auth input ({} bytes)", p.len());
        }
        Some(0x13) => {
            tracing::debug!("bedrock {peer}: move player ({} bytes)", p.len());
        }
        Some(other) => {
            tracing::debug!("bedrock {peer}: game packet id={other:#04x} ({} bytes)", p.len());
        }
        None => {}
    }
}

/// Send StartGame + spawn status. Chunk streaming lands next (mirrors Java M1a).
async fn spawn_bedrock_player(
    sock: &UdpSocket,
    cfg: &ServerConfig,
    world: &WorldConfig,
    sessions: &mut std::collections::HashMap<std::net::SocketAddr, BedrockSession>,
    peer: std::net::SocketAddr,
) {
    let Some(s) = sessions.get_mut(&peer) else { return };
    s.stage = BedrockStage::Playing;
    let sp = world.spawn;
    let sg = bedrock::mcpe::start_game(&bedrock::mcpe::StartGameParams {
        seed: world.seed,
        spawn: sp,
        max_players: cfg.max_players,
        motd: &cfg.motd,
        world_name: &world.name,
        game_version: "1.26.2",
    });
    bedrock_send(sock, &peer, s, &[sg]).await;
    let s = sessions.get_mut(&peer).unwrap();
    let greet = bedrock::mcpe::text_system(&format!("Welcome to {} — flat 26.2 world", cfg.motd));
    bedrock_send(sock, &peer, s, &[bedrock::mcpe::play_status(3), greet]).await;
    let name = sessions.get(&peer).map(|s| s.username.clone()).unwrap_or_default();
    tracing::info!("bedrock {peer}: spawned {name} at {sp:?}");
}
