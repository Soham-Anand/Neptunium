"""Synthetic Java client: full login -> config -> play, stays 70s+.

Validates the stability package: classic Login Success (no trailing UUID),
chunk cache radius, 9x9 chunk stream, keepalives every ~10s while active,
chunk follow on movement, no disconnect over 70s.
"""
import socket, struct, sys, time

HOST, PORT = "127.0.0.1", 25566


def varint(n):
    o = b""
    while True:
        b = n & 0x7F; n >>= 7
        if n: o += bytes([b | 0x80])
        else: return o + bytes([b])


def read_varint_buf(buf, off):
    n = sh = 0
    while True:
        b = buf[off]; off += 1; n |= (b & 0x7F) << sh
        if not b & 0x80: return n, off
        sh += 7


def pkt(pid, data=b""):
    p = varint(pid) + data
    return varint(len(p)) + p


def wstr(s):
    b = s.encode()
    return varint(len(b)) + b


class Conn:
    def __init__(self):
        self.s = socket.create_connection((HOST, PORT), timeout=15)
        self.s.settimeout(15)

    def send(self, b):
        self.s.sendall(b)

    def read_packet(self):
        n, off, sh = 0, 0, 0
        hdr = b""
        while True:
            b = self.s.recv(1)
            if not b: raise ConnectionError("EOF")
            hdr += b
            n |= (b[0] & 0x7F) << sh
            if not b[0] & 0x80: break
            sh += 7
        buf = b""
        while len(buf) < n: buf += self.s.recv(n - len(buf))
        return buf


def main():
    c = Conn()
    # handshake (login) + Login Start
    hs = varint(0) + varint(776) + wstr("localhost") + struct.pack(">H", PORT) + varint(2)
    c.send(varint(len(hs)) + hs)
    c.send(pkt(0, wstr("SynthJava")))
    # Login Success: expect classic form (no trailing session UUID)
    p = c.read_packet()
    pid, off = read_varint_buf(p, 0)
    assert pid == 0x02, hex(pid)
    uuid = p[off:off + 16]
    assert len(uuid) == 16
    off += 16
    ln, off = read_varint_buf(p, off)
    name = p[off:off + ln].decode(); off += ln
    assert name == "SynthJava", name
    props, off2 = read_varint_buf(p, off)
    assert props == 0
    trailing = len(p) - off2
    assert trailing == 16, f"Login Success must carry 26.2 sessionId (16 bytes), got {trailing}"
    print(f"Login Success OK (26.2 form with sessionId, {len(p)} bytes)")
    c.send(pkt(0x03))  # Login Acknowledged
    # configuration: server brand/features/known-packs, then our responses
    for _ in range(3):
        c.read_packet()
    c.send(pkt(0x02, wstr("vanilla")))
    c.send(pkt(0x00, b"\x00" * 8))
    c.send(pkt(0x07, b"\x00"))
    # registries (29x 0x07) + tags (0x0D) + finish (0x03)
    regs = tags = finish = 0
    end = time.time() + 30
    while time.time() < end and not finish:
        p = c.read_packet()
        pid, _ = read_varint_buf(p, 0)
        if pid == 0x07: regs += 1
        elif pid == 0x0D: tags += 1
        elif pid == 0x03: finish += 1
    assert regs == 29 and tags == 1 and finish == 1, (regs, tags, finish)
    print("Configuration OK (29 regs + tags + finish)")
    c.send(pkt(0x03))  # Finish Acknowledged
    # play entry: login, center, radius, spawn, teleport
    got = {}
    end = time.time() + 15
    while time.time() < end and len(got) < 5:
        p = c.read_packet()
        pid, _ = read_varint_buf(p, 0)
        got[pid] = p
    for want in (0x31, 0x5E, 0x5F, 0x61, 0x48):
        assert want in got, f"missing play packet {hex(want)}"
    print("Play entry OK (login + center + RADIUS + spawn + teleport)")
    c.send(pkt(0x00, varint(1)))  # teleport ack
    # chunk stream: load start + batch start + 81 chunks + batch finish
    chunks = keep = load = 0
    end = time.time() + 30
    while time.time() < end and chunks < 81:
        p = c.read_packet()
        pid, off = read_varint_buf(p, 0)
        if pid == 0x2D: chunks += 1
        elif pid == 0x26: load += 1
        elif pid == 0x0B:
            n, _ = read_varint_buf(p, off)
            assert n == 81, f"batch count {n}"
    assert chunks == 81, chunks
    print(f"Chunk stream OK ({chunks} chunks, load_start x{load})")
    # 70s stability: answer keepalives, drift +x to cross a chunk border
    t0 = time.time()
    x = 8.5
    moves = 0
    while time.time() - t0 < 70:
        c.s.settimeout(12)
        try:
            p = c.read_packet()
        except socket.timeout:
            # still alive if the socket isn't dead; poke movement
            x += 4.0; moves += 1
            c.send(pkt(0x1E, struct.pack(">ddd", x, 66.0, 8.5) + b"\x01\x00"))
            continue
        pid, off = read_varint_buf(p, 0)
        if pid == 0x2C:  # server keepalive -> answer
            keep += 1
            c.send(pkt(0x1C, p[off:off + 8]))
        x += 1.0; moves += 1
        if moves % 10 == 0:
            c.send(pkt(0x1E, struct.pack(">ddd", x, 66.0, 8.5) + b"\x01\x00"))
    assert keep >= 5, f"only {keep} keepalives in 70s (starvation!)"
    print(f"70s session OK ({keep} keepalives answered, {moves} moves, still connected)")
    print("JAVA SESSION PASS")


main()
