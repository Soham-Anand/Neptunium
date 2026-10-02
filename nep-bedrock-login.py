"""Synthetic Bedrock client: full RakNet + login pipeline against Neptunium.

Speaks real RakNet (open-conn, frames, ACKs) and MCPE batches
(RequestNetworkSettings -> Login -> packs -> StartGame -> spawn) and asserts
the server drives the whole flow. Mirrors crates/nep-protocol-bedrock.
"""
import base64, json, random, socket, struct, sys, time, zlib

HOST, PORT = "127.0.0.1", 19133
MAGIC = bytes([0x00, 0xFF, 0xFF, 0x00, 0xFE, 0xFE, 0xFE, 0xFE,
               0xFD, 0xFD, 0xFD, 0xFD, 0x12, 0x34, 0x56, 0x78])
MTU = 1400
CLIENT_GUID = random.getrandbits(63)


def uvarint(v):
    o = b""
    while True:
        b = v & 0x7F; v >>= 7
        o += bytes([b | (0x80 if v else 0)])
        if not v: return o


def read_uvarint(buf, off):
    v = s = 0
    while True:
        b = buf[off]; off += 1; v |= (b & 0x7F) << s
        if not b & 0x80: return v, off
        s += 7


def wstr(out, s):
    b = s.encode(); return out + uvarint(len(b)) + b


def triad(v):
    return struct.pack("<I", v)[:3]


def jwt(payload):
    def b64(o):
        return base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
    return f"{b64({'alg': 'none'})}.{b64(payload)}."


def build_login(protocol, name):
    chain = jwt({"extraData": {"displayName": name, "identity": "0" * 36, "XUID": "0"}})
    identity = json.dumps({"Certificate": json.dumps({"chain": [chain]})})
    client = jwt({"DisplayName": name})
    ib, cb = identity.encode(), client.encode()
    tokens = struct.pack("<H", len(ib)) + ib + struct.pack("<H", len(cb)) + cb
    return uvarint(1) + struct.pack(">i", protocol) + uvarint(len(tokens)) + tokens


def batch(*pkts):
    raw = b"".join(uvarint(len(p)) + p for p in pkts)
    return b"\xfe" + zlib.compress(raw)


def unbatch(d):
    assert d[:1] == b"\xfe", d[:8]
    try:
        raw = zlib.decompress(d[1:])
    except Exception:
        raw = d[1:]
    out, off = [], 0
    while off < len(raw):
        ln, off = read_uvarint(raw, off)
        out.append(raw[off:off + ln]); off += ln
    return out


class Conn:
    def __init__(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.settimeout(3)
        self.seq = 0; self.mi = 0; self.oi = 0

    def send(self, b):
        self.s.sendto(b, (HOST, PORT))

    def recv(self):
        d, _ = self.s.recvfrom(4096)
        return d

    def frameset(self, *payloads):
        o = b"\x80" + triad(self.seq); self.seq += 1
        for p in payloads:
            o += b"\x60" + struct.pack(">H", len(p) * 8) + triad(self.mi) + triad(self.oi) + b"\x00" + p
            self.mi += 1; self.oi += 1
        self.send(o)

    def read_frames(self, want_ack=True):
        """Recv until a frameset arrives; ACK it; return inner payloads."""
        while True:
            d = self.recv()
            if d[:1] == b"\xc0" or d[:1] == b"\xa0":
                continue
            if d[0] & 0x80 == 0:
                continue  # unconnected reply; caller handles
            seq = struct.unpack("<I", d[1:4] + b"\x00")[0]
            if want_ack:
                self.send(b"\xc0" + struct.pack(">H", 1) + b"\x01" + triad(seq))
            out, off = [], 4
            while off < len(d):
                flags = d[off]; rel = (flags >> 5) & 7; off += 3
                ln = struct.unpack(">H", d[off - 2:off])[0] // 8
                if rel >= 2: off += 3
                if rel in (1, 4): off += 3
                if rel == 3: off += 4
                if flags & 0x10:
                    n = struct.unpack(">I", d[off:off + 4])[0]
                    frags = []
                    for _ in range(n):
                        fl = struct.unpack(">H", d[off + 1:off + 3])[0] // 8
                        frags.append(d[off + 3:off + 3 + fl]); off += 3 + fl
                    out.append(b"".join(frags))
                else:
                    out.append(d[off:off + ln]); off += ln
            return out


def expect_batch(conn, timeout=5):
    """Collect game packets until a non-empty batch arrives."""
    end = time.time() + timeout
    got = []
    while time.time() < end:
        try:
            for p in conn.read_frames():
                if p[:1] == b"\xfe":
                    got += unbatch(p)
                # else: control frame (pong etc.) — keep waiting
        except socket.timeout:
            break
        if got:
            break
    return got


def main():
    c = Conn()
    # 1. Open Connection Request 1 (pad to MTU) -> Reply 1
    req1 = b"\x05" + MAGIC + bytes([11]) + bytes(MTU - 18)
    for _ in range(3):
        c.send(req1)
        try:
            d = c.recv()
            if d[:1] == b"\x06": break
        except socket.timeout:
            continue
    else:
        sys.exit("FAIL: no OpenConn Reply1")
    mtu = struct.unpack(">H", d[-2:])[0]
    print(f"RakNet open1 OK (mtu {mtu})")

    # 2. Request 2 -> Reply 2
    req2 = b"\x07" + MAGIC + bytes([4, 127, 0, 0, 1]) + struct.pack(">H", PORT)
    req2 += struct.pack(">H", mtu) + struct.pack(">Q", CLIENT_GUID)
    c.send(req2)
    d = c.recv()
    assert d[:1] == b"\x08", d[:1]
    print("RakNet open2 OK")

    # 3. ConnectionRequest -> Accepted
    now = int(time.time() * 1000)
    c.frameset(b"\x09" + struct.pack(">Q", CLIENT_GUID) + struct.pack(">Q", now) + b"\x00")
    inner = c.read_frames()
    assert inner and inner[0][:1] == b"\x10", [p[:1] for p in inner]
    print("RakNet connected OK")

    # 4. NewIncoming + ConnectedPing -> Pong
    c.frameset(b"\x13" + bytes(40), b"\x00" + struct.pack(">Q", now))
    time.sleep(0.3)

    # 5. RequestNetworkSettings -> NetworkSettings
    c.frameset(batch(uvarint(0xC1) + struct.pack(">i", 924)))
    pkts = expect_batch(c)
    ids = [read_uvarint(p, 0)[0] for p in pkts]
    assert 0x8F in ids, [hex(i) for i in ids]
    print("NetworkSettings OK")

    # 6. Login -> PlayStatus(0) + ResourcePacksInfo
    c.frameset(batch(build_login(924, "SynthSteve")))
    pkts = expect_batch(c)
    ids = [read_uvarint(p, 0)[0] for p in pkts]
    assert 0x02 in ids and 0x06 in ids, [hex(i) for i in ids]
    print("Login accepted (PlayStatus + PacksInfo) OK")

    # 7. have_all_packs -> Stack
    r = uvarint(0x08) + uvarint(2); r = wstr(r, "have_all_packs")
    c.frameset(batch(r))
    pkts = expect_batch(c)
    ids = [read_uvarint(p, 0)[0] for p in pkts]
    assert 0x07 in ids, [hex(i) for i in ids]
    print("ResourcePackStack OK")

    # 8. completed -> StartGame + PlayStatus(spawn)
    r = uvarint(0x08) + uvarint(3); r = wstr(r, "completed")
    c.frameset(batch(r))
    end = time.time() + 6
    ids, all_pkts = [], []
    while time.time() < end and not (0x0B in ids and 0x02 in ids):
        pkts = expect_batch(c, timeout=2)
        all_pkts += pkts
        ids += [read_uvarint(p, 0)[0] for p in pkts]
    assert 0x0B in ids, f"no StartGame: {[hex(i) for i in ids]}"
    assert 0x02 in ids, f"no spawn PlayStatus: {[hex(i) for i in ids]}"
    sg = next(p for p in all_pkts if read_uvarint(p, 0)[0] == 0x0B)
    print(f"StartGame OK ({len(sg)} bytes) + spawn PlayStatus OK")
    print("BEDROCK LOGIN PASS")


main()
