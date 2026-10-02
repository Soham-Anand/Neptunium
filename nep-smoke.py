import socket, subprocess, time

def varint(n):
    o = b""
    while True:
        b = n & 0x7F; n >>= 7
        if n: o += bytes([b | 0x80])
        else: return o + bytes([b])

def read_varint(s):
    n = shift = 0
    while True:
        b = s.recv(1)[0]; n |= (b & 0x7F) << shift
        if not b & 0x80: return n
        shift += 7

def read_packet(s):
    ln = read_varint(s)
    buf = b""
    while len(buf) < ln: buf += s.recv(ln - len(buf))
    return buf

def pkt(pid, data=b""):
    p = varint(pid) + data
    return varint(len(p)) + p

srv = subprocess.Popen(["./target/debug/nep-server", "neptunium.toml"],
    stdout=open("nep-boot.log", "w"), stderr=subprocess.STDOUT)
time.sleep(2.5)
ok = True
try:
    # real client status flow against localhost (tests ::1 + 127.0.0.1)
    for host in ("127.0.0.1", "localhost"):
        s = socket.create_connection((host, 25566), timeout=3)
        host_b = b"localhost"
        hs = varint(0) + varint(776) + varint(len(host_b)) + host_b + (25566).to_bytes(2, "big") + varint(1)
        s.sendall(varint(len(hs)) + hs + pkt(0))
        resp = read_packet(s)
        assert b"776" in resp, resp[:100]
        s.sendall(pkt(1, (12345).to_bytes(8, "big")))
        pong = read_packet(s)
        assert (12345).to_bytes(8, "big") in pong
        s.close()
        print(f"JAVA {host}: list + ping OK")
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(3)
    u.sendto(b"\x01" + b"\x00"*8 + b"\x00"*24, ("127.0.0.1", 19133))
    d, _ = u.recvfrom(2048)
    assert b"924" in d
    print("BEDROCK 127.0.0.1: ping OK")
except Exception as e:
    print("SMOKE FAIL", repr(e)); ok = False
srv.terminate()
try: srv.wait(timeout=3)
except Exception: srv.kill()
print(open("nep-boot.log").read()[-600:])
print("SMOKE PASS" if ok else "SMOKE FAIL")
