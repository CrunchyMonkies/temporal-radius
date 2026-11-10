#!/bin/sh
# End-to-end reverse-CoA test against the compose bench (see compose.yaml).
set -u
cd "$(dirname "$0")"

rc() { docker compose exec -T tools radclient -x -r 1 -t 4 "$@" 2>&1; }
fails=0
check() { # name expected-pattern output   (match "Received <code>", not "<code>": radclient's
  # failure text "Expected CoA-ACK got CoA-NAK" contains the expected code too)
  if printf '%s' "$3" | grep -q "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; printf '%s\n' "$3" | sed 's/^/      /'; fails=$((fails + 1)); fi
}

echo "--- 1. CoA before the NAS has connected: NAK 502 (no tunnel for that NAS)"
out=$(printf 'User-Name = "alice"\nNAS-Identifier = "nas-01"\n' | rc freeradius:3799 coa worker-secret)
check "NAK Proxy-Request-Not-Routable" "Error-Cause = Proxy-Request-Not-Routable" "$out"

echo "--- 2. NAS dials out over RadSec (triggered by an Access-Request through it, which also"
echo "    registers its NAS-Identifier nas-01 for CoA)"
out=$(printf 'User-Name = "alice"\nUser-Password = "x"\n' | rc nas:1812 auth testing123)
check "Access-Accept via RadSec -> upstream" "Received Access-Accept" "$out"

echo "--- 3. CoA down the NAS's own connection"
out=$(printf 'User-Name = "alice"\nNAS-Identifier = "nas-01"\n' | rc freeradius:3799 coa worker-secret)
check "CoA-ACK from the NAS" "Received CoA-ACK" "$out"

echo "--- 4. NAK from the NAS is relayed back"
out=$(printf 'User-Name = "nak-bob"\nNAS-Identifier = "nas-01"\n' | rc freeradius:3799 disconnect worker-secret)
check "Disconnect-NAK relayed" "Received Disconnect-NAK" "$out"
check "NAS's Error-Cause relayed" "Error-Cause = Session-Context-Not-Found" "$out"

echo "--- 5. Unknown NAS-Identifier is not routed"
out=$(printf 'User-Name = "alice"\nNAS-Identifier = "nas-99"\n' | rc freeradius:3799 coa worker-secret)
check "NAK 502 for unknown NAS" "Error-Cause = Proxy-Request-Not-Routable" "$out"

echo "--- 6. Missing NAS-Identifier is rejected"
out=$(printf 'User-Name = "alice"\n' | rc freeradius:3799 coa worker-secret)
check "CoA-NAK Missing-Attribute" "Error-Cause = Missing-Attribute" "$out"

echo "--- 7. Health probe"
out=$(docker compose exec -T freeradius sh -c 'echo "Message-Authenticator = 0x00" | radclient -q -r 1 -t 2 127.0.0.1:18121 status probe' 2>&1; echo "exit=$?")
check "status probe" "exit=0" "$out"

echo "--- 8. Keepalive: idle_timeout is ${IDLE:=45}s on the bench"
echo "    nas-02 sends a Status-Server every 35s (longer than FreeRADIUS's built-in 30s client"
echo "    idle_timeout, which sites/radsec must override); nas-03 sends one, then goes silent."
echo "    Both use the shared NAS certificate and put their NAS-Identifier in the watchdog; they"
echo "    send no other traffic, so only the watchdog registers them for reverse CoA."
wnas() { # name interval duration [extra args]; name is the NAS-Identifier, cert is the shared one
  n=$1 i=$2 d=$3; shift 3
  docker run --rm --network radsec-local_bench --add-host freeradius:172.31.83.10 \
    -v "$PWD/watchdog-nas.py:/w/watchdog-nas.py:ro" -v "$PWD/certs/nas:/w/certs:ro" \
    python:3-slim python -I /w/watchdog-nas.py --certs /w/certs --interval "$i" --duration "$d" \
    --nas-identifier "$n" "$@" > "/tmp/radsec-$n.log" 2>&1 &
}
coa_to() { printf 'User-Name = "alice"\nNAS-Identifier = "%s"\n' "$1" | rc freeradius:3799 coa worker-secret; }
wnas nas-02 35 $((IDLE + 15))
wnas nas-03 0 $((IDLE + 15))
sleep 5
check "watchdog alone registers the NAS" "Received CoA-ACK" "$(coa_to nas-02)"
check "silent NAS reachable before idle_timeout" "Received CoA-ACK" "$(coa_to nas-03)"
sleep $((IDLE + 3))
check "watchdog keeps the connection past idle_timeout" "Received CoA-ACK" "$(coa_to nas-02)"
check "silent connection reaped after idle_timeout" "Proxy-Request-Not-Routable" "$(coa_to nas-03)"
wait
for n in nas-02 nas-03; do echo "    $n:"; sed 's/^/      /' "/tmp/radsec-$n.log"; done

echo "--- 9. Connected NAS that never answers: FreeRADIUS gives up after mrd (6s) and NAKs"
wnas nas-02 5 15 --ignore-coa
sleep 3
start=$(date +%s)
out=$(printf 'User-Name = "alice"\nNAS-Identifier = "nas-02"\n' | docker compose exec -T tools radclient -x -r 1 -t 15 freeradius:3799 coa worker-secret 2>&1)
took=$(( $(date +%s) - start ))
check "NAK 502 for an unresponsive NAS" "Received CoA-NAK" "$out"
check "...within mrd + 2s (took ${took}s)" "ok" "$([ "$took" -le 8 ] && echo ok)"
wait

echo "--- 10. NASes sharing one certificate are told apart by NAS-Identifier"
wnas nas-02 5 12
wnas nas-03 5 12
sleep 3
check "CoA for nas-02 answered" "Received CoA-ACK" "$(coa_to nas-02)"
check "CoA for nas-03 answered" "Received CoA-ACK" "$(coa_to nas-03)"
wait
check "nas-02 got exactly its own CoA" "^1$" "$(grep -c 'answered CoA' /tmp/radsec-nas-02.log)"
check "nas-03 got exactly its own CoA" "^1$" "$(grep -c 'answered CoA' /tmp/radsec-nas-03.log)"
# A watchdog without NAS-Identifier registers nothing; Operator-Name keys are stripped.
# (The later --nas-identifier "" overrides the one wnas adds.)
wnas nas-05 5 8 --nas-identifier "" --operator-name +nas-07
sleep 3
check "watchdog without NAS-Identifier is not routable" "Proxy-Request-Not-Routable" "$(coa_to nas-05)"
check "Operator-Name key ignored" "Proxy-Request-Not-Routable" "$(coa_to nas-07)"
wait

[ "$fails" -eq 0 ] && echo "all passed" || { echo "$fails failed"; exit 1; }
