# RadSec and reverse CoA with FreeRADIUS

This guide sets up a FreeRADIUS server that:

* accepts **RadSec** (RADIUS over TLS, RFC 6614, `tcp/2083`) from NASes, including NASes behind
  NAT that can only connect *out*;
* proxies their authentication and accounting to your existing RADIUS server; and
* relays CoA / Disconnect requests from `radius-coa-worker` **back down each NAS's own RadSec
  connection** ("reverse CoA"), so nothing has to reach the NAS from outside.

```
                         NAT / firewall
 ┌──────┐  TLS, NAS dials out  │      ┌────────────────────────── Kubernetes ─────────────────────────┐
 │ NAS  │ ──────────────────────┼────► │ freeradius-radsec :2083 ─┐                                    │
 │      │ ◄─ CoA on the same ───┼───── │                          │  FreeRADIUS  ── UDP ──► upstream    │
 └──────┘    connection        │      │ freeradius-coa :3799 ────┘     (1 pod)          RADIUS server  │
                                      │        ▲                                                       │
                                      │        └── UDP CoA ── radius-coa-worker ◄── Temporal            │
                                      └────────────────────────────────────────────────────────────────┘
```

Everything lives in [`deploy/freeradius`](../deploy/freeradius):

| path | what |
|---|---|
| `image/Dockerfile` | FreeRADIUS 3.2 built with reverse CoA (see [Why a custom image](#why-a-custom-image)) |
| `sites/radsec` | RadSec listener, NAS identification, keepalive limits, proxying to upstream |
| `sites/coa-relay` | UDP CoA listener for the worker; routes each request to a NAS connection |
| `sites/status` | loopback Status-Server listener used by the Kubernetes probes |
| `mods/always` | the only module the sites use |
| `freeradius.yaml`, `kustomization.yaml` | Deployment, Services, NetworkPolicy, generated ConfigMaps |
| `local/` | Docker Compose test bench with a simulated NAS ([Testing locally](#testing-locally)) |

## How a CoA reaches the NAS

1. The NAS connects to `freeradius-radsec:2083` and authenticates with its **client
   certificate**.
2. On the first packet FreeRADIUS answers (a Status-Server watchdog, an Access-Request or an
   Accounting-Request), it labels that TLS connection with the certificate's **Common Name**.
3. The worker sends an ordinary RFC 5176 CoA-Request to `freeradius-coa:3799` with
   `NAS-Identifier` set to that CN.
4. FreeRADIUS sends the request down the connection labelled with that CN. The NAS's ACK or NAK
   travels back the same way and is relayed to the worker.

**Rule: each NAS's certificate CN must equal the `NAS-Identifier` you put in CoA requests.** The
label comes from the certificate, not from anything the NAS sends. FreeRADIUS would also accept
extra labels from a NAS (`Operator-Name = "+name"` in a Status-Server), which would let one NAS
claim another's CoA traffic. `sites/radsec` deletes that attribute, and the test bench checks
that such a claim fails.

## Why a custom image

FreeRADIUS's support for sending CoA down a client's connection (`WITH_COA_TUNNEL`) is compiled
out by default, and the official `freeradius/freeradius-server` images are built without it. They
reject the config with `Invalid type "auth+acct+coa" in listen section`. Worse, a build without
it cannot route by NAS connection at all, so it can never deliver these requests.

`image/Dockerfile` compiles FreeRADIUS with `-DWITH_COA_TUNNEL`. It is pinned to a commit on the
`v3.2.x` branch, because the reverse-CoA fixes listed for 3.2.11 ("now running in production")
are not in a tagged release yet. Move `FREERADIUS_REF` to `release_3_2_11` once that tag exists.
The image ships with empty `sites-enabled/` and `mods-enabled/` directories and an empty
`clients.conf`, runs as uid 101, and works with a read-only root filesystem.

## 1. Certificates

RadSec uses mutual TLS. You need:

| certificate | used by | requirements |
|---|---|---|
| **CA** | both sides | `basicConstraints=CA:TRUE`, `keyUsage=keyCertSign,cRLSign`. Use a private CA dedicated to RadSec: every certificate it issues can connect |
| **server** | FreeRADIUS | `extendedKeyUsage=serverAuth`, SAN = the DNS name NASes connect to |
| **one per NAS** | the NAS | `extendedKeyUsage=clientAuth`, **CN = the NAS's `NAS-Identifier`** |

FreeRADIUS reads them from a Secret named `radsec-tls` with the keys `tls.crt`, `tls.key` and
`ca.crt`. That is the cert-manager layout, so a cert-manager CA issuer works directly:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: { name: radsec-server, namespace: radius-coa-test }
spec:
  secretName: radsec-tls
  commonName: radsec.example.com
  dnsNames: [radsec.example.com]
  usages: [server auth, digital signature, key encipherment]
  issuerRef: { kind: Issuer, name: radsec-ca }   # a CA issuer holding your RadSec CA
```

Or create it by hand:

```sh
kubectl -n radius-coa-test create secret generic radsec-tls \
  --from-file=tls.crt=server.crt --from-file=tls.key=server.key --from-file=ca.crt=ca.crt
```

Issue NAS certificates from the same CA (cert-manager `Certificate` with `usages: [client auth]`,
or `openssl`). See `local/gen-certs.sh` for working `openssl` commands.

FreeRADIUS loads certificates at startup only. After the server certificate is renewed, run
`kubectl rollout restart deploy/freeradius` (every NAS reconnects within a few seconds), or use a
tool such as stakater Reloader to restart it automatically.

## 2. Build and push the image

```sh
docker buildx build --platform linux/amd64,linux/arm64 \
  -t harbor.bne1.ouchi.com.au/library/freeradius-radsec:3.2.11-9ec1249 --push deploy/freeradius/image
```

If you use a different name or tag, change `images:` in `deploy/freeradius/kustomization.yaml`.

## 3. Deploy

The kustomization deploys into `radius-coa-test`, next to the worker from `deploy/test`, and
reuses that namespace's `radius-coa` Secret as the worker-to-FreeRADIUS shared secret. Change
`namespace:` to deploy somewhere else; the namespace then needs its own `radius-coa` Secret with
a `RADIUS_SECRET` key.

1. Create the `radsec-tls` Secret ([step 1](#1-certificates)).
2. Create the upstream RADIUS secret, which must match the client entry for FreeRADIUS on your
   upstream server:
   ```sh
   kubectl -n radius-coa-test create secret generic freeradius-upstream \
     --from-literal=UPSTREAM_RADIUS_SECRET='...'
   ```
3. Set `UPSTREAM_RADIUS_HOST` (and `UPSTREAM_RADIUS_AUTH_PORT`; accounting uses the next port up)
   in `kustomization.yaml`. FreeRADIUS resolves the host name at startup and exits if it can't,
   so the pod restarts until DNS works. If this FreeRADIUS should authenticate users itself
   instead, replace the `Proxy-To-Realm` lines in `sites/radsec` with your policy.
4. Apply it and check that the pod is up:
   ```sh
   kubectl apply -k deploy/freeradius
   kubectl -n radius-coa-test rollout status deploy/freeradius
   kubectl -n radius-coa-test get svc freeradius-radsec    # EXTERNAL-IP is what NASes connect to
   ```
5. Point the DNS name from the server certificate at the `freeradius-radsec` external IP.

Notes on the manifest:

* **One replica, `Recreate` strategy.** A NAS's connection exists in exactly one FreeRADIUS
  process, and the CN-to-connection table is in that process's memory. With two pods, a CoA
  could reach the pod that doesn't hold the connection and be NAKed with 502. A restart drops
  every connection; NASes reconnect and are reachable again after their next packet (within one
  watchdog interval).
* **`externalTrafficPolicy: Local`** keeps the NAS's public (NAT) address visible in FreeRADIUS
  logs instead of a node address.
* **NetworkPolicy:** `2083/tcp` is open to everyone (the certificate is the access control);
  `3799/udp` only accepts pods labelled `app: radius-coa-worker`. To limit which public
  addresses can reach RadSec, set `loadBalancerSourceRanges` on the Service.
* **Sidecars:** the pod opts out of Istio injection. RadSec is already end-to-end TLS, and
  CoA is UDP.

## 4. Configure the NAS

| setting | value |
|---|---|
| RADIUS server | the DNS name from the server certificate, port `2083`, transport TLS (RadSec) |
| shared secret | `radsec` (fixed by RFC 6614; security comes from TLS) |
| client certificate / key | the NAS's certificate, **CN = its `NAS-Identifier`** |
| trusted CA | the RadSec CA |
| `NAS-Identifier` | the same value as the certificate CN |
| Status-Server / watchdog | **on, every 30 seconds** (see [Keepalive](#keepalive)) |
| dynamic authorization (CoA) | accept CoA / Disconnect **on the RadSec connection the NAS opened**. Without this the setup cannot work |

The last row is the one to check first. Accepting CoA on the NAS's own outbound connection is
called "reverse CoA" (IETF draft `draft-ietf-radext-reverse-coa`), and not every NAS supports it.
A NAS that only accepts CoA on its own listening port cannot receive CoA through NAT this way.
Check your vendor's documentation for "CoA over RadSec" or "dynamic authorization over TLS" on
the same connection.

## Keepalive

A NAS behind NAT holds one long-lived TCP connection open. Each layer on the path drops
connections that look idle, and reverse CoA only works while that connection is up. Here is how
the pieces are set, from the NAS inwards:

| layer | typical idle timeout | setting here |
|---|---|---|
| NAS | — | **sends a Status-Server every 30s.** This is the keepalive: it keeps every NAT and load balancer mapping on the path fresh |
| NAT / firewall at the NAS site | ~1 min to several hours, often 5 min | nothing to set, as long as the 30s watchdog is shorter |
| Cloud load balancer in front of the Service | e.g. ~350s on AWS NLB, 4 min default on Azure | keep it above 30s; the watchdog does the rest |
| FreeRADIUS `limit { idle_timeout }` | `RADSEC_IDLE_TIMEOUT=120` | closes a connection after 120s with **no packet at all** (four missed watchdogs) |
| FreeRADIUS `limit { lifetime }` | `0` | never recycles a healthy connection |

Why it is set up this way:

* **FreeRADIUS does not set `SO_KEEPALIVE` on accepted RadSec sockets** (only on its own
  outbound proxy connections), so TCP-level keepalives and `net.ipv4.tcp_keepalive_*` sysctls
  have no effect here. The keepalive must come from the NAS as Status-Server (RFC 5997), which
  RFC 6614 requires RadSec peers to support. FreeRADIUS answers it in the `Autz-Type
  Status-Server` section of `sites/radsec`.
* **The watchdog also registers the NAS for CoA.** The connection is labelled when FreeRADIUS
  answers the NAS's first packet, so with a watchdog the NAS can receive CoA straight after
  connecting, before any user has logged in.
* **`idle_timeout` clears out dead connections.** When a NAS disappears behind a NAT (power loss,
  NAT reboot), no FIN ever arrives and the socket would otherwise stay open indefinitely. Closing
  it after 120s of silence means CoA for that NAS fails fast with NAK 502 instead of waiting on a
  dead connection. The example `tls` config in FreeRADIUS uses `idle_timeout = 30`; don't copy
  it, because it closes connections between watchdogs.
* If you change the watchdog interval, keep `RADSEC_IDLE_TIMEOUT` at least four times larger.

The test bench checks this behaviour: a NAS that sends only watchdogs stays reachable past the
idle timeout, and a NAS that goes silent is disconnected once the idle timeout passes.

## 5. Send a CoA

Address requests to the relay and identify the NAS with `NAS-Identifier`. Include whatever
attributes the NAS needs to find the session:

```sh
kubectl -n radius-coa-test exec deploy/temporal-cli -c cli -- \
  temporal workflow execute --task-queue radius-coa --type SendCoaWorkflow --input '{
    "nasAddress": "freeradius-coa",
    "kind": "disconnect",
    "timeoutMs": 10000,
    "retries": 1,
    "attributes": [
      { "name": "NAS-Identifier", "value": "nas-01" },
      { "name": "User-Name", "value": "alice" },
      { "name": "Acct-Session-Id", "value": "0A0B0C0D" }
    ]}'
```

* **`timeoutMs` must be longer than 7 seconds.** If the NAS doesn't answer, FreeRADIUS gives up
  after `mrd = 6` seconds (`coa { }` in `sites/radsec`) and NAKs. A shorter worker timeout
  retransmits and times out before that NAK arrives. If the worker only ever talks to this relay,
  set `RADIUS_TIMEOUT_MS=10000` and `RADIUS_RETRIES=1` on the worker instead of per request.
* The worker's `RADIUS_SECRET` secures the worker-to-FreeRADIUS hop. The NAS hop uses TLS.

What comes back:

| result | `errorCause` | meaning | what to do |
|---|---|---|---|
| `CoA-ACK` / `Disconnect-ACK` | — | the NAS applied it | done |
| `CoA-NAK` / `Disconnect-NAK` | from the NAS, e.g. `503` | the NAS refused it (session not found, ...) | inspect `errorCause` |
| `CoaNakRetryable` failure | `502` | FreeRADIUS has no connection for that `NAS-Identifier` (NAS offline, reconnecting, CN mismatch), or the NAS didn't answer within 6s | Temporal retries |
| NAK | `506` | every connection for that NAS is busy | retry, or add `506` to `RADIUS_RETRY_ERROR_CAUSES` |
| NAK | `402` | the request has no `NAS-Identifier` | fix the request |
| `CoaTimeout` failure | — | FreeRADIUS didn't answer (pod down, network) | Temporal retries |

A NAK is normally a successful activity result with `acked: false`. The exception is any
Error-Cause listed in the worker's `RADIUS_RETRY_ERROR_CAUSES` (default `502`): the activity fails
with the retryable `CoaNakRetryable` instead, so Temporal's retry policy waits out a NAS that is
reconnecting. `SendCoaWorkflow` makes 5 attempts with 1s-16s backoff, roughly 30-65s in total.
If every attempt gets 502, the workflow fails with `CoaNakRetryable`.

## Testing locally

`deploy/freeradius/local` runs the same `sites/` and `mods/` against a simulated NAS, using
Docker Compose:

```sh
cd deploy/freeradius/local
./gen-certs.sh                      # throwaway CA, server and NAS certificates
docker compose up -d --build --wait
./test.sh
docker compose down
```

| service | role |
|---|---|
| `freeradius` | the server under test (`RADSEC_IDLE_TIMEOUT=20` so the reaping test runs quickly) |
| `nas` | a second FreeRADIUS acting as the NAS: proxies Access-Requests out over RadSec, answers CoA that comes back down the connection |
| `upstream` | stand-in authentication server that accepts everyone |
| `tools` | runs `radclient` in place of the worker |
| `watchdog-nas.py` | started by `test.sh` in a `python:3-slim` container: a minimal NAS that sends only Status-Server watchdogs and ACKs CoA (`--ignore-coa` to stay silent, `--operator-name` to attempt a hijack) |

`test.sh` checks CoA routing, ACK and NAK relaying, every relay-generated NAK, the health probe,
watchdog-only registration, keepalive past the idle timeout, idle reaping, the unresponsive-NAS
NAK, and that a NAS cannot claim another NAS's identity. CI runs the same bench (`radsec-bench` in `.github/workflows/ci.yml`).

To watch FreeRADIUS make decisions, run it in debug mode:
`docker compose run --rm --entrypoint radiusd freeradius -X`.

## Troubleshooting

| symptom | likely cause |
|---|---|
| `Invalid type "auth+acct+coa"` | an image built without `WITH_COA_TUNNEL`, e.g. the official one |
| `Failed resolving "..." to IPv4 address` at startup | `UPSTREAM_RADIUS_HOST` doesn't resolve yet; the pod restarts until it does |
| NAS can't connect, TLS errors in the log | NAS certificate not issued by the RadSec CA, or missing `clientAuth`; CA without `keyUsage` (strict TLS stacks reject it) |
| every CoA gets NAK 502 | certificate CN ≠ `NAS-Identifier` in the request; or the NAS hasn't sent anything since connecting (enable the watchdog) |
| CoA works for a few minutes after the NAS sends traffic, then 502 | no watchdog, so a NAT or load balancer dropped the idle connection, or `idle_timeout` closed it |
| worker reports `CoaTimeout` but the NAS acted on the request | worker `timeoutMs` ≤ 7s; raise it ([step 5](#5-send-a-coa)) |
| CoA intermittently 502 after scaling up | more than one replica; keep `replicas: 1` |
