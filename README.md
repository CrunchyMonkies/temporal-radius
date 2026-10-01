# temporal-radius

A [Temporal](https://temporal.io) worker, written in Rust, that sends RADIUS
**Change-of-Authorization** (CoA) and **Disconnect** requests (RFC 5176) to a NAS. It ships as a
single static binary in a `FROM scratch` image for `linux/amd64` and `linux/arm64`.

It registers the following on the configured task queue:

| type | name | description |
|---|---|---|
| activity | `sendCoa` | Sends a CoA-Request or Disconnect-Request, verifies the reply and returns ACK/NAK |
| workflow | `SendCoaWorkflow` | Thin wrapper that runs `sendCoa` with a 5-attempt retry policy |

TypeScript types for calling these from TS workflows and clients are in
[`types/radius-coa.d.ts`](types/radius-coa.d.ts).

## Configuration

| env var | default | |
|---|---|---|
| `TEMPORAL_ADDRESS` | `localhost:7233` | Temporal frontend |
| `TEMPORAL_NAMESPACE` | `default` | |
| `TEMPORAL_TASK_QUEUE` | `radius-coa` | task queue to poll |
| `TEMPORAL_API_KEY` | | optional |
| `TEMPORAL_TLS`, `TEMPORAL_TLS_*` | | optional TLS/mTLS ([envconfig](https://docs.rs/temporalio-client/latest/temporalio_client/envconfig/)) |
| `RADIUS_SECRET` | **required** | shared secret with the NAS; never logged |
| `RADIUS_COA_PORT` | `3799` | default NAS port when the request omits `nasPort` |
| `RADIUS_TIMEOUT_MS` | `3000` | per-transmission timeout |
| `RADIUS_RETRIES` | `2` | retransmissions per activity attempt |
| `RADIUS_DICTIONARY` | embedded | path to a FreeRADIUS-format dictionary that replaces the built-in one |
| `COA_RESPONDER_BIND` | `0.0.0.0:3799` | `coa-responder` mode only |
| `RUST_LOG` | `info` | |

## Activity contract

```jsonc
// input
{
  "nasAddress": "10.0.0.1",          // hostname or IP
  "nasPort": 3799,                   // optional
  "kind": "coa",                     // "coa" | "disconnect"
  "attributes": [
    { "name": "User-Name", "value": "alice" },
    { "name": "Session-Timeout", "value": 3600 },
    { "name": "Service-Type", "value": "Framed-User" }
  ],
  "vendorAttributes": [               // optional, RFC 2865 VSA format
    { "vendorId": 9, "vendorType": 1, "value": "subscriber:command=reauthenticate" }
  ],
  "timeoutMs": 2000, "retries": 2     // optional overrides
}
// output
{ "code": "CoA-NAK", "acked": false, "errorCause": 503,
  "attributes": [{ "name": "Error-Cause", "value": 503 }],
  "nas": "10.0.0.1:3799", "attempts": 1, "rttMs": 4 }
```

* **NAK** is a successful result with `acked: false`, so the calling workflow decides what to do.
* **Timeouts and network errors** fail with the retryable `CoaTimeout` / `CoaNetworkError`.
* **Invalid input** (`InvalidCoaRequest`) and replies that fail authenticator checks
  (`CoaReplyVerificationFailed`, usually a wrong secret) are **non-retryable**.
* Requests always carry a `Message-Authenticator`. The Request Authenticator is computed as
  RFC 5176 specifies, and replies are checked against both authenticators.

## Running

```sh
RADIUS_SECRET=... TEMPORAL_ADDRESS=temporal:7233 radius-coa-worker            # worker (default)
RADIUS_SECRET=... radius-coa-worker coa-responder                               # test NAS
```

The `coa-responder` mode is a minimal test NAS. It verifies requests with `RADIUS_SECRET` and
replies ACK, or NAK with `Error-Cause=503` when `User-Name` starts with `nak`. It silently drops
requests that fail authentication.

## Building

```sh
cargo test                       # needs protoc (apt install protobuf-compiler)
docker buildx build --platform linux/amd64,linux/arm64 \
  -t <registry>/radius-coa-worker:<tag> --push .
```

The Dockerfile cross-compiles with `cargo-zigbuild` on the build host, so building for arm64
needs no QEMU. Pushing a `v*` tag runs `.github/workflows/release.yml`, which attaches both musl
binaries to a GitHub Release and pushes a multi-arch image to `ghcr.io/crunchymonkies/temporal-radius`.

## Kubernetes smoke test

`deploy/test` contains:
* a worker (with an Istio sidecar, for clusters whose Temporal frontend enforces mTLS)
* a test `coa-responder` behind a UDP Service
* a `temporal-cli` toolbox pod

```sh
kubectl apply -k deploy/test
kubectl -n radius-coa-test exec deploy/temporal-cli -c cli -- \
  temporal workflow execute --task-queue radius-coa --type SendCoaWorkflow \
  --input '{"nasAddress":"coa-responder","attributes":[{"name":"User-Name","value":"alice"}]}'
kubectl delete -k deploy/test
```
