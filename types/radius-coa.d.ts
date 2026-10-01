/**
 * Type definitions for the `radius-coa-worker` Temporal worker (Rust).
 *
 * The worker polls the task queue configured by `TEMPORAL_TASK_QUEUE` (default `"radius-coa"`)
 * and registers:
 *   - activity `actRadiusCoa`         — send a RADIUS CoA-Request / Disconnect-Request (RFC 5176)
 *   - workflow `SendCoaWorkflow` — thin wrapper that runs `actRadiusCoa` with a retry policy
 *
 * Calling the activity from a TypeScript workflow:
 *
 * ```ts
 * import { proxyActivities } from '@temporalio/workflow';
 * import type { RadiusCoaActivities, RadiusCoaTaskQueue } from './radius-coa';
 *
 * const taskQueue: RadiusCoaTaskQueue = 'radius-coa';
 * const { actRadiusCoa } = proxyActivities<RadiusCoaActivities>({
 *   taskQueue,
 *   startToCloseTimeout: '1 minute',
 *   retry: { maximumAttempts: 5, nonRetryableErrorTypes: ['InvalidCoaRequest'] },
 * });
 *
 * const res = await actRadiusCoa({
 *   nasAddress: '10.0.0.1',
 *   attributes: [
 *     { name: 'User-Name', value: 'alice' },
 *     { name: 'Session-Timeout', value: 3600 },
 *   ],
 * });
 * if (!res.acked) throw new Error(`NAS refused CoA: ${res.code} cause=${res.errorCause}`);
 * ```
 *
 * Starting the bundled workflow from a client:
 *
 * ```ts
 * const result = await client.workflow.execute<SendCoaWorkflow>('SendCoaWorkflow', {
 *   taskQueue: 'radius-coa',
 *   workflowId: `coa-${sessionId}`,
 *   args: [request],
 * });
 * ```
 */

/**
 * Default task queue; override on the worker with `TEMPORAL_TASK_QUEUE`.
 * (This file is types-only, so use the string literal at runtime.)
 */
export type RadiusCoaTaskQueue = 'radius-coa' | (string & {});

/** Registered activity type name. */
export type RadiusCoaActivityName = 'actRadiusCoa';
/** Registered workflow type name. */
export type SendCoaWorkflowName = 'SendCoaWorkflow';

/** `"coa"` → CoA-Request (code 43); `"disconnect"` → Disconnect-Request (code 40). */
export type CoaKind = 'coa' | 'disconnect';

/**
 * Attribute value.
 * - `number` for integer / enum / time attributes (e.g. `Session-Timeout`).
 * - `string` for text, IPv4/IPv6 addresses (`"10.1.2.3"`, `"2001:db8::/64"`), and integer
 *   attributes given by dictionary VALUE name (e.g. `Service-Type: "Framed-User"`).
 * - `"0x..."` strings are sent as raw octets (e.g. `Class: "0xdeadbeef"`).
 */
export type AttributeValue = string | number;

export interface Attribute {
  /** Standard RADIUS attribute name from the worker's dictionary, e.g. `"User-Name"`. */
  name: string;
  value: AttributeValue;
}

/** Vendor-Specific attribute (type 26), RFC 2865 §5.26 format. */
export interface VendorAttribute {
  /** IANA Private Enterprise Number, e.g. `9` (Cisco), `14988` (MikroTik). */
  vendorId: number;
  /** Vendor attribute type, 0–255. */
  vendorType: number;
  /** Numbers are encoded as 32-bit integers; strings as text, or raw octets when `0x`-prefixed. */
  value: AttributeValue;
}

/** Input of the `actRadiusCoa` activity and the `SendCoaWorkflow` workflow. */
export interface CoaRequest {
  /** NAS hostname or IP address. */
  nasAddress: string;
  /** NAS CoA port. Default: worker's `RADIUS_COA_PORT` (3799). */
  nasPort?: number;
  /** Default: `"coa"`. */
  kind?: CoaKind;
  /**
   * Session identification and authorization attributes (RFC 5176 §3), e.g.
   * `User-Name`, `Acct-Session-Id`, `Framed-IP-Address`, `NAS-IP-Address`, `Filter-Id`.
   * At least one attribute (or vendor attribute) is required. `Message-Authenticator` is always
   * added by the worker.
   */
  attributes: Attribute[];
  vendorAttributes?: VendorAttribute[];
  /** Per-transmission timeout in ms. Default: worker's `RADIUS_TIMEOUT_MS` (3000). */
  timeoutMs?: number;
  /** Retransmissions after the first send. Default: worker's `RADIUS_RETRIES` (2). */
  retries?: number;
}

export type CoaReplyCode = 'CoA-ACK' | 'CoA-NAK' | 'Disconnect-ACK' | 'Disconnect-NAK';

/** RFC 5176 §3.5 Error-Cause values commonly returned in a NAK. */
export type ErrorCause =
  | 201 // ResidualSessionContextRemoved
  | 202 // InvalidEapPacket
  | 401 // UnsupportedAttribute
  | 402 // MissingAttribute
  | 403 // NasIdentificationMismatch
  | 404 // InvalidRequest
  | 405 // UnsupportedService
  | 406 // UnsupportedExtension
  | 407 // InvalidAttributeValue
  | 501 // AdministrativelyProhibited
  | 502 // RequestNotRoutable
  | 503 // SessionContextNotFound
  | 504 // SessionContextNotRemovable
  | 505 // OtherProxyProcessingError
  | 506 // ResourcesUnavailable
  | 507 // RequestInitiated
  | 508; // MultipleSessionSelectionUnsupported

/** Output of `actRadiusCoa` / `SendCoaWorkflow`. A NAK is a *successful* result with `acked: false`. */
export interface CoaResult {
  code: CoaReplyCode;
  /** `true` for CoA-ACK / Disconnect-ACK. */
  acked: boolean;
  /** Error-Cause from the reply, if present (usually on NAK). See {@link ErrorCause}. */
  errorCause?: number;
  /** Reply attributes. Unknown attributes appear as `Attr-<id>` with a `0x` hex value. */
  attributes: Attribute[];
  /** Resolved NAS socket address, e.g. `"10.0.0.1:3799"`. */
  nas: string;
  /** Number of transmissions in the final activity attempt (1 = answered first time). */
  attempts: number;
  /** Time from first transmission to verified reply, in ms. */
  rttMs: number;
}

/**
 * `ApplicationFailure.type` values the activity can fail with.
 * - `InvalidCoaRequest`           non-retryable: unknown attribute, bad value, empty request
 * - `CoaReplyVerificationFailed`  non-retryable: reply authenticator mismatch (wrong secret?)
 * - `CoaTimeout`                  retryable: no reply after all retransmissions
 * - `CoaNetworkError`             retryable: DNS / socket error
 */
export type CoaFailureType =
  | 'InvalidCoaRequest'
  | 'CoaReplyVerificationFailed'
  | 'CoaTimeout'
  | 'CoaNetworkError';

/** Activity interface for `proxyActivities<RadiusCoaActivities>()`. */
export interface RadiusCoaActivities {
  actRadiusCoa(request: CoaRequest): Promise<CoaResult>;
}

/** Signature of the bundled workflow, for `client.workflow.start<SendCoaWorkflow>(...)`. */
export type SendCoaWorkflow = (request: CoaRequest) => Promise<CoaResult>;

/** Environment variables read by the worker binary. */
export interface RadiusCoaWorkerEnv {
  /** Temporal frontend `host:port`. Default `localhost:7233`. */
  TEMPORAL_ADDRESS?: string;
  /** Default `default`. */
  TEMPORAL_NAMESPACE?: string;
  /** Task queue to poll. Default `radius-coa`. */
  TEMPORAL_TASK_QUEUE?: string;
  TEMPORAL_API_KEY?: string;
  /** `true` to enable TLS; see also the `TEMPORAL_TLS_*` variables. */
  TEMPORAL_TLS?: string;
  TEMPORAL_TLS_SERVER_CA_CERT_PATH?: string;
  TEMPORAL_TLS_CLIENT_CERT_PATH?: string;
  TEMPORAL_TLS_CLIENT_KEY_PATH?: string;
  TEMPORAL_TLS_SERVER_NAME?: string;
  /** Required. Shared secret between the worker and the NAS. */
  RADIUS_SECRET: string;
  /** Default `3799`. */
  RADIUS_COA_PORT?: string;
  /** Default `3000`. */
  RADIUS_TIMEOUT_MS?: string;
  /** Default `2`. */
  RADIUS_RETRIES?: string;
  /** Path to a FreeRADIUS-format dictionary replacing the embedded one. */
  RADIUS_DICTIONARY?: string;
  /** `coa-responder` mode only. Default `0.0.0.0:3799`. */
  COA_RESPONDER_BIND?: string;
  /** tracing filter, e.g. `info`, `radius_coa_worker=debug`. */
  RUST_LOG?: string;
}
