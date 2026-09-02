/**
 * RD-14142 — reference implementation of Rordi's side of pairing.
 *
 * This is the API CONTRACT the spike is proving, expressed as running code so
 * the adversarial harness can attack it rather than attacking prose. It is not
 * wired into the orchestrator: RD-14142 is a spike and production onboarding is
 * an explicit non-goal.
 *
 * The store is injected so the harness can drive it; production is a
 * `workspace_bridge_installations` row plus a compare-and-set on the pairing
 * code, per RD-14092's controller recommendation.
 */

import { CLOCK_SKEW_S, normalizeWorkerUrl, verify } from './pairing.js'

/** Codes are single-use; consumption must be atomic. */
export const PAIRING_CODE_TTL_S = 900

export class PairingError extends Error {
  constructor(code, status) {
    super(code)
    this.code = code
    this.status = status
  }
}

/**
 * Complete a pairing.
 *
 * @param body      `{ claims, signature }` as posted by the helper Worker.
 * @param deps.store           pairing-code store (see harness for the shape)
 * @param deps.fetchAttest     performs the outbound challenge to the worker origin
 * @param deps.now             seconds since epoch
 * @param deps.randomChallenge fresh, unguessable outbound nonce
 */
export async function completePairing(body, deps) {
  const { store, fetchAttest, now, randomChallenge } = deps

  const claims = body?.claims
  const signature = body?.signature
  if (!claims || typeof signature !== 'string') {
    throw new PairingError('malformed_request', 400)
  }

  // 1. Look the code up BEFORE anything else — it selects which key we verify
  //    against. There is no path where an unknown code reaches key material.
  const record = await store.get(String(claims.pairing_code ?? ''))
  if (!record) throw new PairingError('pairing_code_unknown', 404)

  // 2. Single-use. Checked before expiry so a replay of an old, already-spent
  //    code reports the more specific reason.
  if (record.consumedAt) throw new PairingError('pairing_code_consumed', 409)

  // 3. Expiry.
  if (now() > record.expiresAt) throw new PairingError('pairing_code_expired', 410)

  // 4. Workspace binding. The code was minted for exactly one workspace; a
  //    Worker configured for a different workspace must not pair with it, even
  //    if the customer pasted the code correctly.
  if (claims.workspace_id !== record.workspaceId) {
    throw new PairingError('workspace_mismatch', 403)
  }

  // 5. Freshness of the inbound claim.
  const issuedAt = Number(claims.issued_at)
  if (!Number.isFinite(issuedAt)) throw new PairingError('malformed_issued_at', 400)
  if (Math.abs(now() - issuedAt) > CLOCK_SKEW_S) {
    throw new PairingError('pair_claim_stale', 400)
  }

  // 6. Origin hygiene. https, no credentials, no query, origin-only.
  let workerOrigin
  try {
    workerOrigin = normalizeWorkerUrl(String(claims.worker_origin ?? ''))
  } catch (e) {
    throw new PairingError(e instanceof Error ? e.message : 'bad_worker_origin', 400)
  }

  // 7. Signature over the whole claim set, with the installation key that was
  //    minted alongside this code. Proves possession of the key; binds the
  //    origin, workspace, nonce and timestamp into one message.
  const signatureValid = await verify(record.bridgeKey, 'pair', claims, signature)
  if (!signatureValid) throw new PairingError('pair_signature_invalid', 403)

  // 8. Protocol compatibility, by range intersection rather than equality, so a
  //    template one release behind still pairs during a rollout.
  const min = Number(claims.protocol_min)
  const max = Number(claims.protocol_max)
  if (!(min <= record.serverProtocolMax && max >= record.serverProtocolMin)) {
    throw new PairingError('protocol_incompatible', 409)
  }

  // 9. THE STEP THAT MAKES A USER-SUPPLIED URL INSUFFICIENT.
  //    Everything above could be produced by anyone who captured one valid
  //    pair request. Now we call the claimed origin ourselves with a challenge
  //    it has never seen, and require a signature bound to that origin.
  const challenge = randomChallenge()
  let attest
  try {
    attest = await fetchAttest(workerOrigin, challenge)
  } catch {
    throw new PairingError('endpoint_unreachable', 502)
  }
  if (!attest?.claims || typeof attest.signature !== 'string') {
    throw new PairingError('endpoint_attestation_malformed', 502)
  }
  if (attest.claims.challenge !== challenge) {
    throw new PairingError('endpoint_challenge_mismatch', 403)
  }
  // Relay defence: the attestation must name the origin we actually called.
  if (attest.claims.worker_origin !== workerOrigin) {
    throw new PairingError('endpoint_origin_mismatch', 403)
  }
  if (attest.claims.workspace_id !== record.workspaceId) {
    throw new PairingError('endpoint_workspace_mismatch', 403)
  }
  const attestValid = await verify(record.bridgeKey, 'attest', attest.claims, attest.signature)
  if (!attestValid) throw new PairingError('endpoint_attestation_failed', 403)

  // 10. Consume atomically. A concurrent second pair request must lose here,
  //     not at step 2 — step 2 is an early-out, this is the actual guarantee.
  const consumed = await store.consume(record.code, { workerOrigin, at: now() })
  if (!consumed) throw new PairingError('pairing_code_consumed', 409)

  return {
    installation_id: record.installationId,
    workspace_id: record.workspaceId,
    worker_origin: workerOrigin,
    protocol: Math.min(max, record.serverProtocolMax),
    observed_release: String(attest.claims.release ?? ''),
    observed_cf_version_id: String(attest.claims.cf_version_id ?? ''),
    state: 'active',
  }
}
