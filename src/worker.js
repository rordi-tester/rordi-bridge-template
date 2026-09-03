/**
 * RD-14142 — Rordi helper Worker, customer-managed deploy-button template.
 *
 * SCOPE. This template proves ONBOARDING ONLY: deploy, Cloudflare-side secret
 * entry, one-time workspace-bound pairing, and signed liveness / attestation /
 * readiness. It deliberately contains NO credential proxy, NO R2/KV, and no
 * connection to Rordi's EgressBrokerDO / globalOutbound path (RD-9694), whose
 * unauthenticated `/__init` and under-constrained capability checks are known
 * defects that a production spec — not this template — must fix.
 *
 * CONFIGURATION, ALL ENTERED BY THE CUSTOMER ON CLOUDFLARE
 * Plain vars (non-secret, declared in wrangler.jsonc):
 *   RORDI_URL        — Rordi control-plane origin, e.g. https://app.rordi.dev
 *   RORDI_WORKSPACE  — the workspace id this installation is bound to
 * Secrets (declared `secret: true`; the deploy button prompts for them and
 * Cloudflare stores them — they never transit Rordi):
 *   RORDI_PAIRING_CODE — short-lived, single-use, workspace-bound
 *   RORDI_BRIDGE_KEY   — long-lived installation key; signs attestations
 * Binding:
 *   VERSION — Cloudflare version_metadata, supplies the deployed version id
 *
 * ROUTES
 *   GET  /livez            — 204, empty. Discloses nothing.
 *   GET  /_rordi/attest    — signed non-secret identity + compatibility
 *   GET  /_rordi/ready     — signed readiness; secret PRESENCE only, never values
 *   POST /_rordi/pair      — customer-triggered; Worker calls Rordi to pair
 */

import {
  ATTESTATION_MAX_AGE_S,
  PROTOCOL_MAX,
  PROTOCOL_MIN,
  normalizeWorkerUrl,
  sign,
} from './pairing.js'

/** Bumped by an upstream release PR; surfaced in attestation. */
export const TEMPLATE_RELEASE = '0.5.0-rd14142'

export default {
  async fetch(request, env) {
    const url = new URL(request.url)

    // Public liveness. 204 and nothing else — no workspace, version, or state.
    // A prober learns only that something is deployed here.
    if (url.pathname === '/livez') {
      return new Response(null, { status: 204 })
    }

    if (url.pathname === '/_rordi/attest' && request.method === 'GET') {
      return handleAttest(request, url, env)
    }

    if (url.pathname === '/_rordi/ready' && request.method === 'GET') {
      return handleReady(request, url, env)
    }

    if (url.pathname === '/_rordi/pair' && request.method === 'POST') {
      return handlePair(request, env)
    }

    return new Response(null, { status: 404 })
  },
}

/** Non-secret identity of this deployment. Never includes secret material. */
function identity(request, env) {
  return {
    protocol_min: PROTOCOL_MIN,
    protocol_max: PROTOCOL_MAX,
    release: TEMPLATE_RELEASE,
    workspace_id: env.RORDI_WORKSPACE ?? '',
    // version_metadata binding; absent in local dev, so it is optional by design.
    cf_version_id: env.VERSION?.id ?? '',
    cf_version_tag: env.VERSION?.tag ?? '',
    worker_origin: new URL(request.url).origin,
  }
}

/**
 * Rordi's outbound leg of pairing, and its ongoing health check.
 *
 * The caller supplies a challenge nonce it generated; we sign the nonce
 * together with our own origin and workspace. This is what makes a
 * user-supplied URL insufficient on its own: whoever answers here must hold the
 * installation key, and the signature is bound to the origin that answered, so
 * it cannot be relayed from a different endpoint.
 */
async function handleAttest(request, url, env) {
  const challenge = url.searchParams.get('challenge') ?? ''
  if (challenge.length < 16 || challenge.length > 256) {
    return jsonError('invalid_challenge', 400)
  }
  if (!env.RORDI_BRIDGE_KEY) {
    return jsonError('not_configured', 503)
  }

  const claims = { ...identity(request, env), challenge }
  const signature = await sign(env.RORDI_BRIDGE_KEY, 'attest', claims)
  return Response.json({ claims, signature })
}

/**
 * Readiness: can this installation actually do its job?
 *
 * Reports whether each secret is PRESENT — never its value, never its length,
 * never a prefix. Also probes that Rordi's JWKS is reachable from inside the
 * customer's account, which is the failure a customer cannot otherwise see.
 */
async function handleReady(request, url, env) {
  const challenge = url.searchParams.get('challenge') ?? ''
  if (challenge.length < 16 || challenge.length > 256) {
    return jsonError('invalid_challenge', 400)
  }
  if (!env.RORDI_BRIDGE_KEY) {
    return jsonError('not_configured', 503)
  }

  let jwksReachable = false
  let jwksError = ''
  try {
    const origin = String(env.RORDI_URL ?? '').replace(/\/+$/, '')
    const res = await fetch(`${origin}/.well-known/jwks.json`, { redirect: 'manual' })
    jwksReachable = res.ok
    if (!res.ok) jwksError = `status_${res.status}`
  } catch (e) {
    // Message only, never the response body — it could echo request material.
    jwksError = e instanceof Error ? e.name : 'fetch_failed'
  }

  const claims = {
    ...identity(request, env),
    challenge,
    has_pairing_code: Boolean(env.RORDI_PAIRING_CODE),
    has_bridge_key: Boolean(env.RORDI_BRIDGE_KEY),
    rordi_url_configured: Boolean(env.RORDI_URL),
    jwks_reachable: jwksReachable,
    jwks_error: jwksError,
  }
  const signature = await sign(env.RORDI_BRIDGE_KEY, 'ready', claims)
  return Response.json({ claims, signature })
}

/**
 * Inbound leg of pairing: the Worker announces itself to Rordi.
 *
 * Runs Worker→Rordi (not Rordi→Worker) because the deploy button documents no
 * completion callback: Rordi has no way to learn the deployed URL otherwise.
 * The request carries the single-use pairing code plus a signature over the
 * code, this Worker's own origin, a nonce and a timestamp — so a code stolen in
 * transit is useless without the installation key, and a captured request
 * cannot be replayed against a different origin.
 *
 * Rordi MUST NOT trust `worker_origin` from this body alone; it completes
 * pairing by calling /_rordi/attest back at that origin with a fresh nonce.
 */
async function handlePair(request, env) {
  for (const name of ['RORDI_URL', 'RORDI_WORKSPACE', 'RORDI_PAIRING_CODE', 'RORDI_BRIDGE_KEY']) {
    if (!env[name]) return jsonError(`missing_config:${name}`, 503)
  }

  let workerOrigin
  try {
    workerOrigin = normalizeWorkerUrl(new URL(request.url).origin)
  } catch (e) {
    return jsonError(e instanceof Error ? e.message : 'bad_origin', 400)
  }

  const nonce = crypto.randomUUID()
  const issuedAt = Math.floor(Date.now() / 1000)
  const claims = {
    issued_at: issuedAt,
    nonce,
    pairing_code: env.RORDI_PAIRING_CODE,
    protocol_max: PROTOCOL_MAX,
    protocol_min: PROTOCOL_MIN,
    release: TEMPLATE_RELEASE,
    worker_origin: workerOrigin,
    workspace_id: env.RORDI_WORKSPACE,
  }
  const signature = await sign(env.RORDI_BRIDGE_KEY, 'pair', claims)

  const origin = String(env.RORDI_URL).replace(/\/+$/, '')
  const res = await fetch(`${origin}/api/bridge/pair`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ claims, signature }),
    redirect: 'manual',
  })

  // Pass through Rordi's decision verbatim so the customer sees the real reason
  // (expired code, already paired, workspace mismatch) rather than a generic 500.
  const body = await res.text()
  return new Response(body, {
    status: res.status,
    headers: { 'content-type': 'application/json' },
  })
}

function jsonError(error, status) {
  return Response.json({ error }, { status })
}

export const _internal = { ATTESTATION_MAX_AGE_S }
