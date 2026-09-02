/**
 * RD-14142 — pairing / attestation primitives.
 *
 * Shared by the helper Worker (customer's Cloudflare account) and by the Rordi
 * control plane. Deliberately dependency-free and WebCrypto-only so the exact
 * same source runs in workerd, in Node, and in the adversarial harness — the
 * protocol is proven once rather than reimplemented twice and hoped to match.
 *
 * WHAT THE HMAC ATTESTATION PROVES, AND WHAT IT DOES NOT
 * The installation key (`RORDI_BRIDGE_KEY`) is minted by Rordi and entered by
 * the customer into Cloudflare. A valid attestation therefore proves only:
 *   "the endpoint answering at this URL holds the installation key Rordi minted
 *    for installation <id> of workspace <w>".
 * It does NOT prove the deployed code is unmodified, and because Rordi also
 * holds the key it is NOT non-repudiable against Rordi. It is a channel /
 * endpoint binding, not a code attestation. Anything stronger requires a
 * Worker-generated keypair, which requires writable state (KV/DO) — out of
 * scope for this spike. See RD-14142.
 */

const enc = new TextEncoder()

/** Bridge protocol version range this template speaks. */
export const PROTOCOL_MIN = 1
export const PROTOCOL_MAX = 1

/** Skew tolerance (seconds) for a client-supplied timestamp. */
export const CLOCK_SKEW_S = 60
/** Max age (seconds) of a pairing attestation timestamp. */
export const ATTESTATION_MAX_AGE_S = 300

/**
 * Canonical signing string. Field order is fixed and every field is
 * length-prefixed, so no combination of values can be reinterpreted as a
 * different message (the classic `a|b` vs `a|b` concatenation ambiguity).
 */
export function canonical(purpose, fields) {
  const parts = [`v1`, purpose]
  for (const key of Object.keys(fields).sort()) {
    const value = String(fields[key] ?? '')
    parts.push(`${key.length}:${key}=${value.length}:${value}`)
  }
  return parts.join('\n')
}

async function hmacKey(secret) {
  return crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
    'verify',
  ])
}

export function toBase64Url(bytes) {
  let s = ''
  const view = new Uint8Array(bytes)
  for (let i = 0; i < view.length; i++) s += String.fromCharCode(view[i])
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** HMAC-SHA256 over the canonical form, returned base64url. */
export async function sign(secret, purpose, fields) {
  const key = await hmacKey(secret)
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(canonical(purpose, fields)))
  return toBase64Url(sig)
}

/**
 * Constant-time verification. `crypto.subtle.verify` compares internally, so we
 * never do a JS string compare on signature material.
 */
export async function verify(secret, purpose, fields, signatureB64Url) {
  let sigBytes
  try {
    const std = signatureB64Url.replace(/-/g, '+').replace(/_/g, '/')
    const padded = std + '='.repeat((4 - (std.length % 4)) % 4)
    const bin = atob(padded)
    sigBytes = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) sigBytes[i] = bin.charCodeAt(i)
  } catch {
    return false
  }
  const key = await hmacKey(secret)
  return crypto.subtle.verify('HMAC', key, sigBytes, enc.encode(canonical(purpose, fields)))
}

/**
 * Normalize a worker URL before it is signed or compared. Pairing binds the
 * exact origin: an attacker who replays a valid attestation against a different
 * host, port, or scheme must not match.
 */
export function normalizeWorkerUrl(raw) {
  const u = new URL(raw)
  if (u.protocol !== 'https:') throw new Error('worker_url_must_be_https')
  if (u.username || u.password) throw new Error('worker_url_must_not_carry_credentials')
  if (u.search || u.hash) throw new Error('worker_url_must_not_carry_query_or_fragment')
  if (u.pathname !== '/' && u.pathname !== '') throw new Error('worker_url_must_be_origin_only')
  return u.origin
}
