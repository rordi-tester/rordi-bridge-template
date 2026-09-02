/**
 * RD-14142 — adversarial cases against the LIVE deployment.
 *
 * The offline harness proves the verifier's logic. This proves the same
 * rejections hold when the helper is a real Worker on Cloudflare's edge and the
 * control plane is a separate host reached over the public internet — i.e. that
 * nothing about real TLS, real DNS, real isolates or real network timing
 * loosens a check.
 *
 * Env: CP (control-plane URL), HELPER (worker origin), SEED_SECRET, BRIDGE_KEY.
 *
 * POINT `CP` AT THE CONTROL PLANE DIRECTLY, NOT THROUGH A QUICK TUNNEL.
 * Cloudflare's trycloudflare tunnel replaces any 5xx an origin returns with its
 * own branded HTML error page, which swallows the JSON body of every refusal
 * that maps to 502 (endpoint_unreachable, endpoint_attestation_malformed). The
 * server's own audit log confirms it decided correctly; the tunnel just does
 * not relay it. The outbound attestation leg still crosses the real internet to
 * the real Worker on Cloudflare's edge, which is the part that matters here.
 */

import { sign } from '../src/pairing.js'

const CP = process.env.CP
const HELPER = process.env.HELPER
const SEED = process.env.SEED_SECRET
const KEY = process.env.BRIDGE_KEY
const WS = 'ws_spike_14142'
// Attacker-controlled endpoints, really deployed (see live/README).
const JUNK = process.env.JUNK_ORIGIN
const SIGNED = process.env.SIGNED_ORIGIN

let n = 0
const code = () => `pc_live_case_${Date.now()}_${n++}`
const results = []

async function seed(c, over = {}) {
  const r = await fetch(`${CP}/__seed`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-seed-secret': SEED },
    body: JSON.stringify({
      code: c,
      workspaceId: WS,
      bridgeKey: KEY,
      expiresAt: Math.floor(Date.now() / 1000) + 900,
      ...over,
    }),
  })
  if (!r.ok) throw new Error(`seed failed ${r.status}`)
}

async function pairRaw(claims, signature) {
  const r = await fetch(`${CP}/api/bridge/pair`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ claims, signature }),
  })
  return { status: r.status, body: await r.json() }
}

/** A well-formed claim set, signed with `key`, as the helper would produce. */
async function forgeClaims(c, over = {}, key = KEY) {
  const claims = {
    issued_at: Math.floor(Date.now() / 1000),
    nonce: crypto.randomUUID(),
    pairing_code: c,
    protocol_max: 1,
    protocol_min: 1,
    release: '0.1.0-rd14142',
    worker_origin: HELPER,
    workspace_id: WS,
    ...over,
  }
  return { claims, signature: await sign(key, 'pair', claims) }
}

async function check(name, expected, fn) {
  try {
    const { status, body } = await fn()
    const got = body.error ?? `paired(${status})`
    results.push({ name, expected, got, pass: got === expected })
  } catch (e) {
    results.push({ name, expected, got: `threw:${e.message}`, pass: false })
  }
}

// 1. Expired code, live.
await check('expired code', 'pairing_code_expired', async () => {
  const c = code()
  await seed(c, { expiresAt: Math.floor(Date.now() / 1000) - 1 })
  const { claims, signature } = await forgeClaims(c)
  return pairRaw(claims, signature)
})

// 2. Code minted for a different workspace.
await check('wrong workspace', 'workspace_mismatch', async () => {
  const c = code()
  await seed(c, { workspaceId: 'ws_someone_else' })
  const { claims, signature } = await forgeClaims(c)
  return pairRaw(claims, signature)
})

// 3. Attacker holds the code but not the installation key.
await check('code without key', 'pair_signature_invalid', async () => {
  const c = code()
  await seed(c)
  const { claims, signature } = await forgeClaims(c, {}, 'bk_attacker_does_not_know')
  return pairRaw(claims, signature)
})

// 4a. Attacker redirects pairing to an endpoint they control, and signs it
//     correctly (models a leaked installation key). The outbound challenge is
//     the only thing between Rordi and pairing to an attacker's box: this host
//     has no /_rordi/attest at all.
await check('attacker endpoint (no attest route)', 'endpoint_unreachable', async () => {
  const c = code()
  await seed(c)
  const { claims, signature } = await forgeClaims(c, { worker_origin: 'https://example.com' })
  return pairRaw(claims, signature)
})

// 4b. Harder version: an attacker host that DOES answer 200 with valid JSON,
//     just not a signed attestation. Rejected on shape, before any signature
//     work — a 200 is not evidence of anything.
await check('attacker endpoint (200 JSON, not an attestation)', 'endpoint_attestation_malformed', async () => {
  const c = code()
  await seed(c)
  const { claims, signature } = await forgeClaims(c, { worker_origin: JUNK })
  return pairRaw(claims, signature)
})

// 4c. The strongest attacker: a real HTTPS endpoint that returns a perfectly
//     SHAPED attestation, echoing the challenge and its own origin, but signed
//     with a key it invented. Everything except the signature looks right, so
//     this is the case where the signature check is the only thing left.
await check('attacker endpoint (shaped but forged signature)', 'endpoint_attestation_failed', async () => {
  const c = code()
  await seed(c)
  const { claims, signature } = await forgeClaims(c, { worker_origin: SIGNED })
  return pairRaw(claims, signature)
})

// 5. Tampering after signing: flip the origin, leave the signature.
await check('origin swapped post-signature', 'pair_signature_invalid', async () => {
  const c = code()
  await seed(c)
  const { claims, signature } = await forgeClaims(c)
  return pairRaw({ ...claims, worker_origin: 'https://evil.example' }, signature)
})

// 6. Stale claim replayed an hour later.
await check('stale claim', 'pair_claim_stale', async () => {
  const c = code()
  await seed(c)
  const { claims, signature } = await forgeClaims(c, {
    issued_at: Math.floor(Date.now() / 1000) - 3600,
  })
  return pairRaw(claims, signature)
})

// 7. Plain http origin.
await check('http origin', 'worker_url_must_be_https', async () => {
  const c = code()
  await seed(c)
  const { claims, signature } = await forgeClaims(c, {
    worker_origin: HELPER.replace('https://', 'http://'),
  })
  return pairRaw(claims, signature)
})

// 8. Never-minted code.
await check('unknown code', 'pairing_code_unknown', async () => {
  const { claims, signature } = await forgeClaims('pc_never_minted_at_all')
  return pairRaw(claims, signature)
})

// 9. Honest control: everything correct still pairs, live.
await check('honest pair still succeeds', 'paired(200)', async () => {
  const c = code()
  await seed(c)
  const { claims, signature } = await forgeClaims(c)
  return pairRaw(claims, signature)
})

const w = Math.max(...results.map((r) => r.name.length))
let fail = 0
console.log('\nRD-14142 LIVE adversarial (real Worker + real network)\n')
for (const r of results) {
  if (!r.pass) fail++
  console.log(`${r.pass ? 'PASS' : 'FAIL'}  ${r.name.padEnd(w)}  expected=${r.expected}  got=${r.got}`)
}
console.log(`\n${results.length - fail}/${results.length} passed`)
process.exit(fail ? 1 : 0)
