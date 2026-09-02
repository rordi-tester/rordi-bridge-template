/**
 * RD-14142 — adversarial harness for the pairing contract.
 *
 * This is NOT a vitest file and deliberately does not join the orchestrator
 * suite (CLAUDE.md / CC10: a test earns its place by carrying something an
 * agent cannot get by reading the code). It is a spike EVIDENCE PRODUCER: it
 * runs the real worker handler and the real Rordi verifier against each other
 * and prints a pass/fail table that gets pasted into RD-14142.
 *
 * Run: node spikes/rd-14142-bridge-template/harness/adversarial.mjs
 *
 * WHAT THIS CAN AND CANNOT PROVE. Every case here is protocol logic and runs
 * fully offline. It proves the pairing state machine rejects expired, replayed,
 * wrong-workspace and attacker-endpoint attempts. It CANNOT prove the deploy
 * button collects these secrets, that Workers Builds redeploys on merge, or
 * that rollback restores a version — those need a live disposable account.
 */

import { completePairing, PairingError } from '../src/rordi-pair-endpoint.js'
import { sign } from '../src/pairing.js'
import worker from '../src/worker.js'

const WORKSPACE = 'ws_alpha'
const OTHER_WORKSPACE = 'ws_beta'
const ORIGIN = 'https://rordi-bridge-a1b2c3.example.workers.dev'
const EVIL_ORIGIN = 'https://attacker.example.workers.dev'
const RORDI = 'https://app.rordi.test'

// Track real time: the worker handler stamps `issued_at` from the real clock,
// so a synthetic epoch here would trip the freshness check on every case.
const clock = Math.floor(Date.now() / 1000)
const now = () => clock

function makeStore(overrides = {}) {
  const rec = {
    code: 'pc_live_0123456789abcdef',
    installationId: 'inst_1',
    workspaceId: WORKSPACE,
    bridgeKey: 'bk_super_secret_installation_key',
    expiresAt: now() + 900,
    consumedAt: null,
    serverProtocolMin: 1,
    serverProtocolMax: 1,
    ...overrides,
  }
  return {
    rec,
    async get(code) {
      return code === rec.code ? rec : null
    },
    async consume(code) {
      if (code !== rec.code || rec.consumedAt) return false
      rec.consumedAt = now()
      return true
    },
  }
}

/** A worker env; `secrets` overrides let us simulate a misconfigured install. */
function makeEnv(over = {}) {
  return {
    RORDI_URL: RORDI,
    RORDI_WORKSPACE: WORKSPACE,
    RORDI_PAIRING_CODE: 'pc_live_0123456789abcdef',
    RORDI_BRIDGE_KEY: 'bk_super_secret_installation_key',
    VERSION: { id: 'cfver_7f3a', tag: 'v1' },
    ...over,
  }
}

/** Drive the REAL worker handler to produce a real pair body. */
async function realPairBody(env, originUrl = ORIGIN) {
  let captured = null
  const originalFetch = globalThis.fetch
  globalThis.fetch = async (url, init) => {
    captured = JSON.parse(init.body)
    return new Response('{}', { status: 200 })
  }
  try {
    await worker.fetch(new Request(`${originUrl}/_rordi/pair`, { method: 'POST' }), env)
  } finally {
    globalThis.fetch = originalFetch
  }
  return captured
}

/** Honest attest responder: the real worker handler at `origin`. */
function honestAttest(env, origin = ORIGIN) {
  return async (calledOrigin, challenge) => {
    const res = await worker.fetch(
      new Request(`${origin}/_rordi/attest?challenge=${encodeURIComponent(challenge)}`),
      env,
    )
    if (!res.ok) throw new Error(`attest_${res.status}`)
    return res.json()
  }
}

let challengeCounter = 0
const randomChallenge = () => `chal_${(challengeCounter++).toString().padStart(24, '0')}`

const results = []
async function check(name, expected, fn) {
  try {
    const value = await fn()
    const got = expected === 'PAIRS' ? 'PAIRS' : `no-rejection (paired: ${value?.state})`
    results.push({ name, expected, got, pass: expected === 'PAIRS' })
  } catch (e) {
    const got = e instanceof PairingError ? e.code : `unexpected:${e.message}`
    results.push({ name, expected, got, pass: got === expected })
  }
}

// ── 1. Happy path ────────────────────────────────────────────────────────────
await check('honest install pairs', 'PAIRS', async () => {
  const store = makeStore()
  const env = makeEnv()
  return completePairing(await realPairBody(env), {
    store,
    fetchAttest: honestAttest(env),
    now,
    randomChallenge,
  })
})

// ── 2. Replay: the same captured body used twice ─────────────────────────────
await check('replayed pairing code rejected', 'pairing_code_consumed', async () => {
  const store = makeStore()
  const env = makeEnv()
  const body = await realPairBody(env)
  const deps = { store, fetchAttest: honestAttest(env), now, randomChallenge }
  await completePairing(body, deps)
  return completePairing(body, deps)
})

// ── 3. Expired code ──────────────────────────────────────────────────────────
await check('expired pairing code rejected', 'pairing_code_expired', async () => {
  const env = makeEnv()
  const body = await realPairBody(env)
  const store = makeStore({ expiresAt: now() - 1 })
  return completePairing(body, { store, fetchAttest: honestAttest(env), now, randomChallenge })
})

// ── 4. Wrong workspace: correct code, Worker bound to another workspace ──────
await check('wrong-workspace install rejected', 'workspace_mismatch', async () => {
  const env = makeEnv({ RORDI_WORKSPACE: OTHER_WORKSPACE })
  const body = await realPairBody(env)
  return completePairing(body, {
    store: makeStore(),
    fetchAttest: honestAttest(env),
    now,
    randomChallenge,
  })
})

// ── 5. Stolen code, no installation key ──────────────────────────────────────
await check('stolen code without bridge key rejected', 'pair_signature_invalid', async () => {
  const env = makeEnv({ RORDI_BRIDGE_KEY: 'bk_attacker_guess' })
  const body = await realPairBody(env)
  return completePairing(body, {
    store: makeStore(),
    fetchAttest: honestAttest(env),
    now,
    randomChallenge,
  })
})

// ── 6. Attacker-controlled endpoint: valid claim, URL swapped to attacker ────
await check('attacker-supplied URL rejected', 'pair_signature_invalid', async () => {
  const env = makeEnv()
  const body = await realPairBody(env)
  body.claims.worker_origin = EVIL_ORIGIN // signature no longer covers this
  return completePairing(body, {
    store: makeStore(),
    fetchAttest: honestAttest(env),
    now,
    randomChallenge,
  })
})

// ── 7. Endpoint that cannot answer the challenge (no key) ────────────────────
await check('endpoint without key fails attestation', 'endpoint_attestation_failed', async () => {
  const env = makeEnv()
  const body = await realPairBody(env)
  const impostorEnv = makeEnv({ RORDI_BRIDGE_KEY: 'bk_impostor' })
  return completePairing(body, {
    store: makeStore(),
    fetchAttest: honestAttest(impostorEnv),
    now,
    randomChallenge,
  })
})

// ── 8. Relay: endpoint replays a previously captured valid attestation ───────
await check('replayed attestation rejected', 'endpoint_challenge_mismatch', async () => {
  const env = makeEnv()
  const body = await realPairBody(env)
  const stale = await honestAttest(env)(ORIGIN, randomChallenge())
  return completePairing(body, {
    store: makeStore(),
    fetchAttest: async () => stale,
    now,
    randomChallenge,
  })
})

// ── 9. Unreachable endpoint ──────────────────────────────────────────────────
await check('unreachable endpoint rejected', 'endpoint_unreachable', async () => {
  const env = makeEnv()
  const body = await realPairBody(env)
  return completePairing(body, {
    store: makeStore(),
    fetchAttest: async () => {
      throw new Error('ECONNREFUSED')
    },
    now,
    randomChallenge,
  })
})

// ── 10. Stale claim (clock skew abuse) ───────────────────────────────────────
await check('stale pair claim rejected', 'pair_claim_stale', async () => {
  const env = makeEnv()
  const body = await realPairBody(env)
  body.claims.issued_at = now() - 3600
  body.signature = await sign(env.RORDI_BRIDGE_KEY, 'pair', body.claims)
  return completePairing(body, {
    store: makeStore(),
    fetchAttest: honestAttest(env),
    now,
    randomChallenge,
  })
})

// ── 11. Non-https origin ─────────────────────────────────────────────────────
await check('http origin rejected', 'worker_url_must_be_https', async () => {
  const env = makeEnv()
  const body = await realPairBody(env)
  body.claims.worker_origin = 'http://rordi-bridge-a1b2c3.example.workers.dev'
  body.signature = await sign(env.RORDI_BRIDGE_KEY, 'pair', body.claims)
  return completePairing(body, {
    store: makeStore(),
    fetchAttest: honestAttest(env),
    now,
    randomChallenge,
  })
})

// ── 12. Unknown code ─────────────────────────────────────────────────────────
await check('unknown pairing code rejected', 'pairing_code_unknown', async () => {
  const env = makeEnv({ RORDI_PAIRING_CODE: 'pc_never_minted' })
  const body = await realPairBody(env)
  return completePairing(body, {
    store: makeStore(),
    fetchAttest: honestAttest(env),
    now,
    randomChallenge,
  })
})

// ── 13. Protocol incompatibility ─────────────────────────────────────────────
await check('incompatible protocol rejected', 'protocol_incompatible', async () => {
  const env = makeEnv()
  const body = await realPairBody(env)
  return completePairing(body, {
    store: makeStore({ serverProtocolMin: 5, serverProtocolMax: 7 }),
    fetchAttest: honestAttest(env),
    now,
    randomChallenge,
  })
})

// ── 14. /livez discloses nothing ─────────────────────────────────────────────
{
  const res = await worker.fetch(new Request(`${ORIGIN}/livez`), makeEnv())
  const body = await res.text()
  const pass = res.status === 204 && body === ''
  results.push({
    name: '/livez is 204 with empty body',
    expected: '204 + empty',
    got: `${res.status} + ${JSON.stringify(body)}`,
    pass,
  })
}

// ── 15. /_rordi/ready never returns secret values ────────────────────────────
{
  const env = makeEnv()
  const originalFetch = globalThis.fetch
  globalThis.fetch = async () => new Response('{"keys":[]}', { status: 200 })
  let text
  try {
    const res = await worker.fetch(
      new Request(`${ORIGIN}/_rordi/ready?challenge=${randomChallenge()}`),
      env,
    )
    text = await res.text()
  } finally {
    globalThis.fetch = originalFetch
  }
  const leaked = [env.RORDI_BRIDGE_KEY, env.RORDI_PAIRING_CODE].filter((s) => text.includes(s))
  results.push({
    name: '/_rordi/ready leaks no secret value',
    expected: 'no secret substring',
    got: leaked.length ? `LEAKED ${leaked.length}` : 'no secret substring',
    pass: leaked.length === 0,
  })
}

// ── Report ───────────────────────────────────────────────────────────────────
const width = Math.max(...results.map((r) => r.name.length))
let failures = 0
console.log('\nRD-14142 pairing contract — adversarial harness\n')
for (const r of results) {
  if (!r.pass) failures++
  console.log(`${r.pass ? 'PASS' : 'FAIL'}  ${r.name.padEnd(width)}  expected=${r.expected}  got=${r.got}`)
}
console.log(`\n${results.length - failures}/${results.length} passed`)
process.exit(failures === 0 ? 0 : 1)
