/**
 * RD-14142 — TEST-ONLY stand-in for Rordi's control plane.
 *
 * Rordi's real `POST /api/bridge/pair` does not exist yet (production
 * onboarding is an explicit spike non-goal). To prove the pairing exchange over
 * the real internet — including Rordi's OUTBOUND challenge back to the helper
 * Worker — this deploys the reference verifier as its own Worker.
 *
 * NOT PRODUCTION. Two deliberate shortcuts, both spike-only:
 *  - the pairing-code store is module-scope memory, so it is per-isolate and
 *    evaporates on eviction. Real single-use enforcement needs a durable
 *    compare-and-set; KV/DO/R2 are out of scope here. A `consumed` result from
 *    this Worker is therefore only meaningful for requests that land on the
 *    same isolate, which a tight sequential test does.
 *  - it exposes /__seed to load a code, which a real control plane would never
 *    do. Guarded by a shared secret so the deployed instance is not an open
 *    pairing oracle for the duration of the spike.
 */

import { completePairing, PairingError } from './rordi-pair-endpoint.js'

/** code -> record. Per-isolate; see caveat above. */
const store = new Map()

const backing = {
  async get(code) {
    return store.get(code) ?? null
  },
  async consume(code, meta) {
    const rec = store.get(code)
    if (!rec || rec.consumedAt) return false
    rec.consumedAt = meta.at
    rec.workerOrigin = meta.workerOrigin
    return true
  },
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url)

    if (url.pathname === '/__seed' && request.method === 'POST') {
      if (request.headers.get('x-seed-secret') !== env.SEED_SECRET) {
        return new Response('forbidden', { status: 403 })
      }
      const body = await request.json()
      store.set(body.code, {
        code: body.code,
        installationId: body.installationId ?? 'inst_live',
        workspaceId: body.workspaceId,
        bridgeKey: body.bridgeKey,
        expiresAt: body.expiresAt,
        consumedAt: null,
        serverProtocolMin: 1,
        serverProtocolMax: 1,
      })
      return Response.json({ seeded: body.code })
    }

    if (url.pathname === '/__state' && request.method === 'GET') {
      if (request.headers.get('x-seed-secret') !== env.SEED_SECRET) {
        return new Response('forbidden', { status: 403 })
      }
      // Never echo bridgeKey.
      return Response.json(
        [...store.values()].map((r) => ({
          code: r.code,
          workspaceId: r.workspaceId,
          consumedAt: r.consumedAt,
          workerOrigin: r.workerOrigin ?? null,
          expiresAt: r.expiresAt,
        })),
      )
    }

    if (url.pathname === '/api/bridge/pair' && request.method === 'POST') {
      let body
      try {
        body = await request.json()
      } catch {
        return Response.json({ error: 'bad_json' }, { status: 400 })
      }
      try {
        const result = await completePairing(body, {
          store: backing,
          now: () => Math.floor(Date.now() / 1000),
          randomChallenge: () => crypto.randomUUID() + crypto.randomUUID(),
          // The real outbound leg: a live cross-origin fetch to the helper.
          fetchAttest: async (origin, challenge) => {
            const res = await fetch(
              `${origin}/_rordi/attest?challenge=${encodeURIComponent(challenge)}`,
              { redirect: 'manual' },
            )
            if (!res.ok) throw new Error(`attest_status_${res.status}`)
            return res.json()
          },
        })
        return Response.json(result)
      } catch (e) {
        if (e instanceof PairingError) {
          return Response.json({ error: e.code }, { status: e.status })
        }
        return Response.json({ error: 'internal', detail: String(e?.message ?? e) }, { status: 500 })
      }
    }

    return new Response(null, { status: 404 })
  },
}
