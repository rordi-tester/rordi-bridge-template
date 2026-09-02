/**
 * RD-14142 — TEST-ONLY Rordi control plane, as a Node service.
 *
 * Replaces the Worker version (live/control-plane-worker.js), which hit two
 * walls that are artifacts of hosting it on Cloudflare rather than properties
 * of the pairing protocol:
 *   - Cloudflare refuses a Worker->Worker subrequest on the same workers.dev
 *     zone (error 1042), so the helper could not call it at all;
 *   - module-scope state is per-isolate, so a seeded code was invisible to the
 *     next request.
 * A Node process has real process memory and lives off Cloudflare entirely,
 * which is also where Rordi's control plane actually lives. Still test-only:
 * the store is in-process and dies with the process.
 */

import { createServer } from 'node:http'
import { completePairing, PairingError } from '../src/rordi-pair-endpoint.js'

const PORT = Number(process.env.PORT ?? 8791)
const SEED_SECRET = process.env.SEED_SECRET ?? ''
if (!SEED_SECRET) throw new Error('SEED_SECRET required')

/** code -> record */
const store = new Map()
/** Every decision, for the evidence record. */
const audit = []

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

function json(res, status, body) {
  const payload = JSON.stringify(body)
  res.writeHead(status, { 'content-type': 'application/json' })
  res.end(payload)
}

async function readBody(req) {
  const chunks = []
  for await (const c of req) chunks.push(c)
  return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')
}

createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`)
  try {
    if (url.pathname === '/__seed' && req.method === 'POST') {
      if (req.headers['x-seed-secret'] !== SEED_SECRET) return json(res, 403, { error: 'forbidden' })
      const b = await readBody(req)
      store.set(b.code, {
        code: b.code,
        installationId: b.installationId ?? 'inst_live',
        workspaceId: b.workspaceId,
        bridgeKey: b.bridgeKey,
        expiresAt: b.expiresAt,
        consumedAt: null,
        serverProtocolMin: b.serverProtocolMin ?? 1,
        serverProtocolMax: b.serverProtocolMax ?? 1,
      })
      return json(res, 200, { seeded: b.code })
    }

    if (url.pathname === '/__state' && req.method === 'GET') {
      if (req.headers['x-seed-secret'] !== SEED_SECRET) return json(res, 403, { error: 'forbidden' })
      return json(res, 200, {
        // bridgeKey deliberately omitted.
        codes: [...store.values()].map((r) => ({
          code: r.code,
          workspaceId: r.workspaceId,
          expiresAt: r.expiresAt,
          consumedAt: r.consumedAt,
          workerOrigin: r.workerOrigin ?? null,
        })),
        audit,
      })
    }

    // Rordi's JWKS, so the helper's readiness probe has something real to hit.
    if (url.pathname === '/.well-known/jwks.json') return json(res, 200, { keys: [] })

    if (url.pathname === '/api/bridge/pair' && req.method === 'POST') {
      const body = await readBody(req)
      try {
        const result = await completePairing(body, {
          store: backing,
          now: () => Math.floor(Date.now() / 1000),
          randomChallenge: () => crypto.randomUUID() + crypto.randomUUID(),
          fetchAttest: async (origin, challenge) => {
            const r = await fetch(`${origin}/_rordi/attest?challenge=${encodeURIComponent(challenge)}`, {
              redirect: 'manual',
            })
            if (!r.ok) throw new Error(`attest_status_${r.status}`)
            return r.json()
          },
        })
        audit.push({ at: new Date().toISOString(), outcome: 'paired', result })
        return json(res, 200, result)
      } catch (e) {
        const code = e instanceof PairingError ? e.code : `internal:${e?.message}`
        const status = e instanceof PairingError ? e.status : 500
        audit.push({ at: new Date().toISOString(), outcome: 'refused', code })
        return json(res, status, { error: code })
      }
    }

    return json(res, 404, { error: 'not_found' })
  } catch (e) {
    return json(res, 500, { error: String(e?.message ?? e) })
  }
}).listen(PORT, () => console.log(`control plane on :${PORT}`))
