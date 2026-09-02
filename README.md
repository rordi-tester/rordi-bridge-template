# Rordi helper Worker — customer-managed template (RD-14142 spike artifact)

> **This is a spike artifact, not a shipped template.** It is staged inside the
> monorepo so it can be reviewed and run offline. To actually serve a Deploy to
> Cloudflare button it must be published as its own **public** Git repository —
> the button takes a repository URL and clones it into the customer's Git
> account. Nothing here has been deployed to a real Cloudflare account.

## What this proves, and what it does not

Proven offline, by `harness/adversarial.mjs` (15/15 passing):

- the pairing state machine rejects expired, replayed, wrong-workspace,
  unknown-code, stale, non-HTTPS, protocol-incompatible and
  attacker-endpoint attempts;
- `/livez` returns 204 and discloses nothing;
- `/_rordi/ready` reports secret **presence** without ever returning a value.

**Not proven** — every one of these needs a live disposable Cloudflare account
and a human at a browser:

- that the deploy button renders the `vars` / `secrets` prompts this
  `wrangler.jsonc` declares, and stores them as Worker Secrets;
- the exact Cloudflare and Git permissions the button requests;
- the identifiers Cloudflare returns (account id, worker name, `workers.dev`
  subdomain, version id, deployment id);
- that merging an upstream update PR triggers Workers Builds and redeploys;
- that a Cloudflare rollback restores the previous version and that pairing
  survives it;
- disconnect and cleanup behaviour (delete Worker, revoke installation).

## Scope boundaries

This template contains **no credential proxy, no R2, no KV**, and no link to
Rordi's `EgressBrokerDO` / `globalOutbound` path. Those are deliberately out of
scope: RD-14092 found that path has an unauthenticated `/__init` reachable from
untrusted isolate code and under-specified JWT/capability checks. Those are
production-spec defects to fix, not defects to route around here.

## Layout

| Path | Role |
|---|---|
| `src/worker.js` | the helper Worker: `/livez`, `/_rordi/attest`, `/_rordi/ready`, `/_rordi/pair` |
| `src/pairing.js` | canonical signing + HMAC primitives, shared by both sides |
| `src/rordi-pair-endpoint.js` | reference implementation of Rordi's `POST /api/bridge/pair` |
| `harness/adversarial.mjs` | offline attack harness; prints the evidence table |

## The pairing exchange

The deploy button documents **no completion callback**, so Rordi cannot learn
the deployed URL by itself. Pairing is therefore two-legged:

1. **Inbound.** The customer hits `POST /_rordi/pair` on their new Worker. The
   Worker posts to Rordi its pairing code, its own origin, a nonce, a timestamp
   and an HMAC over all of it under the installation key.
2. **Outbound.** Rordi does **not** trust that body's URL. It calls
   `GET /_rordi/attest?challenge=<fresh nonce>` at the claimed origin and
   requires a signature binding that nonce to that origin and workspace.

Only after both legs is the code consumed — atomically, so a concurrent second
attempt loses. A stolen code without the installation key fails leg 1; a
substituted URL fails leg 1's signature; an endpoint that does not hold the key
fails leg 2; a captured attestation replayed later fails the challenge check.

### Honest limit of the attestation

`RORDI_BRIDGE_KEY` is minted by Rordi and entered by the customer, so **Rordi
also holds it**. A valid attestation proves *"the endpoint at this URL holds the
installation key"* — an endpoint/channel binding. It does **not** prove the
deployed code is unmodified, and it is **not** non-repudiable against Rordi.
Stronger attestation needs a Worker-generated keypair, which needs writable
state (KV or a Durable Object) — out of scope for this spike, and a real
decision for the production spec.

## Running the evidence harness

```
node spikes/rd-14142-bridge-template/harness/adversarial.mjs
```

It is intentionally **not** a vitest file and does not join the orchestrator
suite: per CC10 a test earns its place by carrying something an agent cannot get
by reading the code. This is a spike evidence producer with a finite life.
