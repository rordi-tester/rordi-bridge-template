# RD-14142 — live proof against a real disposable Cloudflare account

Executed 2026-09-02 against the disposable account `b08906709abc2c1f7a834ebf36082e68`
("Rordi@agentmail.to's Account", created the same day). **Not** the production
`CLOUDFLARE_*_MODOL` account — `deploy.sh` refuses if the two ever match.

Everything below was deployed, exercised, and then **deleted**; the account now
has zero Worker scripts. Re-run with `deploy.sh`.

## What ran

| Worker | Role |
|---|---|
| `rordi-bridge-helper` | the customer's helper Worker (`src/worker.js`) |
| `rordi-spike-control` | first attempt at a Rordi stand-in — **abandoned**, see below |
| `rordi-spike-imp-junk` | attacker endpoint: answers 200 with non-attestation JSON |
| `rordi-spike-imp-signed` | attacker endpoint: correctly *shaped* attestation, forged signature |

The control plane ended up as a Node process (`control-plane-node.mjs`) exposed
through a `cloudflared` quick tunnel, because two Cloudflare behaviours ruled
out running it as a Worker — both discovered here, neither documented in the
research:

- **Worker→Worker fetch on the same `workers.dev` zone is refused (error 1042).**
  The helper simply could not call a sibling Worker, so the inbound pairing leg
  was untestable in that shape.
- **Module-scope state is per-isolate**, so a pairing code seeded by one request
  was invisible to the next. Any real single-use guarantee needs durable
  compare-and-set storage.

Running the control plane off Cloudflare is also more faithful: that is where
Rordi's control plane actually lives.

## Result

`adversarial-live.mjs` — **11/11**, against the real Worker on the real edge:

```
PASS  expired code                                      pairing_code_expired
PASS  wrong workspace                                   workspace_mismatch
PASS  code without key                                  pair_signature_invalid
PASS  attacker endpoint (no attest route)               endpoint_unreachable
PASS  attacker endpoint (200 JSON, not an attestation)  endpoint_attestation_malformed
PASS  attacker endpoint (shaped but forged signature)   endpoint_attestation_failed
PASS  origin swapped post-signature                     pair_signature_invalid
PASS  stale claim                                       pair_claim_stale
PASS  http origin                                       worker_url_must_be_https
PASS  unknown code                                      pairing_code_unknown
PASS  honest pair still succeeds                        paired(200)
```

Plus, end to end over the public internet: an honest pair succeeded, and an
immediate replay of the same code was refused `409 pairing_code_consumed`.

## Findings that change the production spec

1. **`workers.dev` subdomain CAN be created via API** — `PUT
   /accounts/{id}/workers/subdomain`. The `GET` on a fresh account returns error
   10007 telling you to visit the dashboard, which is misleading: the write path
   works headlessly. RD-14092 listed this as an open assumption.
2. **Worker Secrets survive a redeploy that does not re-declare them.** A script
   update carrying only the non-secret bindings kept both secrets, and the
   attestation still verified under the *original* installation key — so the
   value persisted, not merely the name. Customer-managed updates do not silently
   break the installation.
3. **Secrets also survive a rollback**, and the rolled-back version re-paired
   cleanly. Rordi observed the reverted release and version id, so drift
   detection has something real to compare.
4. **`workers/triggered_by` is rejected** as a deployment annotation (error
   10210); only `workers/message` was accepted.
5. **A malformed upload is safely rejected** — a bad module filename failed the
   PUT and the previously deployed version kept serving unharmed.
6. **The quick tunnel rewrites any origin 5xx into its own HTML error page**, so
   refusals that map to 502 lose their JSON body in transit. Test infrastructure
   caveat only; the server's audit log showed it decided correctly.

## Still NOT proven

The two legs that need a browser and a Git push, both still blocked:

- the **deploy button** itself — whether Cloudflare renders the `vars`/`secrets`
  prompts from `wrangler.jsonc` and stores them as Secrets. This is the custody
  claim, and it remains documentation-derived. Everything above was deployed
  through the **API**, which proves the Worker and the pairing protocol but says
  nothing about the button's UX or what it asks the customer to approve.
- **Workers Builds** — whether merging an upstream update PR redeploys.
