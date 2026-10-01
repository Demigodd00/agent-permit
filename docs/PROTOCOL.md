# AgentPermit protocol

## Roles and state

The deployer is the policy owner. The constructor binds one agent address and one executor address. The contract starts paused without a policy. `set_policy` installs allowed capabilities (`READ_FILES`, `WRITE_FILES`, `NETWORK`, `SPEND`), up to 12 exact outbound domains, an attoGEN amount ceiling, and bounded prohibited-behavior text. Each update increments `policy_version` and preserves an immutable snapshot readable through `get_policy_version`. `set_executor` also increments it, invalidating unconsumed permits bound to the previous executor.

The agent calls `request_permit` with the next exact nonce, one capability, target, amount, action description, full-commit `raw.githubusercontent.com` evidence URL, SHA-256 of the exact evidence bytes, and an expiry no more than 24 hours ahead. The contract rejects malformed requests before model work. Explicit capability, domain, and amount violations yield `BLOCK` receipts without an LLM call.

For a request within hard limits, leader and validators independently fetch at most 16 KB of the public JSON evidence. The packet must contain `purpose`, `steps`, `capability`, `target`, `amount_atto`, and `outbound_domains`. The latter three exact fields must match the request. Missing, malformed, or digest-mismatched evidence yields `INSUFFICIENT_EVIDENCE`; listed outbound domains outside policy yield `BLOCK`. A 5xx/network error remains retryable and creates no receipt.

Validators independently assess the bounded plan against the policy's prohibited behavior. The custom equivalence rule compares the material decision and verified-evidence flag, and for missing evidence also compares the stable failure reason. Free-form explanations are stored but are not treated as consensus fields. LLM errors do not create a receipt.

The receipt ID is the SHA-256 of canonical JSON containing agent, policy version, nonce, capability, target, amount, action, evidence URL/hash, and expiry. The receipt stores this action digest, the action description, executor, decision, evidence verification flag, issue/expiry times, and consumption/revocation flags. `consume_permit` succeeds only for the configured executor and the exact action digest, on a current, unpaused, unexpired, unconsumed, unrevoked `ALLOW` receipt. Consumption is final. `revoke_receipt` is available to owner or agent before consumption.

## Example action plan

`evidence/read_report.json` is the tracked example. Its `raw.githubusercontent.com` URL must use an immutable 40-character commit SHA, never `main`. Hash the exact raw bytes before requesting a permit. The action description, target, capability, and amount supplied to `request_permit` must match the plan. Use `get_policy` to read the current nonce and version.

## Security boundary

Only the named agent can request permits, but external integrations must still verify they are enforcing the same action bytes represented by `action_digest`. `consume_permit` marks authorization as used; it does not itself perform a filesystem, network, or payment operation. The source evidence is a declaration of intent, not proof that the eventual runtime action obeys it. Public evidence may contain prompt injection and is treated as untrusted data. The assessment cannot prove an agent harmless or prevent an executor from violating policy after consumption.

The policy owner can pause requests and consumption immediately. A changed policy invalidates outstanding permits. A `REVIEW` receipt requires a separate human decision outside this contract; it is never consumable. `BLOCK` and `INSUFFICIENT_EVIDENCE` are likewise not consumable.
