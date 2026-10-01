# AgentPermit

AgentPermit is a standalone GenLayer Intelligent Contract that issues one-use, policy-bound receipts for individual agent actions. The policy owner chooses an agent, an executor, allowed capabilities, exact outbound domains, a maximum spend, and prohibited behavior. The agent submits a nonce-bound action with a commit-pinned GitHub action plan and its SHA-256 digest. Validators independently fetch the locked plan, verify the digest, and judge whether its steps fit the policy. The contract stores `ALLOW`, `REVIEW`, `BLOCK`, or `INSUFFICIENT_EVIDENCE`.

The executor can consume an `ALLOW` receipt once, only before expiry, while the issuing policy version is current and the policy is unpaused. An owner or agent can revoke a pending receipt. Policy changes invalidate unconsumed permits.

## Contract boundary

This contract authorizes a specific action plan; it does not execute or sandbox the action. An integrated executor must check and consume the exact `action_digest` before carrying out the same action. A malicious executor can lie about what it executes; use a trustworthy executor or an enforcement layer for real security.

## Contract

`contracts/AgentPermit.py` is the entire Intelligent Contract. It pins a concrete GenVM runner. There is no frontend dependency.

## Quickstart

Install Python 3.12 and then:

```powershell
python -m pip install -r requirements.txt
$env:PYTHONUTF8='1'
genvm-lint check contracts/AgentPermit.py
python -m pytest tests/direct -q
```

For the release flow and exact request format, see [docs/PROTOCOL.md](docs/PROTOCOL.md). Live deployment evidence, when available, is recorded in `deployments/studionet.json` with exact source and transaction hashes.

## Why GenLayer

Deterministic checks enforce the explicit limits. The part requiring validator consensus is whether the detailed, externally hosted action plan faithfully describes the requested action and conflicts with the owner's natural-language prohibitions. Validators refetch and hash the same evidence and independently reproduce the decision; the contract compares the decision, not the free-form explanation. A missing or tampered packet cannot produce an executable `ALLOW` receipt.
