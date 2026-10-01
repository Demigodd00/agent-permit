# Submission package

**Title:** AgentPermit — One-Use AI Agent Action Authorization

**Description:** AgentPermit is a GenLayer Intelligent Contract that lets a policy owner define allowed agent capabilities, exact outbound domains, a spending ceiling, and prohibited behavior. An authorized agent requests a permit for a specific action, nonce, expiry, and SHA-256-bound action plan at an immutable GitHub commit. Validators independently fetch and hash the plan, then compare substantive policy decisions under a custom equivalence rule. Explicit capability, domain, and amount limits remain deterministic. The contract stores `ALLOW`, `REVIEW`, `BLOCK`, or `INSUFFICIENT_EVIDENCE` receipts; only a current, unrevoked `ALLOW` receipt can be consumed once by the designated executor. Policy changes invalidate outstanding permits. AgentPermit is an authorization aid; it does not execute or sandbox the agent action.

**Evidence to provide:** [public repository](https://github.com/Demigodd00/agent-permit), [tracked contract source at the deployed commit](https://github.com/Demigodd00/agent-permit/blob/912a065907e38a92691ab9e4e5b78b7ad8b863e0/contracts/AgentPermit.py), [verified deployment record](../deployments/studionet.json), [StudioNet explorer contract page](https://explorer-studio.genlayer.com/address/0xeb3DCEA98B5A426098682A60Ba7fB0A52ba82F9e), a passing GitHub Actions run, and the [commit-pinned action plan](https://github.com/Demigodd00/agent-permit/blob/912a065907e38a92691ab9e4e5b78b7ad8b863e0/evidence/read_report.json).

The StudioNet deployment is a completed demonstration with disposable signers. Its ALLOW receipt was consumed once. Redeploy with retained wallets to operate a lasting policy.
