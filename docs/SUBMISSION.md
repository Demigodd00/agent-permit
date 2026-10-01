# Submission package

**Title:** AgentPermit — One-Use AI Agent Action Authorization

**Description:** AgentPermit is a GenLayer Intelligent Contract that lets a policy owner define allowed agent capabilities, exact outbound domains, a spending ceiling, and prohibited behavior. An authorized agent requests a permit for a specific action, nonce, expiry, and SHA-256-bound action plan at an immutable GitHub commit. Validators independently fetch and hash the plan, then compare substantive policy decisions under a custom equivalence rule. Explicit capability, domain, and amount limits remain deterministic. The contract stores `ALLOW`, `REVIEW`, `BLOCK`, or `INSUFFICIENT_EVIDENCE` receipts; only a current, unrevoked `ALLOW` receipt can be consumed once by the designated executor. Policy changes invalidate outstanding permits. AgentPermit is an authorization aid; it does not execute or sandbox the agent action.

**Evidence to provide:** public repository, tracked `contracts/AgentPermit.py`, source-pinned deployment record, StudioNet explorer contract page, passing test run, and the sample commit-pinned action plan. Replace any pending deployment fields only after a verified live run.
