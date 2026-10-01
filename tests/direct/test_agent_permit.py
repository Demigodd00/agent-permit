from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json


CONTRACT = Path(__file__).resolve().parents[2] / "contracts" / "AgentPermit.py"
SDK = "v0.2.16"
URL = (
    "https://raw.githubusercontent.com/example/agent-plan/"
    + "a" * 40
    + "/plans/read-report.json"
)
ACTION = "Read the local quarterly report and extract its section headings."
TARGET = "/reports/quarterly.txt"
EXPIRY = int(datetime(2026, 9, 30, 1, tzinfo=timezone.utc).timestamp())


def address(account):
    return "0x" + account.hex()


def packet(*, steps=None, domains=None):
    return {
        "purpose": "Create a section index for the report.",
        "capability": "READ_FILES",
        "target": TARGET,
        "amount_atto": 0,
        "steps": steps or ["Open /reports/quarterly.txt and read its section headings."],
        "outbound_domains": domains or [],
    }


def evidence(vm, plan=None, response=None, url=URL):
    body = json.dumps(plan or packet(), sort_keys=True, separators=(",", ":"))
    vm.mock_web(url, {"status": 200, "body": body})
    vm.mock_llm(
        "Assess this agent action",
        json.dumps(response or {"decision": "ALLOW", "reason": "The plan stays within read access."}),
    )
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def deploy(vm, direct_deploy, owner, agent, executor):
    vm.warp("2026-09-30T00:00:00Z")
    vm.sender = owner
    contract = direct_deploy(str(CONTRACT), address(agent), address(executor), sdk_version=SDK)
    contract.set_policy(
        "READ_FILES,NETWORK,SPEND",
        "api.example.com",
        100,
        "Never upload private files, run shell commands, or request credentials.",
    )
    return contract


def request(contract, vm, agent, digest, *, nonce=1, capability="READ_FILES", target=TARGET, amount=0):
    vm.sender = agent
    return contract.request_permit(nonce, capability, target, amount, ACTION, URL, digest, EXPIRY)


def test_allow_receipt_is_bound_and_consumed_once(
    direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie
):
    contract = deploy(direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie)
    digest = evidence(direct_vm)
    receipt_id = request(contract, direct_vm, direct_bob, digest)
    receipt = contract.get_receipt(receipt_id)
    assert receipt["decision"] == "ALLOW"
    assert receipt["evidence_verified"] is True
    assert receipt["nonce"] == 1
    assert receipt["policy_version"] == 1
    assert receipt["action"] == ACTION
    assert contract.get_policy_version(1)["allowed_capabilities"] == "NETWORK,READ_FILES,SPEND"
    assert receipt["action_digest"] == receipt_id
    assert contract.get_policy()["next_nonce"] == "2"
    leader = direct_vm._captured_validators[-1][0]
    assert direct_vm.run_validator(leader_result=leader) is True

    direct_vm.sender = direct_alice
    with direct_vm.expect_revert("executor_required"):
        contract.consume_permit(receipt_id, receipt_id)
    direct_vm.sender = direct_charlie
    with direct_vm.expect_revert("action_digest_mismatch"):
        contract.consume_permit(receipt_id, "0" * 64)
    contract.consume_permit(receipt_id, receipt_id)
    assert contract.get_receipt(receipt_id)["consumed"] is True
    with direct_vm.expect_revert("receipt_unavailable"):
        contract.consume_permit(receipt_id, receipt_id)


def test_missing_or_tampered_evidence_fails_closed(
    direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie
):
    contract = deploy(direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie)
    evidence(direct_vm)
    receipt_id = request(contract, direct_vm, direct_bob, "f" * 64)
    assert contract.get_receipt(receipt_id)["decision"] == "INSUFFICIENT_EVIDENCE"
    assert contract.get_receipt(receipt_id)["evidence_verified"] is False
    direct_vm.sender = direct_charlie
    with direct_vm.expect_revert("allow_receipt_required"):
        contract.consume_permit(receipt_id, receipt_id)
    direct_vm.clear_mocks()
    direct_vm.mock_web(URL, {"status": 404, "body": "missing"})
    receipt_id = request(contract, direct_vm, direct_bob, "f" * 64, nonce=2)
    assert contract.get_receipt(receipt_id)["reason"] == "evidence_http_status"


def test_static_policy_blocks_excess_amount_and_unlisted_domain(
    direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie
):
    contract = deploy(direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie)
    receipt_id = request(contract, direct_vm, direct_bob, "a" * 64, capability="SPEND", amount=101)
    assert contract.get_receipt(receipt_id)["reason"] == "amount_exceeds_policy"
    receipt_id = request(
        contract, direct_vm, direct_bob, "a" * 64, nonce=2, capability="NETWORK", target="evil.example.com"
    )
    assert contract.get_receipt(receipt_id)["reason"] == "domain_not_allowed"


def test_declared_extra_network_use_is_blocked(
    direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie
):
    contract = deploy(direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie)
    digest = evidence(direct_vm, packet(domains=["api.example.com"]))
    receipt_id = request(contract, direct_vm, direct_bob, digest)
    assert contract.get_receipt(receipt_id)["decision"] == "BLOCK"
    assert contract.get_receipt(receipt_id)["reason"] == "network_requires_capability"


def test_policy_change_and_revocation_invalidate_unconsumed_permits(
    direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie
):
    contract = deploy(direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie)
    digest = evidence(direct_vm)
    first = request(contract, direct_vm, direct_bob, digest)
    direct_vm.sender = direct_alice
    contract.set_policy("READ_FILES", "", 0, "Do not read secret files.")
    assert contract.get_policy_version(1)["prohibited_behavior"].startswith("Never upload")
    assert contract.get_policy_version(2)["prohibited_behavior"] == "Do not read secret files."
    direct_vm.sender = direct_charlie
    with direct_vm.expect_revert("policy_version_changed"):
        contract.consume_permit(first, first)
    direct_vm.sender = direct_bob
    second = request(contract, direct_vm, direct_bob, digest, nonce=2)
    contract.revoke_receipt(second)
    direct_vm.sender = direct_charlie
    with direct_vm.expect_revert("receipt_unavailable"):
        contract.consume_permit(second, second)


def test_nonce_authorization_and_commit_pin(
    direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie
):
    contract = deploy(direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie)
    direct_vm.sender = direct_alice
    with direct_vm.expect_revert("agent_required"):
        contract.request_permit(1, "READ_FILES", TARGET, 0, ACTION, URL, "a" * 64, EXPIRY)
    direct_vm.sender = direct_bob
    with direct_vm.expect_revert("nonce_mismatch"):
        contract.request_permit(2, "READ_FILES", TARGET, 0, ACTION, URL, "a" * 64, EXPIRY)
    with direct_vm.expect_revert("commit_pinned_github_evidence_required"):
        contract.request_permit(
            1, "READ_FILES", TARGET, 0, ACTION,
            "https://raw.githubusercontent.com/example/agent-plan/main/plan.json", "a" * 64, EXPIRY
        )


def test_subjective_block_and_malformed_llm(
    direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie
):
    contract = deploy(direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie)
    digest = evidence(direct_vm, response={"decision": "BLOCK", "reason": "Plan requests secret files."})
    first = request(contract, direct_vm, direct_bob, digest)
    assert contract.get_receipt(first)["decision"] == "BLOCK"
    direct_vm.clear_mocks()
    digest = evidence(direct_vm, response={"decision": "ALLOW"})
    with direct_vm.expect_revert("invalid_response_shape"):
        request(contract, direct_vm, direct_bob, digest, nonce=2)
    assert contract.get_policy()["next_nonce"] == "2"


def test_validator_rejects_different_material_decision(
    direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie
):
    contract = deploy(direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie)
    digest = evidence(direct_vm)
    request(contract, direct_vm, direct_bob, digest)
    leader = direct_vm._captured_validators[-1][0]
    direct_vm.clear_mocks()
    evidence(direct_vm, response={"decision": "BLOCK", "reason": "A prohibited step was detected."})
    assert direct_vm.run_validator(leader_result=leader) is False


def test_pause_and_expiry_prevent_consumption(
    direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie
):
    contract = deploy(direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie)
    digest = evidence(direct_vm)
    receipt_id = request(contract, direct_vm, direct_bob, digest)
    direct_vm.sender = direct_alice
    contract.set_paused(True)
    direct_vm.sender = direct_charlie
    with direct_vm.expect_revert("policy_paused"):
        contract.consume_permit(receipt_id, receipt_id)
    direct_vm.sender = direct_alice
    contract.set_paused(False)
    # Direct VM clock behavior differs by host; force the stored deadline into
    # the past to exercise the contract's expiry branch consistently.
    expired = contract.get_receipt(receipt_id)
    expired["expires_at_unix"] = 0
    contract.receipts[receipt_id] = json.dumps(expired)
    direct_vm.sender = direct_charlie
    with direct_vm.expect_revert("receipt_expired"):
        contract.consume_permit(receipt_id, receipt_id)


def test_only_owner_can_change_rules_or_executor(
    direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie
):
    contract = deploy(direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie)
    direct_vm.sender = direct_bob
    with direct_vm.expect_revert("owner_required"):
        contract.set_policy("READ_FILES", "", 0, "Do not read secrets.")
    with direct_vm.expect_revert("owner_required"):
        contract.set_executor(address(direct_bob))
    direct_vm.sender = direct_alice
    with direct_vm.expect_revert("network_domains_required"):
        contract.set_policy("NETWORK", "", 0, "No private endpoints.")
    assert contract.get_policy()["policy_version"] == "1"
