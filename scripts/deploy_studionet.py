"""Deploy and exercise AgentPermit with disposable StudioNet-only signers."""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from eth_account import Account
from eth_utils import to_checksum_address
from genlayer_py import create_client
from genlayer_py.assertions import tx_execution_succeeded
from genlayer_py.chains import studionet
from genlayer_py.types import TransactionHashVariant, TransactionStatus


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "contracts" / "AgentPermit.py"
RECORD = ROOT / "deployments" / "studionet.json"
EVIDENCE_PATH = "evidence/read_report.json"
ACTION = "Read the local quarterly report and extract its section headings."
TARGET = "/reports/quarterly.txt"


def run_git(*args: str) -> bytes:
    return subprocess.run(
        ["git", *args], cwd=ROOT, check=True, capture_output=True
    ).stdout


def tx_hex(value: object) -> str:
    rendered = str(value)
    return rendered if rendered.startswith("0x") else "0x" + bytes(value).hex()


def wait(client, transaction, *, allow_disagreement: bool = False) -> dict:
    receipt = client.wait_for_transaction_receipt(
        transaction_hash=tx_hex(transaction),
        status=TransactionStatus.FINALIZED,
        interval=5_000,
        retries=120,
        full_transaction=True,
    )
    if (receipt.get("status_name") or receipt.get("statusName")) != TransactionStatus.FINALIZED.value:
        raise RuntimeError("transaction did not finalize: " + tx_hex(transaction))
    if not tx_execution_succeeded(receipt):
        raise RuntimeError("execution failed: " + json.dumps(receipt, default=str))
    result = receipt.get("result_name") or receipt.get("resultName")
    if result not in (None, "AGREE", "MAJORITY_AGREE") and not allow_disagreement:
        raise RuntimeError("consensus failed: " + json.dumps(receipt, default=str))
    return receipt


def write(client, address: str, method: str, args: list) -> tuple[str, dict]:
    tx = client.write_contract(address=address, function_name=method, args=args)
    print(json.dumps({"step": method, "transaction": tx_hex(tx)}), flush=True)
    return tx_hex(tx), wait(client, tx)


def write_with_retry(client, address: str, method: str, args: list) -> tuple[str, dict, list[str]]:
    attempts: list[str] = []
    for index in range(3):
        tx = client.write_contract(address=address, function_name=method, args=args)
        attempts.append(tx_hex(tx))
        print(json.dumps({"step": method, "attempt": index + 1, "transaction": tx_hex(tx)}), flush=True)
        receipt = wait(client, tx, allow_disagreement=True)
        if (receipt.get("result_name") or receipt.get("resultName")) in (None, "AGREE", "MAJORITY_AGREE"):
            return tx_hex(tx), receipt, attempts
    raise RuntimeError(method + " did not reach consensus: " + json.dumps(attempts))


def read(client, address: str, method: str, args: list):
    return client.read_contract(
        address=address,
        function_name=method,
        args=args,
        transaction_hash_variant=TransactionHashVariant.LATEST_FINAL,
    )


def extract_address(receipt: dict) -> str:
    for key in ("tx_data_decoded", "data"):
        item = receipt.get(key)
        if isinstance(item, dict) and item.get("contract_address"):
            return to_checksum_address(str(item["contract_address"]))
    raise RuntimeError("deployment receipt omitted contract address")


def source_hash(source: str) -> str:
    return hashlib.sha256(source.replace("\r\n", "\n").encode("utf-8")).hexdigest()


def verify_deployed_source(client, address: str, expected: str) -> str:
    encoded = client.provider.make_request("gen_getContractCode", [address]).get("result")
    if not isinstance(encoded, str):
        raise RuntimeError("deployed contract code unavailable")
    actual = base64.b64decode(encoded, validate=True).decode("utf-8")
    if source_hash(actual) != source_hash(expected):
        raise RuntimeError("deployed source differs from public commit")
    return source_hash(expected)


def main() -> None:
    if run_git("status", "--porcelain"):
        raise RuntimeError("commit and push the exact source before deploying")
    commit = run_git("rev-parse", "HEAD").decode("ascii").strip()
    source = SOURCE.read_text(encoding="utf-8")
    tracked_source = run_git("show", "HEAD:contracts/AgentPermit.py").decode("utf-8")
    if source.replace("\r\n", "\n") != tracked_source.replace("\r\n", "\n"):
        raise RuntimeError("local source differs from committed source")
    evidence = run_git("show", "HEAD:" + EVIDENCE_PATH)
    url = (
        "https://raw.githubusercontent.com/Demigodd00/agent-permit/"
        + commit + "/" + EVIDENCE_PATH
    )
    with urllib.request.urlopen(url, timeout=20) as response:
        remote = response.read()
    if remote != evidence:
        raise RuntimeError("public evidence bytes differ from pinned Git blob")
    evidence_digest = hashlib.sha256(evidence).hexdigest()

    owner = Account.create()
    agent = Account.create()
    executor = Account.create()
    owner_client = create_client(chain=studionet, account=owner)
    agent_client = create_client(chain=studionet, account=agent)
    executor_client = create_client(chain=studionet, account=executor)

    deployment = owner_client.deploy_contract(
        code=source, account=owner, args=[agent.address, executor.address]
    )
    print(json.dumps({"step": "deploy", "transaction": tx_hex(deployment)}), flush=True)
    address = extract_address(wait(owner_client, deployment))
    print(json.dumps({"step": "deployed", "address": address}), flush=True)

    policy_args = [
        "READ_FILES",
        "",
        0,
        "Do not read secret files, write files, use the network, spend funds, run shell commands, or request credentials.",
    ]
    policy_tx, _ = write(owner_client, address, "set_policy", policy_args)
    policy = read(owner_client, address, "get_policy", [])
    if not isinstance(policy, dict) or policy.get("policy_version") != "1":
        raise RuntimeError("policy not visible after finalization")
    expiry = int(time.time()) + 3_600
    payload = {
        "agent": agent.address.lower(),
        "policy_version": 1,
        "nonce": 1,
        "capability": "READ_FILES",
        "target": TARGET,
        "amount_atto": 0,
        "action": ACTION,
        "evidence_url": url,
        "evidence_sha256": evidence_digest,
        "expires_at_unix": expiry,
    }
    receipt_id = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    request_args = [1, "READ_FILES", TARGET, 0, ACTION, url, evidence_digest, expiry]
    request_tx, _, request_attempts = write_with_retry(
        agent_client, address, "request_permit", request_args
    )
    receipt = read(owner_client, address, "get_receipt", [receipt_id])
    if not isinstance(receipt, dict) or receipt.get("decision") != "ALLOW" or not receipt.get("evidence_verified"):
        raise RuntimeError("live request did not produce a verified ALLOW receipt: " + json.dumps(receipt))
    consume_tx, _ = write(executor_client, address, "consume_permit", [receipt_id, receipt_id])
    consumed = read(owner_client, address, "get_receipt", [receipt_id])
    if not isinstance(consumed, dict) or not consumed.get("consumed"):
        raise RuntimeError("permit did not become consumed")
    policy_snapshot = read(owner_client, address, "get_policy_version", [1])
    if not isinstance(policy_snapshot, dict) or policy_snapshot.get("allowed_capabilities") != "READ_FILES":
        raise RuntimeError("policy snapshot missing")
    record = {
        "network": "studionet",
        "chain_id": 61999,
        "status": "VERIFIED",
        "source_commit": commit,
        "source_sha256": verify_deployed_source(owner_client, address, source),
        "contract_address": address,
        "explorer": "https://explorer-studio.genlayer.com/address/" + address,
        "deploy_transaction": tx_hex(deployment),
        "deployed_at": datetime.now(timezone.utc).isoformat(),
        "wallet_policy": "disposable StudioNet-only signers; private keys not retained",
        "owner": owner.address,
        "agent": agent.address,
        "executor": executor.address,
        "policy_transaction": policy_tx,
        "evidence_url": url,
        "evidence_sha256": evidence_digest,
        "smoke_test": {
            "request_transaction": request_tx,
            "request_attempts": request_attempts,
            "consume_transaction": consume_tx,
            "receipt_id": receipt_id,
            "decision": consumed["decision"],
            "evidence_verified": consumed["evidence_verified"],
            "consumed": consumed["consumed"],
            "policy_snapshot_verified": True,
        },
    }
    RECORD.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"contract": address, "receipt": receipt_id, "record": str(RECORD)}), flush=True)


if __name__ == "__main__":
    main()
