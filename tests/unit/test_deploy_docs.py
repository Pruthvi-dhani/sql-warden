"""docs/deploy.md stays true to the code: its YAML and JSON parse, and the policies in it are
ones sql-warden accepts."""

import json
import re
from pathlib import Path

import pytest
import yaml

from sql_warden.auth import key_hash, new_api_key
from sql_warden.config import parse_config

GUIDE = (Path(__file__).parents[2] / "docs" / "deploy.md").read_text()
BLOCKS = re.findall(r"```(\w*)\n(.*?)```", GUIDE, flags=re.DOTALL)
SECRETS = {
    "WAREHOUSE_DSN": "postgresql://warden:pw@replica.internal/warehouse",
    "WAREHOUSE_PUBLIC_DSN": "postgresql://warden_public:pw@replica.internal/warehouse",
    "AUDIT_DSN": "postgresql://warden:pw@audit.internal/audit",
    "MASKING_KEY": "0123456789abcdef0123456789abcdef",
}


def _blocks(language: str) -> list[str]:
    return [text for lang, text in BLOCKS if lang == language]


def test_every_yaml_block_parses() -> None:
    documents = [doc for text in _blocks("yaml") for doc in yaml.safe_load_all(text)]
    kinds = [doc.get("kind") for doc in documents if isinstance(doc, dict)]
    assert kinds.count("Deployment") == 1
    assert {"ConfigMap", "Service", "NetworkPolicy", "CronJob"} <= set(kinds)


def test_every_json_block_parses() -> None:
    (task,) = [json.loads(text) for text in _blocks("json")]
    (container,) = task["containerDefinitions"]
    assert container["readonlyRootFilesystem"] is True


def _policies() -> list[str]:
    """The policy files in the guide: the one on its own, and the ConfigMap's."""
    found = [text for text in _blocks("yaml") if text.startswith("version: 1")]
    for text in _blocks("yaml"):
        for doc in yaml.safe_load_all(text):
            if isinstance(doc, dict) and doc.get("kind") == "ConfigMap":
                found.append(doc["data"]["warden.yaml"])
    return found


@pytest.mark.parametrize("policy", _policies(), ids=["secrets", "configmap"])
def test_the_policies_are_valid(policy: str, monkeypatch: pytest.MonkeyPatch) -> None:
    for name, value in SECRETS.items():
        monkeypatch.setenv(name, value)
    policy = policy.replace('"<from sql-warden auth new-key>"', key_hash(new_api_key()))
    config = parse_config(policy, source="docs/deploy.md")
    assert config.audit.append_only
    assert config.auth is not None


def test_the_shutdown_grace_fits_inside_the_pod_s() -> None:
    deployment = next(
        doc
        for text in _blocks("yaml")
        for doc in yaml.safe_load_all(text)
        if isinstance(doc, dict) and doc.get("kind") == "Deployment"
    )
    grace = deployment["spec"]["template"]["spec"]["terminationGracePeriodSeconds"]
    assert grace > 30  # server.shutdown_grace_s's default
