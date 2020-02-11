# -*- coding: utf-8 -*-

import re

import pytest
import yaml

from decision.workflow import Workflow

YAML_CONF = """---
fuzzing_config:
  path: /path/to/secret_conf
"""


def test_patterns(tmpdir):

    # Write community fuzzing config
    conf = tmpdir.mkdir("config").mkdir("projects").join("fuzzing.yml")
    conf.write(yaml.dump({"fuzzing": {"workerPools": {"pool-A": {}, "ci": {}}}}))

    # Build resources patterns using that configuration
    workflow = Workflow()
    workflow.community_config_dir = str(tmpdir)
    patterns = workflow.build_resources_patterns()
    assert patterns == [
        "Hook=project-fuzzing/.*",
        "WorkerPool=proj-fuzzing/(?!(ci|pool-A)$)",
    ]

    def _match(test):
        return any([re.match(pattern, test) for pattern in patterns])

    # Check all fuzzing hooks are managed
    assert not _match("Hook=project-another/something")
    assert _match("Hook=project-fuzzing/XXX")
    assert _match("Hook=project-fuzzing/X-Y_Z")

    # Check our pools are managed, avoiding the community ones
    assert _match("WorkerPool=proj-fuzzing/AAAA")
    assert not _match("WorkerPool=proj-fuzzing/ci")
    assert not _match("WorkerPool=proj-fuzzing/pool-A")
    assert _match("WorkerPool=proj-fuzzing/pool-B")
    assert _match("WorkerPool=proj-fuzzing/ci-bis")


def test_configure_local(tmp_path):
    workflow = Workflow()

    # Fails on missing file
    with pytest.raises(AssertionError, match="Missing configuration in nope.yml"):
        workflow.configure(local_path="nope.yml")

    # Read a local conf
    conf = tmp_path / "conf.yml"
    conf.write_text(YAML_CONF)
    assert workflow.configure(local_path=conf) == {
        "community_config": {"url": "git@github.com:mozilla/community-tc-config.git"},
        "fuzzing_config": {"path": "/path/to/secret_conf"},
    }

    # Check override for fuzzing repo & revision
    assert workflow.configure(
        local_path=conf,
        fuzzing_git_repository="git@server:repo.git",
        fuzzing_git_revision="deadbeef",
    ) == {
        "community_config": {"url": "git@github.com:mozilla/community-tc-config.git"},
        "fuzzing_config": {"revision": "deadbeef", "url": "git@server:repo.git"},
    }


def test_configure_secret(mock_taskcluster):
    workflow = Workflow()

    # Read a remote conf from Taskcluster secret
    assert workflow.configure(secret="mock-fuzzing-tc") == {
        "community_config": {"url": "git@github.com:projectA/repo.git"},
        "fuzzing_config": {"url": "git@github.com:projectB/repo.git"},
        "private_key": "ssh super secret",
    }

    # Check override for fuzzing repo & revision
    assert workflow.configure(
        secret="mock-fuzzing-tc",
        fuzzing_git_repository="git@server:repo.git",
        fuzzing_git_revision="deadbeef",
    ) == {
        "community_config": {"url": "git@github.com:projectA/repo.git"},
        "fuzzing_config": {"revision": "deadbeef", "url": "git@server:repo.git"},
        "private_key": "ssh super secret",
    }
