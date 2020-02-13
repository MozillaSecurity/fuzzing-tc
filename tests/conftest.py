# -*- coding: utf-8 -*-
import json
import os
from unittest.mock import Mock

import pytest
import responses

from decision.pool import MachineTypes
from decision.providers import AWS
from decision.providers import GCP
from decision.workflow import Workflow

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


@pytest.fixture
def mock_taskcluster():
    """Mock Taskcluster HTTP services"""

    # Setup mock url for taskcluster services
    os.environ["TASKCLUSTER_ROOT_URL"] = "http://taskcluster.test"

    # Add a basic configuration for the workflow in a secret
    secret = {
        "community_config": {"url": "git@github.com:projectA/repo.git"},
        "fuzzing_config": {"url": "git@github.com:projectB/repo.git"},
        "private_key": "ssh super secret",
    }
    responses.add(
        responses.GET,
        "http://taskcluster.test/api/secrets/v1/secret/mock-fuzzing-tc",
        body=json.dumps({"secret": secret}),
        content_type="application/json",
    )


@pytest.fixture
def mock_clouds():
    """Mock Cloud providers setup"""
    community = os.path.join(FIXTURES_DIR, "community")
    return {"aws": AWS(community), "gcp": GCP(community)}


@pytest.fixture
def mock_machines():
    """Mock a static list of machines"""
    path = os.path.join(FIXTURES_DIR, "machines.yml")
    assert os.path.exists(path)
    return MachineTypes.from_file(path)


@pytest.fixture(autouse=True)
def disable_cleanup():
    """Disable workflow cleanup in unit tests as tmpdir is automatically removed"""
    Workflow.cleanup = Mock()
