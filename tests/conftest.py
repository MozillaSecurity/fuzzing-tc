# -*- coding: utf-8 -*-
import json
import os

import pytest
import responses


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
