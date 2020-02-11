# -*- coding: utf-8 -*-

import re

import yaml

from decision.workflow import Workflow


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
