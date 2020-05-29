# -*- coding: utf-8 -*-

import copy
from datetime import datetime

import pytest
import slugid
import yaml
from freezegun import freeze_time

from fuzzing_tc.common.pool import PoolConfiguration as CommonPoolConfiguration
from fuzzing_tc.decision.pool import DOCKER_WORKER_DEVICES
from fuzzing_tc.decision.pool import PoolConfiguration


@pytest.mark.parametrize(
    "size, divisor, result",
    [
        ("2g", "1g", 2),
        ("2g", "1m", 2048),
        ("2g", 1, 2048 * 1024 * 1024),
        ("128t", "1g", 128 * 1024),
    ],
)
def test_parse_size(size, divisor, result):
    if isinstance(divisor, str):
        divisor = PoolConfiguration.parse_size(divisor)

    assert PoolConfiguration.parse_size(size, divisor) == result


@pytest.mark.parametrize(
    "provider, cpu, cores, ram, metal, result",
    [
        ("gcp", "x64", 1, 1, False, ["base", "metal"]),
        ("gcp", "x64", 2, 1, False, ["2-cpus", "more-ram"]),
        ("gcp", "x64", 2, 5, False, ["more-ram"]),
        ("gcp", "x64", 1, 1, True, ["metal"]),
        ("aws", "arm64", 1, 1, False, ["a1"]),
        ("aws", "arm64", 2, 1, False, ["a2"]),
        ("aws", "arm64", 12, 32, False, []),
        ("aws", "arm64", 1, 1, True, []),
        # x64 is not present in aws
        ("aws", "x64", 1, 1, False, KeyError),
        # invalid provider raises too
        ("dummy", "x64", 1, 1, False, KeyError),
    ],
)
def test_machine_filters(mock_machines, provider, cpu, ram, cores, metal, result):

    if isinstance(result, list):
        assert list(mock_machines.filter(provider, cpu, cores, ram, metal)) == result
    else:
        with pytest.raises(result):
            list(mock_machines.filter(provider, cpu, cores, ram, metal))


# Hook & role should be the same across cloud providers
VALID_HOOK = {
    "kind": "Hook",
    "bindings": [],
    "emailOnError": True,
    "hookGroupId": "project-fuzzing",
    "hookId": "linux-test",
    "name": "linux-test",
    "owner": "fuzzing+taskcluster@mozilla.com",
    "schedule": ["0 0 12 * * *", "0 0 0 * * *"],
    "task": {
        "created": {"$fromNow": "0 seconds"},
        "deadline": {"$fromNow": "1 hour"},
        "expires": {"$fromNow": "1 week"},
        "extra": {},
        "metadata": {
            "description": "*DO NOT EDIT* - This resource is "
            "configured automatically.\n"
            "\n"
            "Fuzzing workers generated by decision "
            "task",
            "name": "Fuzzing decision linux-test",
            "owner": "fuzzing+taskcluster@mozilla.com",
            "source": "https://github.com/MozillaSecurity/fuzzing-tc",
        },
        "payload": {
            "artifacts": {},
            "cache": {},
            "capabilities": {},
            "env": {"TASKCLUSTER_SECRET": "project/fuzzing/decision"},
            "features": {"taskclusterProxy": True},
            "image": {
                "namespace": "project.fuzzing.config.master",
                "path": "public/fuzzing-tc-decision.tar",
                "type": "indexed-image",
            },
            "command": ["fuzzing-decision", "test"],
            "maxRunTime": 3600,
        },
        "priority": "high",
        "provisionerId": "proj-fuzzing",
        "retries": 1,
        "routes": [],
        "schedulerId": "-",
        "scopes": [
            "queue:scheduler-id:-",
            "queue:create-task:highest:proj-fuzzing/linux-test",
            "secrets:get:project/fuzzing/decision",
        ],
        "tags": {},
        "workerType": "linux-test",
    },
    "triggerSchema": {},
    "description": "*DO NOT EDIT* - This resource is configured automatically.\n"
    "\n"
    "Generated Fuzzing hook",
}

VALID_ROLE = {
    "kind": "Role",
    "roleId": "hook-id:project-fuzzing/linux-test",
    "scopes": [
        "queue:create-task:highest:proj-fuzzing/linux-test",
        "queue:scheduler-id:-",
        "secrets:get:project/fuzzing/decision",
    ],
    "description": "*DO NOT EDIT* - This resource is configured automatically.\n"
    "\n"
    "Fuzzing workers generated by decision task",
}


@pytest.mark.parametrize("env", [(None), ({"someKey": "someValue"})])
def test_aws_resources(env, mock_clouds, mock_machines):

    conf = PoolConfiguration(
        "test",
        {
            "cloud": "aws",
            "scopes": [],
            "disk_size": "120g",
            "cycle_time": "12h",
            "cores_per_task": 2,
            "metal": False,
            "name": "Amazing fuzzing pool",
            "tasks": 3,
            "command": ["run-fuzzing.sh"],
            "container": "MozillaSecurity/fuzzer:latest",
            "minimum_memory_per_core": "1g",
            "imageset": "generic-worker-A",
            "parents": [],
            "cpu": "arm64",
            "platform": "linux",
            "macros": {},
        },
    )
    with freeze_time("1970-01-01 00:00:00", tz_offset=0):
        resources = conf.build_resources(mock_clouds, mock_machines, env=env)
    assert len(resources) == 3
    pool, hook, role = resources

    assert pool.to_json() == {
        "kind": "WorkerPool",
        "config": {
            "launchConfigs": [
                {
                    "capacityPerInstance": 1,
                    "launchConfig": {
                        "ImageId": "ami-1234",
                        "InstanceMarketOptions": {"MarketType": "spot"},
                        "InstanceType": "a2",
                        "Placement": {"AvailabilityZone": "us-west-1a"},
                        "SecurityGroupIds": ["sg-A"],
                        "SubnetId": "subnet-XXX",
                    },
                    "region": "us-west-1",
                    "workerConfig": {
                        "dockerConfig": {
                            "linkInfo": {
                                "binds": [{"source": "/dev/shm", "target": "/dev/shm"}]
                            },
                        },
                        "genericWorker": {
                            "config": {
                                "anyKey": "anyValue",
                                "deploymentId": "a17c0937986b2812",
                                "os": "linux",
                                "wstAudience": "communitytc",
                                "wstServerURL": "https://community-websocktunnel.services.mozilla.com",
                            }
                        },
                    },
                }
            ],
            "maxCapacity": 3,
            "minCapacity": 0,
            "lifecycle": {"registrationTimeout": 900},
        },
        "emailOnError": True,
        "owner": "fuzzing+taskcluster@mozilla.com",
        "providerId": "community-tc-workers-aws",
        "workerPoolId": "proj-fuzzing/linux-test",
        "description": "*DO NOT EDIT* - This resource is configured automatically.\n"
        "\n"
        "Fuzzing workers generated by decision task",
    }

    # Update env in valid hook
    valid_hook = copy.deepcopy(VALID_HOOK)
    if env is not None:
        valid_hook["task"]["payload"]["env"].update(env)
    assert hook.to_json() == valid_hook
    assert role.to_json() == VALID_ROLE


@pytest.mark.parametrize("env", [(None), ({"someKey": "someValue"})])
def test_gcp_resources(env, mock_clouds, mock_machines):

    conf = PoolConfiguration(
        "test",
        {
            "cloud": "gcp",
            "scopes": [],
            "disk_size": "120g",
            "cycle_time": "12h",
            "cores_per_task": 2,
            "metal": False,
            "name": "Amazing fuzzing pool",
            "tasks": 3,
            "command": ["run-fuzzing.sh"],
            "container": "MozillaSecurity/fuzzer:latest",
            "minimum_memory_per_core": "1g",
            "imageset": "docker-worker",
            "parents": [],
            "cpu": "x64",
            "platform": "linux",
            "macros": {},
        },
    )
    with freeze_time("1970-01-01 00:00:00", tz_offset=0):
        resources = conf.build_resources(mock_clouds, mock_machines, env=env)
    assert len(resources) == 3
    pool, hook, role = resources

    assert pool.to_json() == {
        "kind": "WorkerPool",
        "config": {
            "launchConfigs": [
                {
                    "capacityPerInstance": 1,
                    "disks": [
                        {
                            "autoDelete": True,
                            "boot": True,
                            "initializeParams": {
                                "diskSizeGb": 120,
                                "sourceImage": "path/to/image",
                            },
                            "type": "PERSISTENT",
                        }
                    ],
                    "machineType": "zones/us-west1-a/machineTypes/2-cpus",
                    "networkInterfaces": [
                        {"accessConfigs": [{"type": "ONE_TO_ONE_NAT"}]}
                    ],
                    "region": "us-west1",
                    "scheduling": {"onHostMaintenance": "terminate"},
                    "workerConfig": {
                        "dockerConfig": {
                            "linkInfo": {
                                "binds": [{"source": "/dev/shm", "target": "/dev/shm"}]
                            }
                        },
                        "shutdown": {"afterIdleSeconds": 900, "enabled": True},
                    },
                    "zone": "us-west1-a",
                },
                {
                    "capacityPerInstance": 1,
                    "disks": [
                        {
                            "autoDelete": True,
                            "boot": True,
                            "initializeParams": {
                                "diskSizeGb": 120,
                                "sourceImage": "path/to/image",
                            },
                            "type": "PERSISTENT",
                        }
                    ],
                    "machineType": "zones/us-west1-b/machineTypes/2-cpus",
                    "networkInterfaces": [
                        {"accessConfigs": [{"type": "ONE_TO_ONE_NAT"}]}
                    ],
                    "region": "us-west1",
                    "scheduling": {"onHostMaintenance": "terminate"},
                    "workerConfig": {
                        "dockerConfig": {
                            "linkInfo": {
                                "binds": [{"source": "/dev/shm", "target": "/dev/shm"}]
                            }
                        },
                        "shutdown": {"afterIdleSeconds": 900, "enabled": True},
                    },
                    "zone": "us-west1-b",
                },
                {
                    "capacityPerInstance": 1,
                    "disks": [
                        {
                            "autoDelete": True,
                            "boot": True,
                            "initializeParams": {
                                "diskSizeGb": 120,
                                "sourceImage": "path/to/image",
                            },
                            "type": "PERSISTENT",
                        }
                    ],
                    "machineType": "zones/us-west1-a/machineTypes/more-ram",
                    "networkInterfaces": [
                        {"accessConfigs": [{"type": "ONE_TO_ONE_NAT"}]}
                    ],
                    "region": "us-west1",
                    "scheduling": {"onHostMaintenance": "terminate"},
                    "workerConfig": {
                        "dockerConfig": {
                            "linkInfo": {
                                "binds": [{"source": "/dev/shm", "target": "/dev/shm"}]
                            }
                        },
                        "shutdown": {"afterIdleSeconds": 900, "enabled": True},
                    },
                    "zone": "us-west1-a",
                },
            ],
            "maxCapacity": 3,
            "minCapacity": 0,
            "lifecycle": {"registrationTimeout": 900},
        },
        "emailOnError": True,
        "owner": "fuzzing+taskcluster@mozilla.com",
        "providerId": "community-tc-workers-google",
        "workerPoolId": "proj-fuzzing/linux-test",
        "description": "*DO NOT EDIT* - This resource is configured automatically.\n"
        "\n"
        "Fuzzing workers generated by decision task",
    }

    # Update env in valid hook
    valid_hook = copy.deepcopy(VALID_HOOK)
    if env is not None:
        valid_hook["task"]["payload"]["env"].update(env)
    assert hook.to_json() == valid_hook
    assert role.to_json() == VALID_ROLE


@pytest.mark.parametrize("env", [None, {"someKey": "someValue"}])
@pytest.mark.parametrize(
    "scope_caps",
    [
        ([], {}),
        (["docker-worker:capability:privileged"], {"privileged": True}),
        (
            ["docker-worker:capability:privileged"]
            + [
                f"docker-worker:capability:device:{dev}"
                for dev in DOCKER_WORKER_DEVICES
            ],
            {
                "privileged": True,
                "devices": {dev: True for dev in DOCKER_WORKER_DEVICES},
            },
        ),
    ],
)
def test_tasks(env, scope_caps):
    scopes, expected_capabilities = scope_caps
    conf = PoolConfiguration(
        "test",
        {
            "cloud": "gcp",
            "scopes": scopes,
            "disk_size": "10g",
            "cycle_time": "1h",
            "cores_per_task": 1,
            "metal": False,
            "name": "Amazing fuzzing pool",
            "tasks": 2,
            "command": ["run-fuzzing.sh"],
            "container": "MozillaSecurity/fuzzer:latest",
            "minimum_memory_per_core": "1g",
            "imageset": "anything",
            "parents": [],
            "cpu": "x64",
            "platform": "linux",
            "macros": {},
        },
    )

    task_ids, tasks = zip(*conf.build_tasks("someTaskId", env=env))

    # Check we have 2 valid generated task ids
    assert len(task_ids) == 2
    assert all(map(slugid.decode, task_ids))

    # Check we have 2 valid task definitions
    assert len(tasks) == 2

    def _check_date(task, *keys):
        # Dates can not be checked directly as they are generated
        assert keys, "must specify at least one key"
        value = task
        for key in keys:
            obj = value
            assert isinstance(obj, dict)
            value = obj[key]
        assert isinstance(value, str)
        date = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
        del obj[key]
        return date

    for i, task in enumerate(tasks):
        created = _check_date(task, "created")
        deadline = _check_date(task, "deadline")
        expires = _check_date(task, "expires")
        assert expires >= deadline > created
        expected_env = {
            "TASKCLUSTER_FUZZING_POOL": "test",
            "TASKCLUSTER_SECRET": "project/fuzzing/decision",
        }
        if env is not None:
            expected_env.update(env)

        log_expires = _check_date(
            task, "payload", "artifacts", "project/fuzzing/private/logs", "expires"
        )
        assert log_expires == expires
        assert set(task["scopes"]) == set(
            ["secrets:get:project/fuzzing/decision"] + scopes
        )
        # scopes are already asserted above
        # - read the value for comparison instead of deleting the key, so the object is
        #   printed in full on failure
        scopes = task["scopes"]
        assert task == {
            "dependencies": ["someTaskId"],
            "extra": {},
            "metadata": {
                "description": "*DO NOT EDIT* - This resource is configured "
                "automatically.\n"
                "\n"
                "Fuzzing workers generated by decision task",
                "name": f"Fuzzing task linux-test - {i+1}/2",
                "owner": "fuzzing+taskcluster@mozilla.com",
                "source": "https://github.com/MozillaSecurity/fuzzing-tc",
            },
            "payload": {
                "artifacts": {
                    "project/fuzzing/private/logs": {
                        "path": "/logs/",
                        "type": "directory",
                    }
                },
                "cache": {},
                "capabilities": expected_capabilities,
                "env": expected_env,
                "features": {"taskclusterProxy": True},
                "image": "MozillaSecurity/fuzzer:latest",
                "maxRunTime": 3600,
            },
            "priority": "high",
            "provisionerId": "proj-fuzzing",
            "retries": 1,
            "routes": [],
            "schedulerId": "-",
            "scopes": scopes,
            "tags": {},
            "taskGroupId": "someTaskId",
            "workerType": "linux-test",
        }


def test_flatten(tmp_path):
    pool_data1 = {
        "cloud": "aws",
        "scopes": ["scope1"],
        "disk_size": "120g",
        "cycle_time": "1h",
        "cores_per_task": 10,
        "metal": False,
        "name": "parent",
        "tasks": 3,
        "command": ["cmd1", "arg1"],
        "container": "MozillaSecurity/fuzzer:latest",
        "minimum_memory_per_core": "1g",
        "imageset": "generic-worker-A",
        "parents": [],
        "cpu": "arm64",
        "platform": "linux",
        "macros": {"ENVVAR1": "123456", "ENVVAR2": "789abc"},
    }
    pool_data2 = {
        "cloud": None,
        "scopes": ["scope2"],
        "disk_size": None,
        "cycle_time": "2h",
        "cores_per_task": None,
        "metal": None,
        "name": "child",
        "tasks": None,
        "command": ["cmd2", "arg2"],
        "container": None,
        "minimum_memory_per_core": None,
        "imageset": None,
        "parents": ["pool1"],
        "cpu": None,
        "platform": None,
        "macros": {"ENVVAR3": "defghi"},
    }
    (tmp_path / "pool1.yml").write_text(yaml.dump(pool_data1))
    (tmp_path / "pool2.yml").write_text(yaml.dump(pool_data2))

    pool = CommonPoolConfiguration.from_file(tmp_path / "pool2.yml")
    assert pool.cloud == "aws"
    assert set(pool.scopes) == {"scope1", "scope2"}
    assert pool.disk_size == 120
    assert pool.cycle_time == 7200
    assert pool.cores_per_task == 10
    assert pool.metal is False
    assert pool.name == "child"
    assert pool.tasks == 3
    assert pool.command == ["cmd2", "arg2"]
    assert pool.container == "MozillaSecurity/fuzzer:latest"
    assert pool.minimum_memory_per_core == 1.0
    assert pool.imageset == "generic-worker-A"
    assert pool.parents == ["pool1"]
    assert pool.cpu == "arm64"
    assert pool.platform == "linux"
    assert pool.macros == {
        "ENVVAR1": "123456",
        "ENVVAR2": "789abc",
        "ENVVAR3": "defghi",
    }


def test_cycle_crons():
    conf = CommonPoolConfiguration(
        "test",
        {
            "cloud": "gcp",
            "scopes": [],
            "disk_size": "10g",
            "cycle_time": "6h",
            "cores_per_task": 1,
            "metal": False,
            "name": "Amazing fuzzing pool",
            "tasks": 2,
            "command": ["run-fuzzing.sh"],
            "container": "MozillaSecurity/fuzzer:latest",
            "minimum_memory_per_core": "1g",
            "imageset": "anything",
            "parents": [],
            "cpu": "x64",
            "platform": "linux",
            "macros": {},
        },
    )

    # cycle time 6h
    assert list(conf.cycle_crons(0)) == [
        "0 0 6 * * *",
        "0 0 12 * * *",
        "0 0 18 * * *",
        "0 0 0 * * *",
    ]

    # cycle time 3.5 days
    conf.cycle_time = 3600 * 24 * 3.5
    assert list(conf.cycle_crons(0)) == [
        "0 0 12 * * 0",
        "0 0 0 * * 4",
    ]

    # cycle time 17h
    conf.cycle_time = 3600 * 17
    crons = list(conf.cycle_crons(0))
    assert len(crons) == (365 * 24 // 17) + 1
    assert crons[:4] == ["0 0 17 1 1 *", "0 0 10 2 1 *", "0 0 3 3 1 *", "0 0 20 3 1 *"]

    # cycle time 48h
    conf.cycle_time = 3600 * 48
    crons = list(conf.cycle_crons(0))
    assert len(crons) == (365 * 24 // 48) + 1
    assert crons[:4] == ["0 0 0 3 1 *", "0 0 0 5 1 *", "0 0 0 7 1 *", "0 0 0 9 1 *"]

    # cycle time 72h
    conf.cycle_time = 3600 * 72
    crons = list(conf.cycle_crons(0))
    assert len(crons) == (365 * 24 // 72) + 1
    assert crons[:4] == ["0 0 0 4 1 *", "0 0 0 7 1 *", "0 0 0 10 1 *", "0 0 0 13 1 *"]

    # cycle time 17d
    conf.cycle_time = 3600 * 24 * 17
    crons = list(conf.cycle_crons(0))
    assert len(crons) == (365 // 17) + 1
    assert crons[:4] == ["0 0 0 18 1 *", "0 0 0 4 2 *", "0 0 0 21 2 *", "0 0 0 10 3 *"]
