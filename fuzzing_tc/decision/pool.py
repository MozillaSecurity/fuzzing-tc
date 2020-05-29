# -*- coding: utf-8 -*-

# This Source Code Form is subject to the terms of the Mozilla Public License,
# v. 2.0. If a copy of the MPL was not distributed with this file, You can
# obtain one at http://mozilla.org/MPL/2.0/.

from datetime import datetime
from datetime import timedelta

from taskcluster.utils import fromNow
from taskcluster.utils import slugId
from taskcluster.utils import stringDate
from tcadmin.resources import Hook
from tcadmin.resources import Role
from tcadmin.resources import WorkerPool

from ..common.pool import PoolConfiguration as CommonPoolConfiguration
from . import DECISION_TASK_SECRET
from . import HOOK_PREFIX
from . import OWNER_EMAIL
from . import PROVIDER_IDS
from . import PROVISIONER_ID
from . import SCHEDULER_ID
from . import WORKER_POOL_PREFIX

DESCRIPTION = """*DO NOT EDIT* - This resource is configured automatically.

Fuzzing workers generated by decision task"""

DOCKER_WORKER_DEVICES = (
    "cpu",
    "loopbackAudio",
    "loopbackVideo",
    "kvm",
)


def add_capabilities_for_scopes(task):
    """Request capabilities to match the scopes specified by the task"""
    capabilities = task["payload"]["capabilities"]
    scopes = set(task["scopes"])
    capabilities.setdefault("devices", {})
    for device in DOCKER_WORKER_DEVICES:
        if f"docker-worker:capability:device:{device}" in scopes:
            capabilities["devices"][device] = True
    if "docker-worker:capability:privileged" in scopes:
        capabilities["privileged"] = True
    if not capabilities["devices"]:
        del capabilities["devices"]


class PoolConfiguration(CommonPoolConfiguration):
    """Fuzzing Pool Configuration

    Attributes:
        cloud (str): cloud provider, like aws or gcp
        command (list): list of strings, command to execute in the image/container
        container (str): name of the container
        cores_per_task (int): number of cores to be allocated per task
        cpu (int): cpu architecture (eg. x64/arm64)
        cycle_time (int): maximum run time of this pool in seconds
        disk_size (int): disk size in GB
        imageset (str): imageset name in community-tc-config/config/imagesets.yml
        macros (dict): dictionary of environment variables passed to the target
        metal (bool): whether or not the target requires to be run on bare metal
        minimum_memory_per_core (float): minimum RAM to be made available per core in GB
        name (str): descriptive name of the configuration
        parents (list): list of parents to inherit from
        platform (str): operating system of the target (linux, windows)
        pool_id (str): basename of the pool on disk (eg. "pool1" for pool1.yml)
        scopes (list): list of taskcluster scopes required by the target
        task_id (str): ID to use to refer to the task in Taskcluster
        tasks (int): number of tasks to run (each with `cores_per_task`)
    """

    @property
    def task_id(self):
        return f"{self.platform}-{self.pool_id}"

    def build_resources(self, providers, machine_types, env=None):
        """Build the full tc-admin resources to compare and build the pool"""

        # Select a cloud provider according to configuration
        assert self.cloud in providers, f"Cloud Provider {self.cloud} not available"
        provider = providers[self.cloud]

        # Build the pool configuration for selected machines
        machines = self.get_machine_list(machine_types)
        config = {
            "minCapacity": 0,
            "maxCapacity": self.tasks,
            "launchConfigs": provider.build_launch_configs(
                self.imageset, machines, self.disk_size
            ),
            "lifecycle": {
                # give workers 15 minutes to register before assuming they're broken
                "registrationTimeout": 900,
            },
        }

        # Mandatory scopes to execute the hook
        # or create new tasks
        decision_task_scopes = (
            f"queue:scheduler-id:{SCHEDULER_ID}",
            f"queue:create-task:highest:{PROVISIONER_ID}/{self.task_id}",
            f"secrets:get:{DECISION_TASK_SECRET}",
        )

        # Build the decision task payload that will trigger the new fuzzing tasks
        decision_task = {
            "created": {"$fromNow": "0 seconds"},
            "deadline": {"$fromNow": "1 hour"},
            "expires": {"$fromNow": "1 week"},
            "extra": {},
            "metadata": {
                "description": DESCRIPTION,
                "name": f"Fuzzing decision {self.task_id}",
                "owner": OWNER_EMAIL,
                "source": "https://github.com/MozillaSecurity/fuzzing-tc",
            },
            "payload": {
                "artifacts": {},
                "cache": {},
                "capabilities": {},
                "env": {"TASKCLUSTER_SECRET": DECISION_TASK_SECRET},
                "features": {"taskclusterProxy": True},
                "image": {
                    "type": "indexed-image",
                    "path": "public/fuzzing-tc-decision.tar",
                    "namespace": "project.fuzzing.config.master",
                },
                "command": ["fuzzing-decision", self.pool_id],
                "maxRunTime": 3600,
            },
            "priority": "high",
            "provisionerId": PROVISIONER_ID,
            "workerType": self.task_id,
            "retries": 1,
            "routes": [],
            "schedulerId": SCHEDULER_ID,
            "scopes": tuple(self.scopes) + decision_task_scopes,
            "tags": {},
        }
        add_capabilities_for_scopes(decision_task)
        if env is not None:
            assert set(decision_task["payload"]["env"].keys()).isdisjoint(
                set(env.keys())
            )
            decision_task["payload"]["env"].update(env)

        # add docker worker config for capability scopes
        scopes = set(self.scopes) | set(decision_task_scopes)
        docker_config = {
            "linkInfo": {"binds": [{"source": "/dev/shm", "target": "/dev/shm"}]}
        }
        if "docker-worker:capability:privileged" in scopes:
            docker_config["allowPrivileged"] = True
        if docker_config:
            for machine in config["launchConfigs"]:
                worker_config = machine.setdefault("workerConfig", {})
                machine_docker_config = worker_config.setdefault("dockerConfig", {})
                machine_docker_config.update(docker_config)

        pool = WorkerPool(
            workerPoolId=f"{WORKER_POOL_PREFIX}/{self.task_id}",
            providerId=PROVIDER_IDS[self.cloud],
            description=DESCRIPTION,
            owner=OWNER_EMAIL,
            emailOnError=True,
            config=config,
        )

        hook = Hook(
            hookGroupId=HOOK_PREFIX,
            hookId=self.task_id,
            name=self.task_id,
            description="Generated Fuzzing hook",
            owner=OWNER_EMAIL,
            emailOnError=True,
            schedule=list(self.cycle_crons()),
            task=decision_task,
            bindings=(),
            triggerSchema={},
        )

        role = Role(
            roleId=f"hook-id:{HOOK_PREFIX}/{self.task_id}",
            description=DESCRIPTION,
            scopes=tuple(self.scopes) + decision_task_scopes,
        )

        return [pool, hook, role]

    def build_tasks(self, parent_task_id, env=None):
        """Create fuzzing tasks and attach them to a decision task"""
        now = datetime.utcnow()
        for i in range(1, self.tasks + 1):
            task_id = slugId()
            task = {
                "taskGroupId": parent_task_id,
                "dependencies": [parent_task_id],
                "created": stringDate(now),
                "deadline": stringDate(now + timedelta(seconds=self.cycle_time)),
                "expires": stringDate(fromNow("1 week", now)),
                "extra": {},
                "metadata": {
                    "description": DESCRIPTION,
                    "name": f"Fuzzing task {self.task_id} - {i}/{self.tasks}",
                    "owner": OWNER_EMAIL,
                    "source": "https://github.com/MozillaSecurity/fuzzing-tc",
                },
                "payload": {
                    "artifacts": {
                        "project/fuzzing/private/logs": {
                            "expires": stringDate(fromNow("1 week", now)),
                            "path": "/logs/",
                            "type": "directory",
                        }
                    },
                    "cache": {},
                    "capabilities": {},
                    "env": {
                        "TASKCLUSTER_FUZZING_POOL": self.pool_id,
                        "TASKCLUSTER_SECRET": DECISION_TASK_SECRET,
                    },
                    "features": {"taskclusterProxy": True},
                    "image": self.container,
                    "maxRunTime": self.cycle_time,
                },
                "priority": "high",
                "provisionerId": PROVISIONER_ID,
                "workerType": self.task_id,
                "retries": 1,
                "routes": [],
                "schedulerId": SCHEDULER_ID,
                "scopes": self.scopes + [f"secrets:get:{DECISION_TASK_SECRET}"],
                "tags": {},
            }
            add_capabilities_for_scopes(task)
            if env is not None:
                assert set(task["payload"]["env"]).isdisjoint(set(env))
                task["payload"]["env"].update(env)

            yield task_id, task
