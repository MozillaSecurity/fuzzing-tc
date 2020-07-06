# -*- coding: utf-8 -*-

# This Source Code Form is subject to the terms of the Mozilla Public License,
# v. 2.0. If a copy of the MPL was not distributed with this file, You can
# obtain one at http://mozilla.org/MPL/2.0/.

import atexit
import logging
import pathlib
import shutil
import tempfile

import yaml
from tcadmin.appconfig import AppConfig

from ..common import taskcluster
from ..common.pool import MachineTypes
from ..common.workflow import Workflow as CommonWorkflow
from . import HOOK_PREFIX
from . import WORKER_POOL_PREFIX
from .pool import PoolConfiguration
from .providers import AWS
from .providers import GCP

logger = logging.getLogger()


class Workflow(CommonWorkflow):
    """Fuzzing decision task workflow"""

    def __init__(self):
        super().__init__()

        self.fuzzing_config_dir = None
        self.community_config_dir = None

        # Automatic cleanup at end of execution
        atexit.register(self.cleanup)

    def configure(self, *args, **kwds):
        config = super().configure(*args, **kwds)
        if config is None:
            raise Exception("Specify local_path XOR secret")
        return config

    @classmethod
    async def tc_admin_boot(cls, resources):
        """Setup the workflow to be usable by tc-admin"""
        appconfig = AppConfig.current()

        local_path = appconfig.options.get("fuzzing_configuration")
        if local_path is not None:
            local_path = pathlib.Path(local_path)

        # Configure workflow using tc-admin options
        workflow = cls()
        config = workflow.configure(
            local_path=local_path,
            secret=appconfig.options.get("fuzzing_taskcluster_secret"),
            fuzzing_git_repository=appconfig.options.get("fuzzing_git_repository"),
            fuzzing_git_revision=appconfig.options.get("fuzzing_git_revision"),
        )

        # Retrieve remote repositories
        workflow.clone(config)

        # Then generate all our Taskcluster resources
        workflow.generate(resources, config)

    def clone(self, config):
        """Clone remote repositories according to current setup"""
        super().clone(config)

        # Clone fuzzing & community configuration repos
        self.fuzzing_config_dir = self.git_clone(**config["fuzzing_config"])
        self.community_config_dir = self.git_clone(**config["community_config"])

    def generate(self, resources, config):

        # Setup resources manager to track only fuzzing instances
        for pattern in self.build_resources_patterns():
            resources.manage(pattern)

        # Load the cloud configuration from community config
        clouds = {
            "aws": AWS(self.community_config_dir),
            "gcp": GCP(self.community_config_dir),
        }

        # Load the machine types
        machines = MachineTypes.from_file(self.fuzzing_config_dir / "machines.yml")

        # Pass fuzzing-tc-config repository through to decision tasks, if specified
        env = {}
        if set(config["fuzzing_config"]) >= {"url", "revision"}:
            env["FUZZING_GIT_REPOSITORY"] = config["fuzzing_config"]["url"]
            env["FUZZING_GIT_REVISION"] = config["fuzzing_config"]["revision"]

        # Browse the files in the repo
        for config_file in self.fuzzing_config_dir.glob("pool*.yml"):
            pool_config = PoolConfiguration.from_file(config_file)
            resources.update(pool_config.build_resources(clouds, machines, env))

    def build_resources_patterns(self):
        """Build regex patterns to manage our resources"""

        # Load existing workerpools from community config
        path = self.community_config_dir / "config" / "projects" / "fuzzing.yml"
        assert path.exists(), f"Missing fuzzing community config in {path}"
        community = yaml.safe_load(path.read_text())
        assert "fuzzing" in community, "Missing fuzzing main key in community config"

        def _suffix(data, key):
            existing = data.get(key, {})
            if not existing:
                # Manage every resource possible
                return ".*"

            # Exclude existing resources from managed resources
            logger.info(
                "Found existing {} in community config: {}".format(
                    key, ", ".join(existing)
                )
            )
            return "(?!({})$)".format("|".join(existing))

        hook_suffix = _suffix(community["fuzzing"], "hooks")
        pool_suffix = _suffix(community["fuzzing"], "workerPools")
        grant_roles = {
            "grants": {
                role.split(f"{HOOK_PREFIX}/", 1)[1]
                for grant in community["fuzzing"].get("grants", [])
                for role in grant.get("to", [])
                if role.startswith(f"hook-id:{HOOK_PREFIX}/") and "*" not in role
            }
        }
        role_suffix = _suffix(grant_roles, "grants")

        return [
            rf"Hook={HOOK_PREFIX}/{hook_suffix}",
            rf"WorkerPool={WORKER_POOL_PREFIX}/{pool_suffix}",
            rf"Role=hook-id:{HOOK_PREFIX}/{role_suffix}",
        ]

    def build_tasks(self, pool_name, task_id, config):
        path = self.fuzzing_config_dir / f"{pool_name}.yml"
        assert path.exists(), f"Missing pool {pool_name}"

        # Pass fuzzing-tc-config repository through to tasks, if specified
        env = {}
        if set(config["fuzzing_config"]) >= {"url", "revision"}:
            env["FUZZING_GIT_REPOSITORY"] = config["fuzzing_config"]["url"]
            env["FUZZING_GIT_REVISION"] = config["fuzzing_config"]["revision"]

        # Build tasks needed for a specific pool
        pool_config = PoolConfiguration.from_file(path)
        tasks = pool_config.build_tasks(task_id, env)

        # Create all the tasks on taskcluster
        queue = taskcluster.get_service("queue")
        for task_id, task in tasks:
            logger.info(f"Creating task {task['metadata']['name']} as {task_id}")
            queue.createTask(task_id, task)

    def cleanup(self):
        """Cleanup temporary folders at end of execution"""
        for folder in (self.community_config_dir, self.fuzzing_config_dir):
            if folder is None or not folder.exists():
                continue
            folder = str(folder)
            if folder.startswith(tempfile.gettempdir()):
                logger.info(f"Removing tempdir clone {folder}")
                shutil.rmtree(folder)
