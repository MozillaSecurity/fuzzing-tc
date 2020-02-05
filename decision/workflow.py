# -*- coding: utf-8 -*-
import atexit
import difflib
import glob
import json
import logging
import os
import shutil
import subprocess
import tempfile

from taskcluster import WorkerManager
from taskcluster.exceptions import TaskclusterRestFailure

from decision import taskcluster
from decision.pool import MachineTypes, PoolConfiguration
from decision.providers import AWS

logger = logging.getLogger()


class Workflow(object):
    """Fuzzing decision task workflow"""

    def __init__(self, task_group_id):
        self.fuzzing_config_dir = None
        self.community_config_dir = None
        self.task_group_id = task_group_id
        self.queue = taskcluster.get_service("queue")
        logger.info(f"Running decision from group {self.task_group_id}")

        self.worker_manager = WorkerManager(taskcluster.options)

        # Automatic cleanup at end of execution
        atexit.register(self.cleanup)

    def run(self, config):
        assert isinstance(config, dict)

        # Setup ssh private key if any
        private_key = config.get("private_key")
        if private_key is not None:
            path = os.path.expanduser("~/.ssh/id_rsa")
            assert not os.path.exists(path), f"Existing ssh key found at {path}"
            with open(path, "w") as f:
                f.write(private_key)
            os.chmod(path, 0o400)
            logger.info("Installed ssh private key")

        # Clone fuzzing & community configuration repos
        self.fuzzing_config_dir = self.clone(**config["fuzzing_config"])
        self.community_config_dir = self.clone(**config["community_config"])

        # Load the AWS configuration from community config
        aws = AWS(self.community_config_dir)

        # Load the machine types
        machines = MachineTypes.from_file(
            os.path.join(self.fuzzing_config_dir, "machines.yml")
        )

        # Browse the files in the repo
        fuzzing_glob = os.path.join(self.fuzzing_config_dir, "pool*.yml")
        for config_file in glob.glob(fuzzing_glob):

            pool = PoolConfiguration.from_file(config_file)

            # Dump it as json
            payload = pool.build_payload(aws, machines)

            # Retrieve the existing one
            try:
                existing = self.worker_manager.workerPool(pool.id)
            except TaskclusterRestFailure as e:
                if e.status_code == 404:
                    logger.info(f"Worker pool {pool.id} does not exist")
                    existing = None
                else:
                    raise

            diff = self.diff(existing, payload)
            if diff is None:
                logger.info(f"No changes for {pool.id}")
            else:
                logger.info(f"Changes need to be applied on {pool.id}")
                print(diff)

    def clone(self, url=None, path=None, **kwargs):
        """Clone a configuration repository"""
        if path is not None:
            # Use local path when available
            assert os.path.isdir(path), "Invalid repo dir {path}"
            logger.info(f"Using local configuration in {path}")
            return path

        elif url is not None:
            # Clone from remote repository
            clone_dir = tempfile.mkdtemp(suffix=url[url.rindex("/") + 1 :])

            # Clone the configuration repository
            logger.info(f"Cloning {url}")
            cmd = ["git", "clone", "--quiet", url, clone_dir]
            subprocess.check_output(cmd)
            logger.info(f"Using cloned config files in {clone_dir}")

            return clone_dir
        else:
            raise Exception("You need to specify a repo url or local path")

    def diff(self, existing, generated):
        """Compare two dict payloads using unidiff"""
        diff = difflib.unified_diff(
            json.dumps(existing, sort_keys=True, indent=4).splitlines(),
            json.dumps(generated, sort_keys=True, indent=4).splitlines(),
            fromfile="existing.json",
            tofile="generated.json",
        )
        diff_lines = list(diff)
        if not diff_lines:
            return None
        return "\n".join(diff_lines)

    def cleanup(self):
        """Cleanup temporary folders at end of execution"""
        for folder in (self.community_config_dir, self.fuzzing_config_dir):
            if folder and folder.startswith(tempfile.gettempdir()):
                logger.info(f"Removing tempdir clone {folder}")
                shutil.rmtree(folder)
