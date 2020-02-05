# -*- coding: utf-8 -*-
import atexit
import glob
import logging
import os
import shutil
import subprocess
import tempfile

import yaml
from taskcluster import Secrets, optionsFromEnvironment
from tcadmin.appconfig import AppConfig

from decision import HOOK_PREFIX, WORKER_POOL_PREFIX
from decision.pool import MachineTypes, PoolConfiguration
from decision.providers import AWS

logger = logging.getLogger()


class Workflow(object):
    """Fuzzing decision task workflow"""

    def __init__(self):
        self.fuzzing_config_dir = None
        self.community_config_dir = None

        # Automatic cleanup at end of execution
        atexit.register(self.cleanup)

    @staticmethod
    async def tc_admin_boot(resources):
        """Setup the workflow to be usable by tc-admin"""
        appconfig = AppConfig.current()

        # Configure workflow using tc-admin options
        workflow = Workflow()
        config = workflow.configure(
            local_path=appconfig.options.get("fuzzing_configuration"),
            secret=appconfig.options.get("fuzzing_taskcluster_secret"),
        )

        # Retrieve remote repositories
        workflow.clone(config)

        # Then generate all our Taskcluster resources
        workflow.generate(resources)

    def configure(self, local_path=None, secret=None):
        """Load configuration either from local file or Taskcluster secret"""

        if local_path is not None:
            assert os.path.exists(local_path), f"Missing configuration in {local_path}"
            config = yaml.safe_load(open(local_path))

        elif secret is not None:
            # Use Proxy when available
            tc_options = optionsFromEnvironment()
            if "TASKCLUSTER_PROXY_URL" in os.environ:
                tc_options["rootUrl"] = os.environ["TASKCLUSTER_PROXY_URL"]
            secrets = Secrets(tc_options)
            response = secrets.get(secret)
            assert response is not None, "Invalid Taskcluster secret payload"
            config = response["secret"]
        else:
            raise Exception("Specify local_path XOR secret")

        assert isinstance(config, dict)
        assert "fuzzing_config" in config, "Missing fuzzing_config"
        if "community_config" not in config:
            config["community_config"] = {
                "url": "git@github.com:mozilla/community-tc-config.git"
            }

        # TODO: detect Github repos + revisions

        return config

    def clone(self, config):
        """Clone remote repositories according to current setup"""
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
        self.fuzzing_config_dir = self.git_clone(**config["fuzzing_config"])
        self.community_config_dir = self.git_clone(**config["community_config"])

    def generate(self, resources):

        # Setup resources manager to track only fuzzing instances
        patterns = [rf"WorkerPool={WORKER_POOL_PREFIX}/.*", rf"Hook={HOOK_PREFIX}/.*"]
        for pattern in patterns:
            resources.manage(pattern)

        # Load the AWS configuration from community config
        aws = AWS(self.community_config_dir)

        # Load the machine types
        machines = MachineTypes.from_file(
            os.path.join(self.fuzzing_config_dir, "machines.yml")
        )

        # Browse the files in the repo
        fuzzing_glob = os.path.join(self.fuzzing_config_dir, "pool*.yml")
        for config_file in glob.glob(fuzzing_glob):

            pool_config = PoolConfiguration.from_file(config_file)

            pool = pool_config.build_resource(aws, machines)

            resources.add(pool)

    def git_clone(self, url=None, path=None, **kwargs):
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

    def cleanup(self):
        """Cleanup temporary folders at end of execution"""
        for folder in (self.community_config_dir, self.fuzzing_config_dir):
            if folder and folder.startswith(tempfile.gettempdir()):
                logger.info(f"Removing tempdir clone {folder}")
                shutil.rmtree(folder)
