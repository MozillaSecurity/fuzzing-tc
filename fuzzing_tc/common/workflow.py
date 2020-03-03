# -*- coding: utf-8 -*-

# This Source Code Form is subject to the terms of the Mozilla Public License,
# v. 2.0. If a copy of the MPL was not distributed with this file, You can
# obtain one at http://mozilla.org/MPL/2.0/.

import logging
import os
import pathlib
import subprocess
import tempfile

import yaml
from taskcluster.helper import TaskclusterConfig

logger = logging.getLogger()


class Workflow:
    def __init__(self):
        # Shared taskcluster configuration
        self.taskcluster = TaskclusterConfig(
            "https://community-tc.services.mozilla.com"
        )
        self.taskcluster.auth()

    @property
    def in_taskcluster(self):
        return "TASK_ID" in os.environ and "TASKCLUSTER_ROOT_URL" in os.environ

    def configure(
        self,
        local_path=None,
        secret=None,
        fuzzing_git_repository=None,
        fuzzing_git_revision=None,
    ):
        """Load configuration either from local file or Taskcluster secret"""

        if local_path is not None:
            assert local_path.is_file(), f"Missing configuration in {local_path}"
            config = yaml.safe_load(local_path.read_text())

        elif secret is not None:
            config = self.taskcluster.load_secrets(secret)

        else:
            return None

        assert isinstance(config, dict)
        if "community_config" not in config:
            config["community_config"] = {
                "url": "git@github.com:mozilla/community-tc-config.git"
            }

        # Use Github repo & revision from environment when specified
        if fuzzing_git_repository and fuzzing_git_revision:
            logger.info(
                f"Use Fuzzing git repository from options: {fuzzing_git_repository} @ {fuzzing_git_revision}"
            )
            config["fuzzing_config"] = {
                "url": fuzzing_git_repository,
                "revision": fuzzing_git_revision,
            }

        assert "fuzzing_config" in config, "Missing fuzzing_config"

        return config

    def clone(self, config):
        """Clone remote repositories according to current setup"""
        assert isinstance(config, dict)

        # Setup ssh private key if any
        private_key = config.get("private_key")
        if private_key is not None:
            ssh_path = pathlib.Path("~/.ssh").expanduser()
            ssh_path.mkdir(mode=0o700, exist_ok=True)
            path = ssh_path / "id_rsa"
            assert not path.exists(), f"Existing ssh key found at {path}"
            path.write_text(private_key)
            path.chmod(0o400)
            logger.info("Installed ssh private key")

    def git_clone(self, url=None, path=None, revision=None, **kwargs):
        """Clone a configuration repository"""
        if path is not None:
            path = pathlib.Path(path)
            # Use local path when available
            assert path.is_dir(), f"Invalid repo dir {path}"
            logger.info(f"Using local configuration in {path}")

        elif url is not None:
            # Clone from remote repository
            path = pathlib.Path(tempfile.mkdtemp(suffix=url[url.rindex("/") + 1 :]))

            # Clone the configuration repository
            logger.info(f"Cloning {url}")
            cmd = ["git", "clone", "--quiet", url, str(path)]
            subprocess.check_output(cmd)
            logger.info(f"Using cloned config files in {path}")
        else:
            raise Exception("You need to specify a repo url or local path")

        # Update to specified revision
        # Fallback to pulling remote references
        if revision is not None:
            logger.info(f"Updating repo to {revision}")
            try:
                cmd = ["git", "checkout", revision, "-q"]
                subprocess.check_output(cmd, cwd=str(path))

            except subprocess.CalledProcessError:
                logger.info("Updating failed, trying to pull")
                cmd = ["git", "pull", "origin", revision, "-q"]
                subprocess.check_output(cmd, cwd=str(path))

        return path
