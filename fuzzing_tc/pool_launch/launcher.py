# -*- coding: utf-8 -*-

# This Source Code Form is subject to the terms of the Mozilla Public License,
# v. 2.0. If a copy of the MPL was not distributed with this file, You can
# obtain one at http://mozilla.org/MPL/2.0/.

import ctypes
import logging
import os
import sys

from ..common.pool import PoolConfiguration
from ..common.workflow import Workflow

logger = logging.getLogger()


class PoolLauncher(Workflow):
    """Launcher for a fuzzing pool, using docker parameters from a private repo.
    """

    def __init__(self, command, pool_name):
        super().__init__()

        self.command = command.copy()
        self.environment = os.environ.copy()
        self.pool_name = pool_name
        self.log_dir = "/logs"

    def clone(self, config):
        """Clone remote repositories according to current setup"""
        super().clone(config)

        # Clone fuzzing & community configuration repos
        self.fuzzing_config_dir = self.git_clone(**config["fuzzing_config"])

    def load_params(self):
        path = self.fuzzing_config_dir / f"{self.pool_name}.yml"
        assert path.exists(), f"Missing pool {self.pool_name}"

        # Build tasks needed for a specific pool
        pool_config = PoolConfiguration.from_file(path)

        if pool_config.command:
            assert not self.command, "Specify command-line args XOR pool.command"
            self.command = pool_config.command.copy()
        self.environment.update(pool_config.macros)

    def exec(self):
        assert self.command

        if self.in_taskcluster:
            logging.info(f"Creating private logs directory '{self.log_dir}/'")
            if os.path.isdir(self.log_dir):
                os.chmod(self.log_dir, 0o777)
            else:
                os.mkdir(self.log_dir, mode=0o777)
            logging.info(f"Redirecting stdout/stderr to {self.log_dir}/live.log")
            sys.stdout.flush()
            sys.stderr.flush()

            # redirect stdout/stderr to a log file
            # not sure if the assertions would print
            with open(os.path.join(self.log_dir, "live.log"), "w") as log:
                result = os.dup2(log.fileno(), 1)
                assert result != -1, "dup2 failed: " + os.strerror(ctypes.get_errno())
                result = os.dup2(log.fileno(), 2)
                assert result != -1, "dup2 failed: " + os.strerror(ctypes.get_errno())
        else:
            sys.stdout.flush()
            sys.stderr.flush()

        os.execvpe(self.command[0], self.command, self.environment)
