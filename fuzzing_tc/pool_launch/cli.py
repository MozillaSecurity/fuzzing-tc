# -*- coding: utf-8 -*-

# This Source Code Form is subject to the terms of the Mozilla Public License,
# v. 2.0. If a copy of the MPL was not distributed with this file, You can
# obtain one at http://mozilla.org/MPL/2.0/.

import argparse
import os

from .launcher import PoolLauncher


def main(args=None):
    parser = argparse.ArgumentParser(prog="fuzzing-pool-launch")
    parser.add_argument(
        "--pool-name",
        type=str,
        help="The target fuzzing pool to create tasks for",
        default=os.environ.get("FUZZING_POOL"),
    )
    parser.add_argument(
        "--taskcluster-secret",
        type=str,
        help="Taskcluster Secret path for configuration",
        default=os.environ.get("TASKCLUSTER_SECRET"),
    )
    parser.add_argument(
        "--configuration",
        type=str,
        help="Local configuration file replacing Taskcluster secrets for fuzzing",
    )
    parser.add_argument("command", help="docker command-line", nargs=argparse.REMAINDER)
    args = parser.parse_args(args=args)

    # Configure workflow using the secret or local configuration
    launcher = PoolLauncher(args.command, args.pool_name)
    config = launcher.configure(
        local_path=args.configuration, secret=args.taskcluster_secret
    )

    if config is not None:
        # Retrieve remote repository
        launcher.clone(config)
        launcher.load_params()

    # Build all task definitions for that pool
    launcher.exec()
