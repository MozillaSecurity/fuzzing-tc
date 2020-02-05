# -*- coding: utf-8 -*-
import logging
import os

import yaml

logger = logging.getLogger()


class AWS(object):
    """Amazon Cloud provider config for Taskcluster"""

    def __init__(self, base_dir):
        # Load configuration from cloned community config
        self.regions = self.load_regions(os.path.join(base_dir, "config", "aws.yml"))
        self.imagesets = yaml.safe_load(
            open(os.path.join(base_dir, "config", "imagesets.yml"))
        )
        logger.info("Loaded AWS configuration")

    def load_regions(self, path):
        """Load AWS regions from community tc file"""
        aws = yaml.safe_load(open(path))
        assert "subnets" in aws, "Missing subnets in AWS config"
        assert "security_groups" in aws, "Missing security_groups in AWS config"
        assert (
            aws["subnets"].keys() == aws["security_groups"].keys()
        ), "Keys mismatch in AWS config"
        return {
            region: {
                "subnets": subnets,
                "security_groups": aws["security_groups"][region],
            }
            for region, subnets in aws["subnets"].items()
        }

    def get_amis(self, worker):
        assert worker in self.imagesets, "Missing worker {worker}"
        return self.imagesets[worker]["aws"]["amis"]

    def get_worker_config(self, worker):
        assert worker in self.imagesets, "Missing worker {worker}"
        out = self.imagesets[worker]["workerConfig"]

        # Fixed config for websocket tunnel
        out.update(
            {
                "wstAudience": "communitytc",
                "wstServerURL": "https://community-websocktunnel.services.mozilla.com",
            }
        )

        return out
