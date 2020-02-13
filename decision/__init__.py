# -*- coding: utf-8 -*-
import logging

# Setup logger
logging.basicConfig(level=logging.INFO)

# Constants for our resources
OWNER_EMAIL = "fuzzing+taskcluster@mozilla.com"
SCHEDULER_ID = "-"
PROVISIONER_ID = "proj-fuzzing"
WORKER_POOL_PREFIX = "proj-fuzzing"
HOOK_PREFIX = "project-fuzzing"
PROVIDER_IDS = {"aws": "community-tc-workers-aws", "gcp": "community-tc-workers-google"}
