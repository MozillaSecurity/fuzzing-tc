import logging
from taskcluster.helper import TaskclusterConfig

# Run decision task on community TC instance
taskcluster = TaskclusterConfig("https://community-tc.services.mozilla.com")

# Setup logger
logging.basicConfig(level=logging.INFO)
