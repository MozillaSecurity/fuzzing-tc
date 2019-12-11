from decision import taskcluster
from taskcluster.utils import slugId, stringDate
from datetime import datetime, timedelta
import logging
import tempfile
import subprocess
import atexit
import shutil
import yaml
import glob
import os

logger = logging.getLogger()


class Workflow(object):
    """Fuzzing decision task workflow"""

    def __init__(self, task_group_id):
        self.config_dir = None
        self.task_group_id = task_group_id
        self.queue = taskcluster.get_service("queue")
        logger.info(f"Running decision from group {self.task_group_id}")

    def run(self, config):
        assert isinstance(config, dict)

        if "url" in config:
            # Clone remote repository
            self.clone_config(config["url"], config.get("private_key"))
        elif "path" in config:
            # Use local repo for dev
            assert os.path.isdir(config["path"]), \
                f"Invalid config path {config['path']}"
            self.config_dir = config["path"]
            logger.info(f"Using local config in {self.config_dir}")
        else:
            raise Exception("Missing url or path in config declaration")

        # Browse the files in the repo
        for config_file in glob.glob(os.path.join(self.config_dir, "*.yml")):
            try:
                config = yaml.safe_load(open(config_file))
            except Exception as e:
                logger.error(f"Failed to load config file {config_file}: {e}")
                continue

            # Directly create a task per file
            self.start_task(config)

    def clone_config(self, repo_url, private_key=None):
        """Clone private configuration repository"""
        # Config will be stored in a temp dir
        self.config_dir = tempfile.mkdtemp(suffix="fuzzing-tc-config")

        # Automatic cleanup at end of execution
        atexit.register(self.cleanup)

        # Setup ssh private key if any
        if private_key is not None:
            path = os.path.expanduser("~/.ssh/id_rsa")
            assert not os.path.exists(path), \
                f"Existing ssh key found at {path}"
            with open(path, "w") as f:
                f.write(private_key)
            os.chmod(path, 0o400)
            logger.info("Installed ssh private key")

        # Clone the configuration repository
        logger.info(f"Cloning {repo_url}")
        cmd = [
            "git", "clone",
            "--quiet",
            repo_url,
            self.config_dir,
        ]
        subprocess.check_output(cmd)
        logger.info(f"Using cloned config files in {self.config_dir}")

    def start_task(self, config):
        """Start a task according to a payload in the config repo"""
        assert isinstance(config, dict)
        assert "name" in config, "Missing name"
        assert "description" in config, "Missing name"
        assert "payload" in config, "Missing payload"

        now = datetime.utcnow()
        deadline = timedelta(seconds=config.get('deadline', 3600))
        task_id = slugId()
        payload = {
            "taskGroupId": self.task_group_id,
            "created": stringDate(now),
            "deadline": stringDate(now + deadline),
            "metadata": {
                "name": config["name"],
                "description": config["description"],
                "owner": "fuzzing+taskcluster@mozilla.com",
                "source": "https://github.com/MozillaSecurity/fuzzing-tc",
            },
            "payload": config["payload"],

            # Where to run !
            "provisionerId": "proj-fuzzing",
            "workerType": "decision",
        }
        logger.info(f"Trying to create task {config['name']}")
        self.queue.createTask(task_id, payload)
        logger.info(f"Created task f{task_id}")

        return task_id

    def cleanup(self):
        logger.info("Removing config files")
        shutil.rmtree(self.config_dir)
