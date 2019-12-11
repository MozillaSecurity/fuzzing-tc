import os
import argparse
from taskcluster.utils import slugId, stringDate
from decision import taskcluster
from datetime import datetime, timedelta
import yaml


def parse_cli():
    """Parse CLI arguments to build initial configuration"""
    parser = argparse.ArgumentParser(
        description="Mozilla Fuzzing Decision task"
    )
    parser.add_argument(
        "-g",
        "--task-group",
        help="Task group id to add new tasks to",
        default=os.environ.get("TASK_ID"),
    )
    parser.add_argument(
        "-c",
        "--configuration",
        help="Local configuration file replacing Taskcluster secrets",
        type=open,
    )
    parser.add_argument(
        "--taskcluster-secret",
        help="Taskcluster Secret path",
        default=os.environ.get("TASKCLUSTER_SECRET"),
    )
    return parser.parse_args()


def start_task(task_group_id):
    """Start a dummy task in the same task group"""
    queue = taskcluster.get_service("queue")
    now = datetime.utcnow()
    task_id = slugId()
    payload = {
        "taskGroupId": task_group_id,
        "created": stringDate(now),
        "deadline": stringDate(now + timedelta(seconds=600)),
        "metadata": {
            "name": "A followup task",
            "description": "Dummy task",
            "owner": "babadie@mozilla.com",
            "source": "https://github.com/MozillaSecurity/fuzzing-tc",
        },
        "payload": {
            "maxRunTime": 1200,
            "image": "hello-world",
        },

        # Where to run !
        "provisionerId": "proj-fuzzing",
        "workerType": "decision",
    }
    queue.createTask(task_id, payload)
    print('Created dummy task', task_id)


def main():
    # Load Taskcluster configuration
    args = parse_cli()
    taskcluster.load_secrets(
        args.taskcluster_secret,
        local_secrets=yaml.safe_load(args.configuration)
        if args.configuration
        else None,
    )
    assert args.task_group, "No task group specified"

    print("Running decision from group", args.task_group)
    start_task(args.task_group)


if __name__ == "__main__":
    main()
