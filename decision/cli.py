import os
import argparse
from decision import taskcluster
from decision.workflow import Workflow
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


def main():
    # Load Taskcluster configuration
    args = parse_cli()
    secrets = taskcluster.load_secrets(
        args.taskcluster_secret,
        required=["fuzzing_config"],
        existing={
            "community_config": {
                "url": "git@github.com:mozilla/community-tc-config.git",
            }
        },
        local_secrets=yaml.safe_load(args.configuration)
        if args.configuration
        else None,
    )
    assert args.task_group, "No task group specified"

    workflow = Workflow(args.task_group)
    workflow.run(secrets)


if __name__ == "__main__":
    main()
