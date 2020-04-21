# -*- coding: utf-8 -*-

# This Source Code Form is subject to the terms of the Mozilla Public License,
# v. 2.0. If a copy of the MPL was not distributed with this file, You can
# obtain one at http://mozilla.org/MPL/2.0/.

import logging

from tcadmin.resources import WorkerPool

from fuzzing_tc.common import taskcluster

logger = logging.getLogger()


async def cancel_pool_tasks(action, resource):
    """Cancel all the tasks on a WorkerPool being updated or deleted"""
    assert isinstance(resource, WorkerPool)

    # List workers in that pool
    queue = taskcluster.get_service("queue")
    provisioner, worker_type = resource.workerPoolId.split("/")
    logger.info(f"Cancelling tasks for {provisioner} / {worker_type}")
    workers = queue.listWorkers(provisioner, worker_type)
    for worker in workers["workers"]:
        latest_task = worker["latestTask"]
        if not latest_task:
            continue

        # Check the state of the latest task
        task_id = latest_task["taskId"]
        status = queue.status(task_id)
        run = status["status"]["runs"][latest_task["runId"]]

        # State can be pending,running,completed,failed,exception
        # We only cancel pending & running tasks
        if run["state"] not in ("pending", "running"):
            logger.debug(f"Skipping {run['state']} task {task_id}")
            continue

        # Cancel the task
        logger.info(f"Cancelling task {task_id}")
        queue.cancel(task_id)
