# -*- coding: utf-8 -*-

# This Source Code Form is subject to the terms of the Mozilla Public License,
# v. 2.0. If a copy of the MPL was not distributed with this file, You can
# obtain one at http://mozilla.org/MPL/2.0/.

import logging

from tcadmin.resources import Hook
from tcadmin.resources import WorkerPool

from fuzzing_tc.common import taskcluster
from fuzzing_tc.decision.pool import cancel_tasks

logger = logging.getLogger()


async def cancel_pool_tasks(action, resource):
    """Cancel all the tasks on a WorkerPool being updated or deleted"""
    assert isinstance(resource, WorkerPool)

    _, worker_type = resource.workerPoolId.split("/")
    cancel_tasks(worker_type)


async def trigger_hook(action, resource):
    """Trigger a Hook after it is created or updated"""
    assert isinstance(resource, Hook)

    hooks = taskcluster.get_service("hooks")
    logger.info(f"Triggering hook {resource.hookGroupId} / {resource.hookId}")
    hooks.triggerHook(resource.hookGroupId, resource.hookId, {})
