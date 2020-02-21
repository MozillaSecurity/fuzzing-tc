# -*- coding: utf-8 -*-

# This Source Code Form is subject to the terms of the Mozilla Public License,
# v. 2.0. If a copy of the MPL was not distributed with this file, You can
# obtain one at http://mozilla.org/MPL/2.0/.

import logging

from taskcluster.helper import TaskclusterConfig

# Setup logger
logging.basicConfig(level=logging.INFO)

# Shared taskcluster configuration
taskcluster = TaskclusterConfig("https://community-tc.services.mozilla.com")
taskcluster.auth()
