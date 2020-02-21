# -*- coding: utf-8 -*-
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from pathlib import Path

from setuptools import setup

if __name__ == "__main__":
    setup(
        use_scm_version={"fallback_version": Path("VERSION").read_text().strip()},
        setup_requires=["setuptools_scm"],
    )
