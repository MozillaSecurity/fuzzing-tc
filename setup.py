# -*- coding: utf-8 -*-
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import setuptools


def read_requirements(file_):
    lines = []
    with open(file_) as f:
        for line in f.readlines():
            lines.append(line)
    return sorted(list(set(lines)))


with open("VERSION") as f:
    VERSION = f.read().strip()


setuptools.setup(
    name="fuzzing-decision",
    version=VERSION,
    description="Triggers a decision task for Mozilla Firefox build fuzzing",
    author="Mozilla Security",
    author_email="fuzzing+taskcluster@mozilla.com",
    url="https://github.com/mozillasecurity/fuzzing-tc",
    install_requires=read_requirements("requirements.txt"),
    packages=setuptools.find_packages(),
    include_package_data=True,
    zip_safe=False,
    license="MPL2",
)
