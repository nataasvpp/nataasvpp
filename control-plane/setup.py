# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2022 Cisco Systems, Inc.

from setuptools import setup, find_packages

setup(
    name="vppconf",
    use_scm_version={
        "root": "..",
    },
    install_requires=[
        "deepdiff",
    ],
    packages=find_packages(),
    include_package_data=True,
    python_requires=">= 3.9",
)

##############################################################################
# THE END