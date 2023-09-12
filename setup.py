#!/usr/bin/env python

from setuptools import setup

setup(
    packages=["cowrie", "twisted"],
    include_package_data=True,
    package_dir={"": "src"},
    package_data={"": ["*.md"]},
    use_incremental=True,
    scripts=["bin/fsctl", "bin/asciinema", "bin/cowrie", "bin/createfs", "bin/playlog"],
    setup_requires=["incremental", "click"],
)

import sys


def refresh_plugin_cache():
    from twisted.plugin import IPlugin, getPlugins
    list(getPlugins(IPlugin))
