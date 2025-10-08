#!/usr/bin/env python

from setuptools import setup

setup(
    packages=["cowrie", "twisted"],
    include_package_data=True,
    package_dir={"": "src"},
    package_data={"": ["*.md"]},
    setup_requires=["click"],
)

def refresh_plugin_cache():
    from twisted.plugin import IPlugin, getPlugins
    list(getPlugins(IPlugin))
