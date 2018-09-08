#!/usr/bin/env python

from setuptools import find_packages, setup

setup(
    name="Cowrie",
    version="1.0",
    description="Cowrie SSH/Telnet Honeypot.",
    maintainer="Michel Oosterhof",
    maintainer_email="michel@oosterhof.net",
    keywords="ssh telnet honeypot",
    url="https://github.com/cowrie/cowrie",
    packages=find_packages('src'),
    include_package_data=True,
    package_dir={'': 'src'},
    package_data={'': ['*.md']},
    use_incremental=True,
    scripts=[
        'bin/fsctl',
        'bin/asciinema',
        'bin/cowrie',
        'bin/createfs',
        'bin/playlog'
    ],
    setup_requires=[
        'incremental',
        'click'
    ],
    install_requires=[
        'twisted>=17.1.0',
        'cryptography>=0.9.1',
        'configparser',
        'pyopenssl',
        'pyparsing',
        'incremental',
        'packaging',
        'appdirs>=1.4.0',
        'python-dateutil',
        'service_identity>=14.0.0'
    ],
    entry_points={
        'console_scripts': ['cowrie = cowrie.scripts.cowrie:run']
    },

    extras_require={
        'csirtg': ['csirtgsdk>=0.0.0a17'],
        'dshield': ['requests'],
        'elasticsearch': ['pyes'],
        'mysql': ['mysqlclient'],
        'mongodb': ['pymongo'],
        'rethinkdblog': ['rethinkdb'],
        's3': ['botocore'],
        'slack': ['slackclient'],
        'splunklegacy': ['splunk-sdk'],
        'influxdb': ['influxdb']
    }
)
