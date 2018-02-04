#!/usr/bin/env python

from setuptools import setup, find_packages

setup (
    name             = "Cowrie",
    version          = "1.0",
    description      = "Cowrie SSH/Telnet Honeypot.",
    maintainer       = "Michel Oosterhof",
    maintainer_email = "michel@oosterhof.net",
    keywords         = "ssh telnet honeypot",
    url              = "https://github.com/micheloosterhof/cowrie",
    packages         = find_packages(),
    include_package_data=True,
    package_data     = { '': ['*.md'] },
    scripts          = ["bin/fsctl",
                        "bin/asciinema",
                        "bin/cowrie",
                        "bin/createfs",
                        "bin/playlog"],
    install_requires = ["twisted>=17.1.0",
                        "cryptography>=0.9.1",
                        "configparser",
                        "pyopenssl",
                        "pyparsing",
                        "packaging",
                        "appdirs>=1.4.0",
                        "python-pyasn1",
                        "python-gmpy2",
                        "python-mysqldb",
                        "klein>=15.0.0",
                        "treq>=15.0.0",
                        "python-dateutil",
                        "service_identity>=14.0.0"],
    entry_points     = {'console_scripts':
                        ['run-the-app = deployme:main']},

    extras_require   = { 'csirtg': ["csirtgsdk>=0.0.0a17"],
                         'dshield': ["requests"],
                         'elasticsearch': ["pyes"],
                         'mysql': ["mysqlclient"],
                         'mongodb': ["pymongo"],
                         'rethinkdblog': ["rethinkdb"],
                         's3': ["botocore"],
                         'slack': ["slackclient"],
                         'splunklegacy': ["splunk-sdk"],
                         'influxdb': ["influxdb"]}
)

