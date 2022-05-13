#!/usr/bin/env python3

from distutils.core import setup

setup(
    name='turnkey-netinfo',
    version='1.0',
    description='Python utility for obtaining network information',
    author='Stefan Davis',
    url='https://github.com/turnkeylinux/turnkey-netinfo',
    packages=['netinfo'],
    package_data={"netinfo": ["py.typed"]})
