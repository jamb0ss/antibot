# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

import os
import codecs

PACKAGE_DIR = os.path.abspath(os.path.dirname(__file__))

with codecs.open(os.path.join(PACKAGE_DIR, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

with open(os.path.join(PACKAGE_DIR, 'version')) as version_file:
    version = version_file.read().strip()


setup(
    name='antibot',
    version=version,
    description='Analytics tool to identify bots in the web server logs.',
    long_description=long_description,
    author='jamb0ss',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
    ],
    packages=find_packages(exclude=['contrib', 'docs', 'tests']),
    install_requires=[],
    entry_points={
        'console_scripts': [
            'antibot=antibot:run',
        ],
    },
)

