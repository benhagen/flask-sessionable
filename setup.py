#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name = "flask-sessionable",
    version = "0.0.1",
    author = "Ben Hagen",
    author_email = "benhagen@gmail.com",
    description = "Sessions; NOW WITH MOAR",
    license = "MIT",
    keywords = "flask sessions",
    url = "https://github.com/benhagen/flask-sessionable",
    packages=find_packages(),
    requires=['flask','arrow', 'hashlib', 'binascii', 'pycrypto']
)
