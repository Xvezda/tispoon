#!/usr/bin/env python
# -*- coding: utf-8 -*-


from os import path
from setuptools import setup, find_packages


with open(path.join("tispoon", "__version__.py")) as f:
    exec(f.read())


here = path.abspath(path.dirname(__file__))

with open(path.join(here, "README.md")) as f:
    long_description = f.read()

setup(
    name=__title__,
    version=__version__,
    description="Tistory blogging library using open API",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Xvezda/%s" % __title__,
    author=__author__,
    author_email=__email__,
    classifiers=[
        "Natural Language :: Korean",
        "Topic :: Education :: Testing",
        "Topic :: Other/Nonlisted Topic",
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
    ],
    entry_points="""
        [console_scripts]
        tispoon=tispoon.core:main
    """,
    keywords="blog blogging openapi korean tistory library",
    packages=find_packages(),
    install_requires=["requests", "markdown2"],
    zip_safe=False,
)
