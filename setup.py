#!/usr/bin/env python
# -*- coding: utf-8 -*-

from os import path

from setuptools import setup
from tispoon import VERSION, AUTHOR, AUTHOR_EMAIL

here = path.abspath(path.dirname(__file__))

with open(path.join(here, "README.md")) as f:
    long_description = f.read()

setup(
    name="tispoon",
    version=VERSION,
    description="Tistory blogging library using open API",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Xvezda/tispoon",
    author=AUTHOR,
    author_email=AUTHOR_EMAIL,
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
        tispoon=tispoon:main
    """,
    keywords="blog blogging openapi korean tistory library",
    py_modules=["tispoon"],
    install_requires=["requests", "markdown2", "six"],
)
