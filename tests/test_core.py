#!/usr/bin/env python
# -*- coding: utf-8 -*-


import pytest
from tispoon import core


def test_dotget():
    fake = {"foo": {"bar": "baz"}}
    assert core.dotget(fake, "foo.bar") == "baz"


if __name__ == "__main__":
    pytest.main()
