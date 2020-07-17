#!/usr/bin/env python
# -*- coding: utf-8 -*-


import pytest
from tispoon import core


@pytest.fixture
def tispoon_cli():
    return core.Tispoon()


def test_dotget():
    fake = {"foo": {"bar": "baz"}}
    assert core.dotget(fake, "foo.bar") == "baz"
    assert core.dotget(fake, "foo.egg") == None
    assert core.dotget(fake, "egg.spam") == None


if __name__ == "__main__":
    pytest.main()
