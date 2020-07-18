#!/usr/bin/env python
# -*- coding: utf-8 -*-


import pytest
from tispoon import core


class MockArgs(object):
    pass


class MockResponse(object):
    @property
    def status_code(self):
        return self.status_code

    @property
    def text(self):
        return self.text


@pytest.fixture
def tispoon_cli():
    args = MockArgs()
    return core.Tispoon(args)


def test_dotget():
    fake = {"foo": {"bar": "baz"}}
    assert core.dotget(fake, "foo.bar") == "baz"
    assert core.dotget(fake, "foo.egg") == None
    assert core.dotget(fake, "egg.spam") == None


def test_list(tispoon_cli, monkeypatch):
    def mockget(*args, **kwargs):
        class MockHtmlResponse(MockResponse):
            status_code = 200
            text = "<html></html>"

        return MockHtmlResponse()

    monkeypatch.setattr("requests.get", mockget)
    with pytest.raises(core.TispoonError, match=r"JSON"):
        tispoon_cli.blog_info()


if __name__ == "__main__":
    pytest.main()
