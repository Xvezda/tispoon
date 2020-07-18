#!/usr/bin/env python
# -*- coding: utf-8 -*-


import pytest
from tispoon import core


class MockArgs(object):
    def __init__(self, token=None):
        self._token = token

    @property
    def token(self):
        return self._token


class MockResponse(object):
    MOCK_JSON_BASE = """\
    {
        "tistory": {
            "status": %s,
            "item": %s,
            "error_message": %s
        }
    }
    """

    @property
    def status_code(self):
        return self._status_code

    @property
    def text(self):
        try:
            return self._text
        except AttributeError:
            return self.MOCK_JSON_BASE % (
                '"%s"' % getattr(self, "_status_code", 200),
                "%s" % getattr(self, "_item", "{}"),
                '"%s"' % getattr(self, "_error_message", ""),
            )


class MockHtmlResponse(MockResponse):
    _status_code = 200
    _text = "<html></html>"


class MockHtmlErrorResponse(MockHtmlResponse):
    _status_code = 500


class MockBlogListResponse(MockResponse):
    _status_code = 200
    # 응답값 예
    # https://tistory.github.io/document-tistory-apis/apis/v1/blog/list.html#%EC%9D%91%EB%8B%B5%EA%B0%92-%EC%98%88
    _item = """\
    {
        "id": "blog_oauth_test@daum.net",
        "userId": "12345",
        "blogs": [
            {
                "name": "oauth-test",
                "url": "http://oauth-test.tistory.com",
                "secondaryUrl": "http://",
                "nickname": "티스토리 테스트",
                "title": "테스트 블로그 1",
                "description": "안녕하세요! 티스토리입니다.",
                "default": "Y",
                "blogIconUrl": "https://blog_icon_url",
                "faviconUrl": "https://favicon_url",
                "profileThumbnailImageUrl": "https://profile_image",
                "profileImageUrl": "https://profile_image",
                "role": "소유자",
                "blogId": "123",
                "statistics": {
                    "post": "182",
                    "comment": "146",
                    "trackback": "0",
                    "guestbook": "39",
                    "invitation": "0"
                }
            }
        ]
    }
    """


class MockBlogListErrorResponse(MockBlogListResponse):
    _status_code = 500
    _error_message = "foobar"


@pytest.fixture
def tispoon_cli():
    args = MockArgs()
    return core.Tispoon(args)


def mockget(response):
    def wrapper(*args, **kwargs):
        return response

    return wrapper


class TestUtils:
    def test_u(self):
        assert isinstance(core.u(u"가"), str)

    def test_quote(self):
        assert core.quote(u"가") == "%EA%B0%80"

    def test_unquote(self):
        assert core.unquote("%EA%B0%80") == u"가"


def test_dotget():
    fake = {"foo": {"bar": "baz"}}
    with pytest.raises(KeyError):
        core.dotget(fake, "egg.spam")
    assert core.dotget(fake, "egg.spam", optional=True) is None

    with pytest.raises(KeyError):
        core.dotget(fake, "foo.egg")
    assert core.dotget(fake, "foo.egg", optional=True) is None

    assert core.dotget(fake, "foo.bar") == "baz"


def test_auth_empty_config(tispoon_cli, monkeypatch):
    with pytest.raises(ValueError):
        tispoon_cli.auth()


def test_auth_assign_token(tispoon_cli, monkeypatch):
    tispoon_cli.token = "deadbeef"
    assert tispoon_cli.auth()


def test_blog_info_html_handling(tispoon_cli, monkeypatch):
    monkeypatch.setattr("requests.get", mockget(MockHtmlResponse()))
    with pytest.raises(core.TispoonError, match=r"JSON"):
        tispoon_cli.blog_info()


def test_blog_info_html_error_handling(tispoon_cli, monkeypatch):
    monkeypatch.setattr("requests.get", mockget(MockHtmlErrorResponse()))
    with pytest.raises(core.TispoonError, match=r"JSON"):
        tispoon_cli.blog_info()


def test_blog_info(tispoon_cli, monkeypatch):
    monkeypatch.setattr("requests.get", mockget(MockBlogListResponse()))
    blog_info = tispoon_cli.blog_info()
    first_blog = blog_info[0]
    first_blog_name = first_blog.get("name")
    assert first_blog_name == "oauth-test"
    assert first_blog_name == tispoon_cli.blogs[0].get("name")


def test_blog_info_error(tispoon_cli, monkeypatch):
    monkeypatch.setattr("requests.get", mockget(MockBlogListErrorResponse()))
    with pytest.raises(core.TispoonError, match="foobar"):
        tispoon_cli.blog_info()


if __name__ == "__main__":
    pytest.main()
