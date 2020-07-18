#!/usr/bin/env python
# -*- coding: utf-8 -*-


import pytest
from tispoon import core


def noop(*args, **kwargs):
    pass


class MockArgs(object):
    def __init__(self, token=None):
        self._token = token

    @property
    def token(self):
        return self._token


class MockConnection(object):
    def __init__(self, responses=None, *args, **kwargs):
        self.g = self._stream()
        self.responses = responses

    def _stream(self):
        for response in self.responses:
            yield response

    def recv(self, *args):
        return next(self.g)

    def send(self, *args):
        pass

    def close(self, *args):
        pass


class MockSocket(object):
    def __init__(self, responses=None, *args, **kwargs):
        self.responses = responses

    def accept(self, *args):
        return MockConnection(self.responses), "0.0.0.0"

    def bind(self, *args):
        pass

    def setsockopt(self, *args):
        pass

    def listen(self, *args):
        pass

    def close(self, *args):
        pass


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
        return getattr(self, "_status_code", 200)

    @property
    def text(self):
        try:
            return self._text
        except AttributeError:
            return self.MOCK_JSON_BASE % (
                '"%s"' % self.status_code,
                "%s" % getattr(self, "_item", "{}"),
                '"%s"' % getattr(self, "_error_message", ""),
            )


class MockHtmlResponse(MockResponse):
    _status_code = 200
    _text = "<html></html>"


class MockHtmlErrorResponse(MockHtmlResponse):
    _status_code = 500


@pytest.fixture
def tispoon_cli():
    args = MockArgs()
    return core.Tispoon(args)


def mockget(response):
    def wrapper(*args, **kwargs):
        return response

    return wrapper


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


def test_auth_callback(tispoon_cli, monkeypatch, capsys):
    # FIXME
    # TODO: auth 함수를 조금 더 작은 단위로 쪼개야 함.
    # b'POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4'
    # b'\r\n\r\n1234'

    monkeypatch.setenv("TISPOON_APP_ID", "test_app_id")
    monkeypatch.setenv("TISPOON_APP_SECRET", "test_app_secret")

    path = core.urlparse(core.REDIR_URL).path
    monkeypatch.setattr("os.urandom", lambda n: b"A" * n)
    # sha256(Ax32)
    # == 22a48051594c1949deed7040850c1f0f8764537f5191be56732d16a54c1d8153
    hash = b"22a48051594c1949deed7040850c1f0f8764537f5191be56732d16a54c1d8153"

    def mocksocket(*args, **kwargs):
        return MockSocket(
            responses=[
                b"GET %s?code=deadbeef&state=%s HTTP/1.1\r\n\r\n"
                % (path.encode("utf-8"), hash)
            ]
        )

    monkeypatch.setattr("socket.socket", mocksocket)

    import webbrowser

    def webbrowser_get():
        raise webbrowser.Error

    monkeypatch.setattr("webbrowser.get", webbrowser_get)
    monkeypatch.setattr("webbrowser.open", noop)

    class MockTokenResponse(MockResponse):
        _status_code = 200
        _text = "access_token=deadbeef"

    monkeypatch.setattr("requests.get", mockget(MockTokenResponse()))

    tispoon_cli.auth()
    output = capsys.readouterr()

    assert "http" in output.err
    assert tispoon_cli.token == "deadbeef"


def test_blog_info_html_handling(tispoon_cli, monkeypatch):
    monkeypatch.setattr("requests.get", mockget(MockHtmlResponse()))
    with pytest.raises(core.TispoonError, match=r"JSON"):
        tispoon_cli.blog_info()


def test_blog_info_html_error_handling(tispoon_cli, monkeypatch):
    monkeypatch.setattr("requests.get", mockget(MockHtmlErrorResponse()))
    with pytest.raises(core.TispoonError, match=r"JSON"):
        tispoon_cli.blog_info()


class MockBlogListResponse(MockResponse):
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


def test_blog_info(tispoon_cli, monkeypatch):
    monkeypatch.setattr("requests.get", mockget(MockBlogListResponse()))
    assert tispoon_cli.blogs[0].get("name") == "oauth-test"


def test_blog_info_error(tispoon_cli, monkeypatch):
    monkeypatch.setattr("requests.get", mockget(MockBlogListErrorResponse()))
    with pytest.raises(core.TispoonError, match="foobar"):
        tispoon_cli.blog_info()


def test_blog(tispoon_cli, monkeypatch):
    monkeypatch.setattr("requests.get", mockget(MockBlogListResponse()))
    assert tispoon_cli.blog == "oauth-test"

    # 기본 블로그 임의 지정
    tispoon_cli.blog = "foobar"
    assert tispoon_cli.blog == "foobar"

    with pytest.raises(ValueError):
        tispoon_cli.blog = 1


class MockPostListResponse(MockResponse):
    # https://tistory.github.io/document-tistory-apis/apis/v1/post/list.html
    _item = """\
    {
      "url": "http://oauth-test.tistory.com",
      "secondaryUrl": "",
      "page": "1",
      "count": "2",
      "totalCount": "181",
      "posts": [
        {
          "id": "201",
          "title": "테스트 입니다.",
          "postUrl": "http://oauth-test.tistory.com/entry/hello-world",
          "visibility": "0",
          "categoryId": "0",
          "comments": "0",
          "trackbacks": "0",
          "date": "2018-06-01 17:54:28"
        },
        {
          "id": "202",
          "title": "다람쥐 헌 쳇바퀴에 타고파",
          "postUrl": "http://oauth-test.tistory.com/entry/this-is-slogan",
          "visibility": "0",
          "categoryId": "0",
          "comments": "0",
          "trackbacks": "0",
          "date": "2018-06-02 12:34:56"
        }
      ]
    }"""


def test_post_list(tispoon_cli, monkeypatch):
    tispoon_cli.blog = "oauth-test"
    monkeypatch.setattr("requests.get", mockget(MockPostListResponse()))
    count = 0
    for post in tispoon_cli.posts:
        count += 1
    assert count > 0


def test_find_post(tispoon_cli, monkeypatch):
    tispoon_cli.blog = "oauth-test"
    monkeypatch.setattr("requests.get", mockget(MockPostListResponse()))

    post = tispoon_cli.find_post(title=u"테스트 입니다.")
    assert post

    post = tispoon_cli.find_post(slogan=u"/hello-world")
    assert post

    post = tispoon_cli.find_post(slogan=u"hello-world")
    assert post


def test_post_read(tispoon_cli, monkeypatch):
    tispoon_cli.blog = "oauth-test"
    monkeypatch.setattr("requests.get", mockget(MockPostListResponse()))

    with pytest.raises(core.TispoonError, match="post_id"):
        tispoon_cli.post_read()

    post = tispoon_cli.post_read(201)
    assert post


def test_post_write(tispoon_cli, monkeypatch):
    class MockPostWriteSuccessResponse(MockResponse):
        # https://tistory.github.io/document-tistory-apis/apis/v1/post/write.html
        _text = """\
        {
            "tistory":{
                "status":"200",
                "postId":"74",
                "url":"http://foobar.tistory.com/74"
            }
        }
        """

    def mockpost(*args, **kwargs):
        assert args[0].startswith("https://www.tistory.com/apis/post/write")
        return MockPostWriteSuccessResponse()

    tispoon_cli.blog = "foobar"
    monkeypatch.setattr("requests.post", mockpost)
    result = tispoon_cli.post_write(
        {"title": "hello world", "content": "ham and egg"}
    )
    assert result.get("post_id")
    assert result.get("url")


def test_post_modify(tispoon_cli, monkeypatch):
    class MockPostWriteSuccessResponse(MockResponse):
        _text = """\
        {
            "tistory":{
                "status":"200",
                "postId":"74",
                "url":"http://foobar.tistory.com/74"
            }
        }
        """

    def mockpost(*args, **kwargs):
        assert args[0].startswith("https://www.tistory.com/apis/post/modify")
        return MockPostWriteSuccessResponse()

    tispoon_cli.blog = "foobar"
    monkeypatch.setattr("requests.post", mockpost)
    result = tispoon_cli.post_modify(
        74, {"title": "hello world", "content": "spam and egg"}
    )
    assert result.get("post_id")
    assert result.get("url")


if __name__ == "__main__":
    pytest.main()
