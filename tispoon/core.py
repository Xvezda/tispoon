#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2020 Xvezda <xvezda@naver.com>
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

"""
Tispoon의 핵심 기능을 모아놓은 모듈입니다.
"""

import re
import os
import sys
import json
import time
import socket
import hashlib
import textwrap

# Debugging modules
import traceback
import logging

# Third party modules
import requests
from markdown2 import markdown as _markdown

# Get version info
from .version import VERSION

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())

# Version compatible helpers
PY2 = sys.version_info[0] == 2
PY3 = sys.version_info[0] == 3

if PY2:
    from urllib import quote as _quote
    from urllib import unquote as _unquote  # noqa
    from urlparse import urlparse  # noqa
else:
    from urllib.parse import quote as _quote
    from urllib.parse import unquote as _unquote
    from urllib.parse import urlparse


def u(text):
    if PY2:
        return unicode(text).encode("utf-8")  # noqa
    return str(text)


def quote(url):
    if PY3:
        return _quote(bytes(str(url), encoding="utf-8"))
    return _quote(str(url))


def unquote(url):
    if PY3:
        return _unquote(str(url), encoding="utf-8")
    return _unquote(u(url)).decode("utf-8")


def markdown(*args, **kwargs):
    """기존 마크다운 모듈을 깃허브 스타일로 바꿔주는 wrapper 입니다."""
    try:
        extras = kwargs.pop("extras")
    except KeyError:
        extras = []

    extras.extend(
        [
            "code-friendly",
            "fenced-code-blocks",
            "metadata",
            "nofollow",
            "spoiler",
            "tables",
            "target-blank-links",
        ]
    )
    return _markdown(*args, extras=extras, **kwargs)


API_VERSION = "v1"
BASE_URL = "https://www.tistory.com"
# Tispoon 토큰 발급시에 콜백으로 사용되는 포트번호 입니다.
PORT = int(os.getenv("TISPOON_PORT", 9638))
# 토큰 발급시의 콜백 URL 입니다.
REDIR_URL = "http://127.0.0.1:%s/callback" % (PORT,)

TTL_DEF = int(os.getenv("TISPOON_TTL", 600))
TTL_INF = -1

# Tistory OpenAPI에 정의된 게시글 공개 범위 상수 입니다.
VISIBILITY_PRIVATE = (0,)
# 글 목록에 사용되는 게시글 공개 범위 상수값이 작성시의 값과 다름
VISIBILITY_PROTECTED = (1, 15)
VISIBILITY_PUBLISHED = (3, 20)

COMMENT_ACCEPT = 0
COMMENT_CLOSED = 1

COMMENT_SECRET = 1
COMMENT_PUBLIC = 0


DEMO_MARKDOWN = """\
---
title: Hello world from Tispoon!
visibility: 3
---

# Hello World!

파이썬 기반 티스토리 블로깅 라이브러리
[Tispoon](https://github.com/Xvezda/tispoon)
으로 쓰여진 테스트 게시글 입니다. :)

## H2
### H3

```
#include <stdio.h>

int main(void)
{
    printf("Hello World!\n");

    return 0;
}
```

- foo
  * bar
  + baz

"""


def dotget(obj, expr, optional=False):
    """`.`으로 연결된 객체접근 표현식을 parsing, 반복하여 반환하는 유틸리티 함수입니다.

    Args:
        expr (str): 문자열 형태의 연속된 객체접근 표현식입니다.
        optional (bool, optional): 자바스크립트의 `optional chaining`과 같이,
            해당 속성이 객체에 존재하지 않을 경우에도 에러를 발생시키지 않습니다.

    Returns:
        `eval(expr)`을 실행한 것과 같은 결과를 보여줍니다.
    """
    context = obj
    for token in expr.split("."):
        try:
            context = context.get(token)
        except AttributeError:
            if optional:
                return None
    return context


class CacheItem(object):
    """캐싱에 사용되는 아이템의 일반화 된 추상클래스 입니다."""

    def __init__(self, value):
        self.timestamp = time.time()
        self.value = value


class BaseCache(object):
    """캐시된 아이템을 관리하는 관리객체의 기반 클래스입니다."""

    def __init__(self, hashing="md5"):
        self.hashing = lambda x: getattr(hashlib, hashing)(
            x.encode()
        ).hexdigest()
        self.items = {}

    def set(self, name, value):
        """값을 `CacheItem` 클래스를 사용하여 캐싱합니다.

        Args:
            name (str): 문자열로 이루어진 값의 임의 이름입니다.
            value: 저장할 값의 객체입니다.
        """
        self.items[self.hashing(name)] = CacheItem(value)

    def get(self, name, fallback=None):
        """캐시된 값을 반환하는 매서드함수 입니다.

        `fallback` 콜백함수가 정의된 경우 캐시된 객체가 없거나, 캐시 유효기간(TTL)이 만료된 경우
        `name`을 인자로 호출하여 반환된 값을 캐싱하고, 반환합니다.

        Args:
            name (str): 문자열로 이루어진 저장된 값의 이름입니다.
            fallback: 캐싱된 내용을 찾을 수 없는 경우 호출될 콜백 함수 입니다.
                첫번째 인자로 `name`인자가 넘어갑니다.

        Returns:
            저장된 객체를 돌려줍니다.
        """
        item = self.items.get(self.hashing(name))
        if not item:
            if fallback:
                logger.debug("fallback으로 부터 가져옴: %s" % (name,))
                item = fallback(name)
                self.set(name, item)
                return item
            return

        if self.TTL != TTL_INF and time.time() - item.timestamp >= self.TTL:
            logger.debug("캐시 만료: %s" % (name,))
            del self.items[self.hashing(name)]
            if fallback:
                logger.debug("fallback으로 부터 가져옴: %s" % (name,))
                item = fallback(name)
                self.set(name, item)
                return item
            return
        logger.debug("cache로 부터 가져옴: %s" % (name,))
        return item.value


class TispoonBase(object):
    """Tispoon에서 사용되는 모든 객체들의 조상클래스 입니다."""

    pass


class TispoonCache(BaseCache):
    TTL = TTL_DEF


class TispoonError(Exception):
    pass


class Tispoon(TispoonBase):
    """Tistory OpenAPI의 wrapper 클래스 입니다."""

    def __init__(self, args, cache=None):
        self.args = args

        self._token = getattr(args, "token", None) or os.getenv(
            "TISPOON_TOKEN"
        )
        self._blog = getattr(args, "blog", None) or os.getenv("TISPOON_BLOG")
        self._cache = cache or TispoonCache()

    def auth(self, app_id="", app_secret=""):
        """토큰이 없는 경우, API로부터 토큰을 새로 발급하는 매서드함수 입니다."""
        if self.token:
            logger.debug("토큰이 이미 존재합니다.")
            return True

        if not app_id:
            app_id = os.getenv("TISPOON_APP_ID")
        if not app_secret:
            app_secret = os.getenv("TISPOON_APP_SECRET")

        if not app_id or not app_secret:
            raise ValueError("app_id, app_secret 둘 중 하나는 반드시 제공되어야 합니다.")

        # 보안을 위한 임의 토큰을 생성합니다.
        state = hashlib.sha256(os.urandom(32)).hexdigest()
        url = (
            textwrap.dedent(
                """\
        {base_url}/oauth/authorize?
        client_id={client_id}
        &redirect_uri={redirect_uri}
        &response_type=code
        &state={state}
        """
            )
            .replace("\n", "")
            .format(
                base_url=BASE_URL,
                client_id=app_id,
                redirect_uri=REDIR_URL,
                state=quote(state),
            )
        )
        import webbrowser

        try:
            browser = webbrowser.get()
            browser.open(url, new=2)
        except webbrowser.Error:  # 웹 브라우저가 존재하지 않는경우 인증 주소를 stdout으로 알립니다.
            print("다음의 주소를 방문하여 권한을 허락해주세요.", file=sys.stderr)
            print(url, file=sys.stderr)

        # Callback 인증에 사용될 임시 HTTP 서버를 생성합니다.
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("", 9638))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.listen(1)
        conn, addr = s.accept()

        prev_state = state
        # HTTP Body를 제외한 헤더만을 가져옵니다.
        req = conn.recv(1024).decode().split("\r\n\r\n")[0]
        try:
            if not req.startswith("GET %s" % (urlparse(REDIR_URL).path,)):
                logger.debug("잘못된 요청 입니다.")
                return False
            code = re.search(
                r"^GET /[^\?]*\?.*&?code=([^&]*).* HTTP/\d\.\d", req, re.M
            ).group(1)
            state = re.search(
                r"^GET /[^\?]*\?.*&?state=([^&]*).* HTTP/\d\.\d", req, re.M
            ).group(1)
        except AttributeError:
            logger.debug("요구조건을 충족하지 않았습니다.")
            return False
        finally:
            conn.send(b"HTTP/1.1 200 OK\r\n")
            conn.send(b"Content-Length: 0\r\n")
            conn.send(b"Connection: close\r\n")
            conn.send(b"\r\n")
            conn.close()
            s.close()

        if prev_state != state:
            logger.debug("잘못된 공격방지 문자열이 전달되었습니다.")
            return False

        url = (
            textwrap.dedent(
                """\
        {base_url}/oauth/access_token?
        client_id={client_id}
        &client_secret={client_secret}
        &redirect_uri={redirect_uri}
        &code={code}
        &grant_type=authorization_code
        """
            )
            .replace("\n", "")
            .format(
                base_url=BASE_URL,
                client_id=app_id,
                client_secret=app_secret,
                redirect_uri=REDIR_URL,
                code=code,
            )
        )
        # Callback으로 반환된 코드를 기반으로 토큰을 발급 받습니다.
        r = requests.get(url)
        try:
            token = re.search(r"access_token=(\w+)", r.text).group(1)
        except AttributeError:
            logger.debug("access token을 가져오는데 실패했습니다.")
            return False

        self.token = token
        return True

    @property
    def token(self):
        """토큰 문자열을 반환합니다."""
        return self._token

    @token.setter
    def token(self, value):
        if type(value) is not str:
            raise ValueError("값은 반드시 문자열이어야 합니다.")
        self._token = value

    @property
    def blog(self):
        """기본 블로그."""
        if not self._blog:
            self._blog = self.default_blog().get("name")
        return self._blog

    @blog.setter
    def blog(self, value):
        if type(value) is not str:
            raise ValueError("값은 반드시 문자열이어야 합니다.")
        self._blog = value

    @property
    def cache(self):
        return self._cache

    @cache.setter
    def cache(self, value):
        self._cache = value

    def assemble_url(self, path, output="json", **kwargs):
        """`kwargs`를 URL parameter 형식으로 변환하여 API 요청에 적합하도록 조립하는 함수입니다.

        Args:
            path (str): 문자열로 이루어진 URL 경로입니다.
            output (str): 응답형식을 지정하며 생략가능합니다.
                생략할 경우 요청헤더의 `Content-Type`을 보고 응답형식을 결정하며 기본 값은 `xml`입니다.
            kwargs (dict): URL parameter로 변환 될 객체입니다.
                `key=value, key2=value2` 형태의 인자가 `?key=value&key2=value2`처럼 변환됩니다.

        Returns:
            str: 조립된 URL 문자열을 반환합니다.
        """  # noqa
        ret = "%s/apis/%s?access_token=%s&output=%s" % (
            BASE_URL,
            path,
            self.token,
            output,
        )
        for keyname in kwargs:
            if kwargs[keyname] is None:
                continue
            ret += "&%s=%s" % (keyname, quote(u(kwargs[keyname])))
        return ret

    def blog_info(self):
        """계정에 존재하는 모든 블로그 목록 정보를 반환합니다.

        Returns:
            list: 블로그 목록
        """
        url = self.assemble_url("blog/info")
        if self.cache:
            r = self.cache.get(url, requests.get)
        else:
            r = requests.get(url)

        try:
            res = json.loads(r.text, encoding="utf-8")
        except ValueError:
            logger.debug("응답: %s" % r.text)
            raise
        else:
            if r.status_code != 200:
                raise TispoonError(
                    dotget(res, "tistory.error_message") or "예상치 못한 오류"
                )
        return dotget(res, "tistory.item.blogs")

    def default_blog(self):
        """운영 블로그 목록에서 가져온 대표(기본) 블로그 정보를 반환합니다."""
        blogs = self.blog_info()
        blog = iter(filter(lambda x: x.get("default") == "Y", blogs))
        return next(blog)

    @property
    def blogs(self):
        """운영 블로그 목록을 반환합니다. `blog_info` 메서드의 줄임 표현 입니다."""
        return self.blog_info()

    def _post_list(self, page=1, blog_name=None):
        url = self.assemble_url(
            "post/list", blogName=blog_name or self.blog, page=page
        )
        if self.cache:
            r = self.cache.get(url, requests.get)
        else:
            r = requests.get(url)

        if r.status_code != 200:
            raise TispoonError("예상치 못한 오류 발생")

        try:
            res = json.loads(r.text)
        except ValueError:
            logger.debug("응답: %s" % r.text)
            raise
        else:
            if r.status_code != 200:
                raise TispoonError(
                    dotget(res, "tistory.error_message") or "예상치 못한 오류 발생"
                )
        return res

    def post_list(self, page=1):
        """글 목록을 가져옵니다.

        Args:
            page (int): 페이지를 지정합니다.

        Returns:
            list: 글 목록입니다.
        """
        return dotget(
            self._post_list(blog_name=self.blog, page=page),
            "tistory.item.posts",
        )

    def post_count(self):
        """작성된 글의 갯수를 가져옵니다.

        Returns:
            int: 작성된 글의 갯수
        """
        return int(
            dotget(
                self._post_list(blog_name=self.blog), "tistory.item.totalCount"
            )
        )

    @property
    def posts(self):
        """작성된 게시글의 목록을 제너레이터로 반환합니다.

        Yields:
            게시글의 정보를 반환합니다.
        """
        posts = []
        count = 0
        page = 0
        for _ in range(self.post_count()):
            if not count:
                page += 1
                res = self._post_list(page=page)
                count = int(dotget(res, "tistory.item.count"))
                posts.extend(dotget(res, "tistory.item.posts"))
            count -= 1
            yield posts.pop(0)

    def find_post(self, title=None, slogan=None):
        """지정된 속성과 일치하는 게시글을 찾아서 반환합니다."""
        for post in self.posts:
            if slogan:

                def remove_prefix(url):
                    return re.sub(r"^(\.{0,2}\/)*", "", url)

                post_url = post.get("postUrl")
                logger.debug("post url: %s" % post_url)
                if not post_url:
                    raise TispoonError("예상치 못한 오류 발생")

                post_path = urlparse(post_url).path
                if not post_path:
                    raise TispoonError("예상치 못한 오류 발생")

                post_slogan = re.sub(r"^/?entry/", "", post_path)
                simplified_slogan = remove_prefix(post_slogan.replace("-", ""))
                logger.debug("simplified slogan: %s" % simplified_slogan)

                clean_slogan = remove_prefix(slogan)
                if simplified_slogan.startswith(quote(u(clean_slogan))):
                    logger.debug("포스팅 발견! -> %s" % u(post.get("title")))
                    return post

            elif title:
                if post.get("title") == title:
                    return post
        return None

    def find_posts(self, title=None, slogan=None):
        """지정된 속성과 일치하는 게시글의 목록을 반환합니다."""
        post_list = list(self.posts)
        results = []
        # TODO: Implement all features
        if title:
            results.extend(
                list(filter(lambda x: x.get("title") == title, post_list))
            )
        else:
            results = post_list
        return results

    def post_read(self, post_id=None):
        """게시글의 내용을 가져옵니다."""
        if not post_id:
            raise TispoonError("post_id가 비어있습니다.")

        url = self.assemble_url(
            "post/read", blogName=self.blog, postId=post_id
        )
        r = requests.get(url)

        try:
            res = json.loads(r.text)
        except ValueError:
            logger.debug("응답: %s" % r.text)
            raise
        else:
            if r.status_code != 200:
                raise TispoonError(
                    dotget(res, "tistory.error_message") or "예상치 못한 오류 발생"
                )
        return dotget(res, "tistory.item")

    def post_write(self, post):
        """게시글을 작성합니다."""
        url = self.assemble_url("post/write", blogName=self.blog)

        data = {
            "title": post.get("title"),
            "content": post.get("content"),
            "visibility": post.get("visibility"),
            "category": post.get("category"),
            "published": post.get("published"),
            "slogan": post.get("slogan"),
            "tag": post.get("tag"),
            "acceptComment": post.get("accept_comment"),
            "password": post.get("password"),
        }

        r = requests.post(url, data=data)

        try:
            res = json.loads(r.text)
        except ValueError:
            logger.debug("응답: %s" % r.text)
            raise
        else:
            if r.status_code != 200:
                raise TispoonError(
                    dotget(res, "tistory.error_message") or "예상치 못한 오류 발생"
                )

        return {
            "post_id": dotget(res, "tistory.postId"),
            "url": dotget(res, "tistory.url"),
        }

    def post_modify(self, post_id, post):
        """게시글을 수정합니다."""
        url = self.assemble_url(
            "post/modify", blogName=self.blog, postId=post_id,
        )

        data = {
            "title": post.get("title"),
            "content": post.get("content"),
            "visibility": post.get("visibility"),
            "category": post.get("category"),
            "published": post.get("published"),
            "slogan": post.get("slogan"),
            "tag": post.get("tag"),
            "acceptComment": post.get("accept_comment"),
            "password": post.get("password"),
        }

        r = requests.post(url, data=data)

        try:
            res = json.loads(r.text)
        except ValueError:
            logger.debug("응답: %s" % r.text)
            raise
        else:
            if r.status_code != 200:
                raise TispoonError(
                    dotget(res, "tistory.error_message") or "예상치 못한 오류 발생"
                )

        return {
            "post_id": dotget(res, "tistory.postId"),
            "url": dotget(res, "tistory.url"),
        }

    def post_attach(self, path=None, fp=None):
        """첨부파일을 업로드합니다."""
        if not path and not fp:
            raise TispoonError("path 혹은 fp가 필요합니다.")
        files = {"uploadedfile": fp or open(path, "rb")}

        url = self.assemble_url("post/attach", blogName=self.blog)

        r = requests.post(url, files=files)

        try:
            res = json.loads(r.text)
        except ValueError:
            logger.debug("응답: %s" % r.text)
            raise
        else:
            if r.status_code != 200:
                raise TispoonError(
                    dotget(res, "tistory.error_message") or "예상치 못한 오류 발생"
                )

        return {
            "url": dotget(res, "tistory.url"),
            "replacer": dotget(res, "tistory.replacer"),
        }

    def post_demo(self):
        """데모 게시글을 작성합니다."""
        post = self.markdown_to_post(DEMO_MARKDOWN)
        return self.post_write(post)

    def json_to_post(self, json_):
        """`json` 파일을 게시글 객체로 변환합니다."""
        post = json.loads(json_)
        return post

    def markdown_to_post(self, md):
        """`markdown` 파일을 게시글 객체로 변환합니다.

        게시글의 첫 부분이 `---` 로 시작할 경우
        해당 영역을 `yaml`형식으로 파싱하여 메타데이터로서 사용합니다.
        """
        parsed = markdown(md)
        post = parsed.metadata or {}
        post["content"] = parsed
        return post

    def post_url_to_slogan(self, post_url):
        """포스트 주소에서 slogan을 추출하여 변환, 반환합니다."""
        unquoted_url = unquote(post_url)
        slogan_match = re.match(r"https?\:\/\/.+\/entry\/(.+)", unquoted_url)
        if slogan_match:
            return slogan_match.group(1)
        return ""

    def post_json(self, json_):
        """`json`파일을 게시글로 작성합니다."""
        return self.post_write(self.json_to_post(json_))

    def post_markdown(self, md):
        """`markdown`파일을 게시글로 작성합니다.

        다음과 같은 경우에 게시글을 새로 작성하기 보다 업데이트 합니다.
          - 만약 포스팅 아이디가 게시글의 메타데이터에 존재하는 경우
          - 만약 같은 포스팅 URL(Slogan)이 게시글에 존재하는 경우
        """
        logger.debug("마크다운 파일을 포스팅합니다.")

        post = self.markdown_to_post(md)
        post_id = post.get("id") or post.get("postId")
        founded = self.find_post(slogan=post.get("slogan"))
        if post_id or founded:
            if founded:
                logger.info("동일한 포스팅 발견")
                logger.info(" " * 2 + "- id: %s" % founded.get("id"))
                logger.info(" " * 2 + "- title: %s" % founded.get("title"))
                if not post_id:
                    post_id = founded.get("id")
            logger.info("포스팅 업데이트 중...")
            return self.post_modify(post_id, post)
        return self.post_write(post)

    def post_file_path(self, file_path):
        """파일 경로를 읽어 게시글로 작성합니다."""
        if file_path == "-":
            content = sys.stdin.read()
            if content.startswith("{"):
                return self.post_json(content)
            return self.post_markdown(content)
        else:
            with open(file_path, "r") as f:
                content = f.read()
            if file_path.endswith(".json"):
                return self.post_json(content)
            return self.post_markdown(content)

    def category_list(self):
        """블로그 카테고리 목록을 가져옵니다."""
        url = self.assemble_url("category/list", blogName=self.blog)

        if self.cache:
            r = self.cache.get(url, requests.get)
        else:
            r = requests.get(url)
        try:
            res = json.loads(r.text)
        except ValueError:
            logger.debug("응답: %s" % r.text)
            raise
        else:
            if r.status_code != 200:
                raise TispoonError(
                    dotget(res, "tistory.error_message") or "예상치 못한 오류 발생"
                )

        return dotget(res, "tistory.item.categories")

    def find_category(self, id=None, name=None, label=None, parent=None):
        if id is not None:
            pass
        return self.find_categories(name=name, label=label, parent=parent)[:1]

    def find_categories(self, id=None, name=None, label=None, parent=None):
        categories = self.category_list()
        results = []

        if parent:
            same_parents = filter(
                lambda x: x.get("parent") in parent, categories
            )
            if name:
                results.extend(
                    list(filter(lambda x: x.get("name") in name, same_parents))
                )
            else:
                results.extend(list(same_parents))
        elif label:
            results.extend(
                list(filter(lambda x: x.get("label") in label, categories))
            )
        elif name:
            results.extend(
                list(filter(lambda x: x.get("name") in name, categories))
            )
        else:
            results = categories
        return results

    def comment_newest(self, page=1, count=10):
        """최신 댓글을 가져옵니다."""
        url = self.assemble_url(
            "comment/newest", blogName=self.blog, page=page, count=count
        )
        if self.cache:
            r = self.cache.get(url, requests.get)
        else:
            r = requests.get(url)

        try:
            res = json.loads(r.text)
        except ValueError:
            logger.debug("응답: %s" % r.text)
            raise
        else:
            if r.status_code != 200:
                raise TispoonError(
                    dotget(res, "tistory.error_message") or "예상치 못한 오류 발생"
                )

        return dotget(res, "tistory.item.comments.comment")

    def comment_list(self, post_id):
        """댓글 목록을 가져옵니다."""
        url = self.assemble_url(
            "comment/list", blogName=self.blog, postId=post_id
        )
        r = requests.get(url)
        try:
            res = json.loads(r.text)
        except ValueError:
            logger.debug("응답: %s" % r.text)
            raise
        else:
            if r.status_code != 200:
                raise TispoonError(
                    dotget(res, "tistory.error_message") or "예상치 못한 오류 발생"
                )

        if r.status_code != 200:
            raise TispoonError(
                dotget(res, "tistory.error_message") or "예상치 못한 오류 발생"
            )
        logger.debug("response: %s" % res)
        if dotget(res, "tistory.item.totalCount") == "0":
            return []

        return dotget(res, "tistory.item.comments")

    def comment_write(self, post_id, comment):
        """댓글을 작성합니다."""
        url = self.assemble_url("comment/write", blogName=self.blog,)

        data = {
            "postId": post_id,
            "parentId": comment.get("parent_id"),
            "content": comment.get("content"),
            "secret": comment.get("secret"),
        }

        r = requests.post(url, data=data)

        try:
            res = json.loads(r.text)
        except ValueError:
            logger.debug("응답: %s" % r.text)
            raise
        else:
            if r.status_code != 200:
                raise TispoonError(
                    dotget(res, "tistory.error_message") or "예상치 못한 오류 발생"
                )

        return dotget(res, "tistory.commentUrl")

    def comment_modify(self, post_id, comment):
        """댓글을 수정합니다."""
        url = self.assemble_url("comment/modify", blogName=self.blog,)

        data = {
            "postId": post_id,
            "parentId": comment.get("parent_id"),
            "commentId": comment.get("comment_id"),
            "content": comment.get("content"),
            "secret": comment.get("secret"),
        }
        r = requests.post(url, data=data)

        try:
            res = json.loads(r.text)
        except ValueError:
            logger.debug("응답: %s" % r.text)
            raise
        else:
            if r.status_code != 200:
                raise TispoonError(
                    dotget(res, "tistory.error_message") or "예상치 못한 오류 발생"
                )

        return dotget(res, "tistory.commentUrl")

    def comment_delete(self, post_id, comment_id):
        """댓글을 삭제합니다."""
        url = self.assemble_url(
            "comment/delete",
            blogName=self.blog,
            postId=post_id,
            commentId=comment_id,
        )
        r = requests.post(url)
        try:
            res = json.loads(r.text)
        except ValueError:
            logger.debug("응답: %s" % r.text)
            raise
        else:
            if r.status_code != 200:
                raise TispoonError(
                    dotget(res, "tistory.error_message") or "예상치 못한 오류 발생"
                )
                return False
        return True


def _info_command(args):
    """블로그 정보 API를 관리하는 명령어 함수 입니다."""
    client = Tispoon(args)
    print("blogs:")
    for blog in client.blogs:
        print(
            textwrap.dedent(
                """\
            - name: %s
              title: %s
              url: %s"""
                % (blog.get("name"), blog.get("title"), blog.get("url"))
            )
        )
    if args.post_id:
        print("posts:")
        for post_id in args.post_id:
            post = client.post_read(post_id)
            # url
            print("- url: %s" % post.get("postUrl"))
            # id
            print("  id: %s" % post.get("id"))
            # title
            print("  title: %s" % post.get("title"))
            # content
            content = post.get("content")
            print("  content: |")
            print("\n".join(map(lambda l: " " * 4 + l, content.split("\n"))))
            # tags
            tags = post.get("tags")
            if tags:
                print("  tags:")
                print(
                    "\n".join(
                        map(lambda t: " " * 2 + " - " + t, tags.get("tag"))
                    )
                )


def _post_command(args):
    """블로그 글을 관리하는 API의 명령어 함수 입니다."""
    client = Tispoon(args)
    files = args.file or [] + args.files

    def transform(url):
        if not args.encode_url:
            return unquote(url)
        return url

    if args.list:
        for post in client.posts:
            print(
                textwrap.dedent(
                    """\
                    - title: %s
                      id: %s
                      url: %s"""
                    % (
                        post.get("title"),
                        post.get("id"),
                        transform(post.get("postUrl")),
                    )
                )
            )
        return
    for file_path in files:
        client.post_file_path(file_path)


def _category_command(args):
    """카테고리를 관리하는 API의 명령어 함수 입니다."""
    client = Tispoon(args)
    categories = client.find_categories(name=args.name, label=args.label)
    for category in categories:
        print(
            textwrap.dedent(
                """\
            - name: %s
              id: %s"""
                % (category.get("name"), category.get("id"))
            )
        )


def _comment_command(args):
    """블로그 댓글을 관리하는 API의 명령어 함수 입니다."""
    client = Tispoon(args)
    if args.delete:
        client.comment_delete(args.post_id, args.comment_id)
        print("삭제완료: %d" % args.comment_id)
        return

    if args.list:
        if args.new:
            func = client.comment_newest
        else:
            func = client.comment_list

        comments = func(args.post_id)
        for comment in comments:
            print(
                textwrap.dedent(
                    """\
                - id: %s
                  name: %s
                  comment: %s"""
                    % (
                        comment.get("id"),
                        comment.get("name"),
                        comment.get("comment"),
                    )
                )
            )
        return
    if args.content:
        content = args.content
    else:
        content = sys.stdin.read()
    url = client.comment_write(args.post_id, {"content": content})
    print("url: %s" % url)


def _import_command(args):
    client = Tispoon(args)
    if args.blog:
        blog_name = args.blog
    else:
        default_blog = client.default_blog()
        blog_name = default_blog.get("name")
    # 옵션이 지정되어 있다면 덮어씁니다.
    if args.output_dir:
        blog_name = args.output_dir
    logger.debug(blog_name)
    try:
        os.makedirs(blog_name)
    except OSError:
        # Re-raise error if exists file is not directory
        if not os.path.isdir(blog_name):
            raise
        pass
    for post in client.posts:
        slogan = client.post_url_to_slogan(post.get("postUrl"))
        if slogan:
            identifier = slogan
        else:
            identifier = post.get("id")
        file_name = "%s.md" % identifier
        dest = os.path.join(blog_name, file_name)
        if os.path.exists(dest):
            continue
        print(post.get("title"), "다운로드 중...")

        post_detail = client.post_read(post.get("id"))
        attributes = post_detail.keys()
        except_attr = [
            "categoryId",
            "content",
            "comments",
            "tags",
            "trackbacks",
            "url",
            "visibility",
            "slogan",
            "secondaryUrl",
            "postUrl",
        ]
        content = ""
        if attributes:
            content += "---\n"
            # 자동으로 속성추가
            for attribute in attributes:
                if attribute in except_attr:
                    continue
                content += "%s: %s\n" % (attribute, post_detail.get(attribute))
            # 수동으로 속성추가
            logger.debug("post_detail: %r" % post_detail)
            visibilities = [
                VISIBILITY_PRIVATE,
                VISIBILITY_PROTECTED,
                VISIBILITY_PUBLISHED,
            ]
            visibility = post_detail.get("visibility")
            for values in visibilities:
                if int(visibility) in values:
                    post_visibility = values[0]
                    break
            else:
                post_visibility = int(visibility)
            content += "visibility: %s\n" % post_visibility
            tags = post_detail.get("tags")
            if tags:
                content += "tag: %s\n" % ", ".join(tags.get("tag"))
            if slogan:
                content += "slogan: /%s\n" % slogan
            content += "---\n\n"
        content += post_detail.get("content")
        content += "\n"
        logger.debug("content: %s" % content)
        with open(dest, "w") as f:
            f.write(u(content))
    print("불러오기가 완료되었습니다!")


def main():
    import argparse  # noqa

    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument("--token", "-t", help="인증 토큰을 설정합니다.")
    common_parser.add_argument(
        "--client-id", "-u", help="Open API의 client id값을 설정합니다."
    )
    common_parser.add_argument(
        "--client-secret", "-p", help="Open API의 client secret값을 설정합니다."
    )
    common_parser.add_argument(
        "--blog",
        "-b",
        help="블로그 이름을 설정합니다. 예) `xvezda.tistory.com` 의 경우 `xvezda`",
    )
    common_parser.add_argument(
        "--verbose",
        "-v",
        action="count",
        default=0,
        help="로그의 정보량을 설정합니다. `v`의 갯수에 따라 정보량이 달라집니다.",
    )
    common_parser.add_argument(
        "--version",
        "-V",
        action="version",
        version=VERSION,
        help="버전 정보를 출력하고 종료합니다.",
    )

    parser = argparse.ArgumentParser(parents=[common_parser])
    subparsers = parser.add_subparsers(dest="command")

    info_parser = subparsers.add_parser(
        "info", parents=[common_parser], help="자신의 블로그 정보를 가져오는 API 입니다."
    )
    info_parser.add_argument(
        "--post-id", "-i", action="append", help="정보를 가져올 포스트 아이디를 설정합니다."
    )
    info_parser.set_defaults(func=_info_command)

    post_parser = subparsers.add_parser(
        "post", parents=[common_parser], help="블로그 글을 관리하는 API 입니다."
    )
    post_parser.add_argument(
        "--list", "-l", action="store_true", help="포스트 목록을 가져옵니다."
    )
    post_parser.add_argument(
        "--encode-url",
        "-e",
        action="store_true",
        help="포스트 주소를 URL 인코딩 형태로 보여줍니다.",
    )
    # NOTE: Tistory API v1 does not support deleting post.. WHAT?
    # post_parser.add_argument("--delete", "-d", action="store_true")
    post_parser.add_argument(
        "--file",
        "-f",
        action="append",
        help="마크다운 또는 JSON 파일의 경로를 설정합니다. "
        "`-` 으로 설정하여 stdin으로 부터 읽어올 수 있습니다.",
    )
    post_parser.add_argument(
        "--demo", "-D", action="store_true", help="블로그에 데모 포스팅을 작성합니다.",
    )
    post_parser.add_argument("files", nargs="*")
    post_parser.set_defaults(func=_post_command)

    category_parser = subparsers.add_parser(
        "category", parents=[common_parser], help="블로그 카테고리를 정보를 가져오는 API 입니다."
    )
    category_parser.add_argument(
        "--name", "-n", action="append", default=[], help="카테고리 이름"
    )
    category_parser.add_argument(
        "--label", "-l", action="append", default=[], help="카테고리 라벨"
    )
    category_parser.add_argument(
        "--id", "-i", action="append", default=[], help="카테고리 아이디"
    )
    category_parser.add_argument(
        "--parent", "-m", action="append", default=[], help="부모 카테고리 아이디"
    )
    category_parser.set_defaults(func=_category_command)

    comment_parser = subparsers.add_parser(
        "comment", parents=[common_parser], help="블로그 댓글을 관리하는 API 입니다."
    )
    comment_parser.add_argument(
        "--list", "-l", action="store_true", help="댓글 목록을 가져옵니다."
    )
    comment_parser.add_argument(
        "--new", "-n", action="store_true", help="최근 댓글 목록을 가져옵니다."
    )
    comment_parser.add_argument(
        "--delete", "-d", action="store_true", help="댓글을 삭제합니다."
    )
    comment_parser.add_argument(
        "--parent-id", "-m", type=str, help="대댓글을 작성할 댓글의 아이디."
    )
    comment_parser.add_argument(
        "--comment-id", "-i", type=str, help="댓글의 아이디."
    )
    comment_parser.add_argument(
        "--post-id", "-A", required=True, type=str, help="댓글을 작성할 포스트의 아이디."
    )
    comment_parser.add_argument(
        "content",
        nargs="?",
        type=str,
        help="댓글의 내용. 설정하지 않으면 stdin으로 부터 읽어옵니다.",
    )
    comment_parser.set_defaults(func=_comment_command)

    import_parser = subparsers.add_parser(
        "import", parents=[common_parser], help="게시된 게시글을 불러오는 명령어입니다."
    )
    import_parser.add_argument(
        "--output-dir",
        "-O",
        help="게시글을 저장할 디렉토리를 설정합니다. " "기본값은 블로그의 이름을 사용합니다.",
    )
    import_parser.set_defaults(func=_import_command)

    args = parser.parse_args()

    try:
        # dotenv 모듈이 설치된 경우 `.env` 파일로 작성된 환경변수를 자동으로 읽어옵니다.
        from dotenv import load_dotenv, find_dotenv  # noqa

        load_dotenv(find_dotenv(usecwd=True), verbose=(args.verbose > 0))
    except ImportError:
        pass

    # 로그가 작성되는 단계를 설정합니다.
    if args.verbose == 1:
        logger.setLevel(logging.INFO)
    elif args.verbose == 2:
        logger.setLevel(logging.DEBUG)

    if not args.command:
        parser.error("too few arguments")

    try:
        args.func(args)
    except Exception as err:
        if args.verbose > 0:
            # 오류 발생시 로그의 정보량 단계가 지정된 경우 콜스택 정보를 보여줍니다.
            print(traceback.format_exc(), file=sys.stderr)
        parser.error(u(err))
        parser.print_help()


if __name__ == "__main__":
    main()
