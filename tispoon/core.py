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

import requests
import six
from six.moves.urllib.parse import quote, urlparse
from markdown2 import markdown as _markdown
import yaml

from .version import VERSION

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())


def u(text):
    if sys.version_info[0] < 3:
        return unicode(text).encode("utf-8")  # noqa
    return text


def markdown(*args, **kwargs):
    """기존 마크다운 모듈을 깃허브 스타일로 바꿔주는 wrapper 입니다."""
    try:
        extras = kwargs.pop("extras")
    except KeyError:
        extras = []

    extras.extend(
        [
            "target-blank-links",
            "spoiler",
            "nofollow",
            "fenced-code-blocks",
            "code-friendly",
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
VISIBILITY_PRIVATE = 0
VISIBILITY_PROTECTED = 1
VISIBILITY_PUBLISHED = 3

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


def dotget(obj, name):
    """`.`으로 연결된 객체접근 표현식을 parsing, 반복하여 반환하는 유틸리티 함수입니다."""
    context = obj
    for token in name.split("."):
        context = context.get(token)
    return context


class CacheItem(object):
    """캐싱에 사용되는 아이템의 일반화 된 추상클래스 입니다."""

    def __init__(self, value):
        self.timestamp = time.time()
        self.value = value


class BaseCache(object):
    """캐시된 아이템을 관리하는 관리객체의 기반 클래스입니다."""

    def __init__(self, hashing="md5"):
        self.hashing = lambda x: getattr(
            hashlib, hashing)(x.encode()).hexdigest()
        self.items = {}

    def set(self, name, value):
        """값을 `CacheItem` 클래스를 사용하여 캐싱합니다."""
        self.items[self.hashing(name)] = CacheItem(value)

    def get(self, name, fallback=None):
        """캐시된 값을 반환하는 매서드함수 입니다.

        `fallback` 콜백함수가 정의된 경우 캐시된 객체가 없거나, 캐시 유효기간(TTL)이 만료된 경우
        `name`을 인자로 호출하여 반환된 값을 캐싱하고, 반환합니다.
        """
        item = self.items.get(self.hashing(name))
        if not item:
            if fallback:
                logger.debug("Retrieving from fallback: %s" % (name,))
                item = fallback(name)
                self.set(name, item)
                return item
            return

        if self.TTL != TTL_INF and time.time() - item.timestamp >= self.TTL:
            logger.debug("Cache expired: %s" % (name,))
            del self.items[self.hashing(name)]
            if fallback:
                logger.debug("Retrieving from fallback: %s" % (name,))
                item = fallback(name)
                self.set(name, item)
                return item
            return
        logger.debug("Retrieving from cache: %s" % (name,))
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

    def __init__(self, token="", blog="", cache=None):
        self._token = token or os.getenv("TISPOON_TOKEN")
        self._blog = blog or os.getenv("TISPOON_BLOG")
        self._cache = cache or TispoonCache()

    def auth(self, app_id="", app_secret=""):
        """토큰이 없는 경우, API로부터 토큰을 새로 발급하는 매서드함수 입니다."""
        if self.token:
            logger.debug("Token already exists")
            return True

        if not app_id:
            app_id = os.getenv("TISPOON_APP_ID")
        if not app_secret:
            app_secret = os.getenv("TISPOON_APP_SECRET")

        if not app_id or not app_secret:
            raise ValueError("app_id, app_secret must be provided")

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
            print("Visit following link to grant access", file=sys.stderr)
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
                logger.debug("Request is invalid")
                return False
            code = re.search(
                r"^GET /[^\?]*\?.*&?code=([^&]*).* HTTP/\d\.\d", req, re.M
            ).group(1)
            state = re.search(
                r"^GET /[^\?]*\?.*&?state=([^&]*).* HTTP/\d\.\d", req, re.M
            ).group(1)
        except AttributeError:
            logger.debug("Requirements not satisfied")
            return False
        finally:
            conn.send(b"HTTP/1.1 200 OK\r\n")
            conn.send(b"Content-Length: 0\r\n")
            conn.send(b"Connection: close\r\n")
            conn.send(b"\r\n")
            conn.close()
            s.close()

        if prev_state != state:
            logger.debug("Invalid state integrity")
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
            logger.debug("Fail to fetch access token")
            return False

        self.token = token
        return True

    @property
    def token(self):
        return self._token

    @token.setter
    def token(self, value):
        if type(value) is not str:
            raise ValueError("value must be type of str")
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
            raise ValueError("value must be type of str")
        self._blog = value

    @property
    def cache(self):
        return self._cache

    @cache.setter
    def cache(self, value):
        self._cache = value

    def assemble_url(self, path, output="json", **kwargs):
        """`kwargs`를 URL parameter 형식으로 변환하여 API 요청에 적합하도록 조립하는 함수입니다."""
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
        url = self.assemble_url("blog/info")
        if self.cache:
            r = self.cache.get(url, requests.get)
        else:
            r = requests.get(url)

        try:
            res = json.loads(r.text, encoding="utf-8")
        except ValueError:
            logger.debug("response: %s" % r.text)
            raise
        else:
            if r.status_code != 200:
                raise TispoonError(
                    dotget(res, "tistory.error_message") or "unexpected error"
                )
        return res.get("tistory").get("item").get("blogs")

    def default_blog(self):
        """운영 블로그 목록에서 가져온 대표(기본) 블로그."""
        blogs = self.blog_info()
        blog = iter(filter(lambda x: x.get("default") == "Y", blogs))
        return six.next(blog)

    @property
    def blogs(self):
        """운영 블로그 목록."""
        return self.blog_info()

    def _post_list(self, page=1):
        url = self.assemble_url("post/list", blogName=self.blog, page=page)
        if self.cache:
            r = self.cache.get(url, requests.get)
        else:
            r = requests.get(url)

        try:
            res = json.loads(r.text)
        except ValueError:
            logger.debug("response: %s" % r.text)
            raise
        else:
            if r.status_code != 200:
                raise TispoonError(
                    dotget(res, "tistory.error_message") or "unexpected error"
                )
        return res

    def post_list(self, page=1):
        """글 목록을 가져옵니다."""
        return dotget(self._post_list(self.blog, page), "tistory.item.posts")

    def post_count(self):
        """작성된 글의 갯수를 가져옵니다."""
        return int(
            dotget(
                self._post_list(self.blog),
                "tistory.item.totalCount"))

    @property
    def posts(self):
        """작성된 게시글의 목록을 제너레이터로 반환합니다."""
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

    def post_read(self, post_id=None):
        """게시글의 내용을 가져옵니다."""
        if not post_id:
            raise TispoonError("post_id is empty")

        url = self.assemble_url(
            "post/read", blogName=self.blog, postId=post_id)
        r = requests.get(url)

        try:
            res = json.loads(r.text)
        except ValueError:
            raise
        else:
            if r.status_code != 200:
                raise TispoonError(
                    dotget(res, "tistory.error_message") or "unexpected error"
                )
        return dotget(res, "tistory.item")

    def post_write(self, post):
        """게시글을 작성합니다."""
        url = self.assemble_url(
            "post/write",
            blogName=self.blog
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
            logger.debug("response: %s" % r.text)
            raise
        else:
            if r.status_code != 200:
                raise TispoonError(
                    dotget(res, "tistory.error_message") or "unexpected error"
                )

        return {
            "post_id": dotget(res, "tistory.postId"),
            "url": dotget(res, "tistory.url"),
        }

    def post_modify(self, post_id, post):
        """게시글을 수정합니다."""
        url = self.assemble_url(
            "post/modify",
            blogName=self.blog,
            postId=post_id,
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
            logger.debug("response: %s" % r.text)
            raise
        else:
            if r.status_code != 200:
                raise TispoonError(
                    dotget(res, "tistory.error_message") or "unexpected error"
                )

        return {
            "post_id": dotget(res, "tistory.postId"),
            "url": dotget(res, "tistory.url"),
        }

    def post_attach(self, path=None, fp=None):
        """첨부파일을 업로드합니다."""
        if not path and not fp:
            raise TispoonError("path or fp required")
        files = {"uploadedfile": fp or open(path, "rb")}

        url = self.assemble_url("post/attach", blogName=self.blog)

        r = requests.post(url, files=files)

        try:
            res = json.loads(r.text)
        except ValueError:
            logger.debug("response: %s" % r.text)
            raise
        else:
            if r.status_code != 200:
                raise TispoonError(
                    dotget(res, "tistory.error_message") or "unexpected error"
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

        `R MarkDown`의 문법과 유사하게, 게시글의 첫 부분이 `---` 로 시작할 경우
        해당 영역을 `yaml`형식으로 파싱하여 메타데이터로서 사용합니다.
        """
        metadata = re.match(r"""^---\s(.+?)\s---""", md, flags=re.S)
        if metadata:
            post = yaml.load(metadata.group(1), Loader=yaml.BaseLoader)
            content = re.sub(r"""^---\s(.+?)\s---\s*""", "", md, flags=re.S)
            post["content"] = markdown(content)
            return post
        return {"content": markdown(md)}

    def post_json(self, json_):
        """`json`파일을 게시글로 작성합니다."""
        return self.post_write(self.json_to_post(json_))

    def post_markdown(self, md):
        """`markdown`파일을 게시글로 작성합니다."""
        return self.post_write(self.markdown_to_post(md))

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
            logger.debug("response: %s" % r.text)
            raise
        else:
            if r.status_code != 200:
                raise TispoonError(
                    dotget(res, "tistory.error_message") or "unexpected error"
                )

        return dotget(res, "tistory.item.categories")

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
            logger.debug("response: %s" % r.text)
            raise
        else:
            if r.status_code != 200:
                raise TispoonError(
                    dotget(res, "tistory.error_message") or "unexpected error"
                )

        return dotget(res, "tistory.item.comments.comment")

    def comment_list(self, post_id):
        """댓글 목록을 가져옵니다."""
        url = self.assemble_url(
            "comment/list", blogName=self.blog, postId=post_id)
        r = requests.get(url)
        try:
            res = json.loads(r.text)
        except ValueError:
            logger.debug("response: %s" % r.text)
            raise
        else:
            if r.status_code != 200:
                raise TispoonError(
                    dotget(res, "tistory.error_message") or "unexpected error"
                )

        if r.status_code != 200:
            raise TispoonError(
                dotget(res, "tistory.error_message") or "unexpected error"
            )

        return dotget(res, "tistory.item.comments.comment")

    def comment_write(self, post_id, comment):
        """댓글을 작성합니다."""
        url = self.assemble_url(
            "comment/write",
            blogName=self.blog,
        )

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
            logger.debug("response: %s" % r.text)
            raise
        else:
            if r.status_code != 200:
                raise TispoonError(
                    dotget(res, "tistory.error_message") or "unexpected error"
                )

        return dotget(res, "tistory.commentUrl")

    def comment_modify(self, post_id, comment):
        """댓글을 수정합니다."""
        url = self.assemble_url(
            "comment/modify",
            blogName=self.blog,
        )

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
            logger.debug("response: %s" % r.text)
            raise
        else:
            if r.status_code != 200:
                raise TispoonError(
                    dotget(res, "tistory.error_message") or "unexpected error"
                )

        return dotget(res, "tistory.commentUrl")

    def comment_delete(self, post_id, comment):
        """댓글을 삭제합니다."""
        url = self.assemble_url(
            "comment/delete",
            blogName=self.blog,
            postId=post_id,
            commentId=comment.get("comment_id"),
        )
        r = requests.post(url)
        try:
            res = json.loads(r.text)
        except ValueError:
            logger.debug("response: %s" % r.text)
            raise
        else:
            if r.status_code != 200:
                raise TispoonError(
                    dotget(res, "tistory.error_message") or "unexpected error"
                )
                return False

        return True


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--token", "-t")
    parser.add_argument("--client-id", "-u")
    parser.add_argument("--client-secret", "-p")
    parser.add_argument(
        "--file",
        "-f",
        action="append",
        help="markdown or json file to post, set '-' to read from stdin.",
    )
    parser.add_argument(
        "--list", "-l", action="store_true", help="list blog informations"
    )
    parser.add_argument(
        "--blog", "-b", help="specify blog name. (i.e. [blogName].tistory.com)"
    )
    parser.add_argument(
        "--demo", "-d", action="store_true",
        help="posting demo article to blog.")
    parser.add_argument("--verbose", "-v", action="count", default=0)
    parser.add_argument("--version", "-V", action="version", version=VERSION)
    parser.add_argument("files", nargs="*")
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

    try:
        t = Tispoon(token=args.token, blog=args.blog)
        if args.demo:
            t.post_demo()
        elif args.file or args.files:
            for path in args.file or [] + args.files:
                print("posting %s..." % "stdin" if path == "-" else path)
                res = t.post_file_path(path)
                print('url: %s' % res.get('url'))
        elif args.list:
            for blog in t.blogs:
                print(textwrap.dedent(
                    """\
                    - name: %s
                      title: %s
                      url: %s
                """ % (blog.get("name"), blog.get("title"), blog.get("url"))))
        else:
            parser.print_help()
    except Exception as err:
        if args.verbose > 0:
            print(traceback.format_exc(), file=sys.stderr)
        parser.error(u(err))
        parser.print_help()


if __name__ == "__main__":
    main()
