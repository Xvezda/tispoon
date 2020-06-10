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


import re
import os
import sys
import json
import time
import socket
import hashlib
import textwrap

import traceback
import logging

# logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

import requests
import six
from six.moves.urllib.parse import quote, urlparse
from markdown2 import markdown as _markdown
import yaml


def u(text):
    if sys.version_info[0] < 3:
        return unicode(text).encode("utf-8")
    return text


def markdown(*args, **kwargs):
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


AUTHOR = "Xvezda"
AUTHOR_EMAIL = "xvezda@naver.com"
VERSION = "1.0.2"
API_VERSION = "v1"
BASE_URL = "https://www.tistory.com"
PORT = int(os.getenv("TISPOON_PORT", 9638))
REDIR_URL = "http://127.0.0.1:%s/callback" % (PORT,)
TTL_DEF = int(os.getenv("TISPOON_TTL", 600))
TTL_INF = -1

VISIBILITY_PRIVATE = 0
VISIBILITY_PROTECTED = 1
VISIBILITY_PUBLISHED = 3

COMMENT_ACCEPT = 0
COMMENT_CLOSED = 1

COMMENT_SECRET = 1
COMMENT_PUBLIC = 0


DEMO_MARKDOWN = """\
---
title: Tispoon 테스트
visibility: 1
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
    context = obj
    for token in name.split("."):
        context = context.get(token)
    return context


class CacheItem(object):
    def __init__(self, value):
        self.timestamp = time.time()
        self.value = value


class BaseCache(object):
    def __init__(self, hashing="md5"):
        self.hashing = lambda x: getattr(hashlib, hashing)(x.encode()).hexdigest()
        self.items = {}

    def set(self, name, value):
        self.items[self.hashing(name)] = CacheItem(value)

    def get(self, name, fallback=None):
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
    pass


class TispoonCache(BaseCache):
    TTL = TTL_DEF


class TispoonError(Exception):
    pass


class Tispoon(TispoonBase):
    def __init__(self, token="", blog="", cache=None):
        self._token = token or os.getenv("TISPOON_TOKEN")
        self._blog = blog or os.getenv("TISPOON_BLOG")
        self._cache = cache or TispoonCache()

    def auth(self, app_id="", app_secret=""):
        if self.token:
            logger.debug("Token already exists")
            return True

        if not app_id:
            app_id = os.getenv("TISPOON_APP_ID")
        if not app_secret:
            app_secret = os.getenv("TISPOON_APP_SECRET")

        if not app_id or not app_secret:
            raise ValueError("app_id, app_secret must be provided")

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
        except webbrowser.Error as err:
            print("Visit following link to grant access", file=sys.stderr)
            print(url, file=sys.stderr)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("", 9638))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.listen(1)
        conn, addr = s.accept()

        prev_state = state
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
        res = json.loads(r.text, encoding="utf-8")
        if r.status_code != 200:
            raise TispoonError(
                dotget(res, "tistory.error_message") or "unexpected error"
            )
        return res.get("tistory").get("item").get("blogs")

    def default_blog(self):
        blogs = self.blog_info()
        blog = filter(lambda x: x.get("default") == "Y", blogs)
        return six.next(blog)

    @property
    def blogs(self):
        return self.blog_info()

    def _post_list(self, page=1):
        url = self.assemble_url("post/list", blogName=self.blog, page=page)
        if self.cache:
            r = self.cache.get(url, requests.get)
        else:
            r = requests.get(url)
        res = json.loads(r.text)
        if r.status_code != 200:
            raise TispoonError(
                dotget(res, "tistory.error_message") or "unexpected error"
            )
        return res

    def post_list(self, page=1):
        return dotget(self._post_list(self.blog, page), "tistory.item.posts")

    def post_count(self):
        return int(dotget(self._post_list(self.blog), "tistory.item.totalCount"))

    @property
    def posts(self):
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
        if not post_id:
            raise TispoonError("post_id is empty")

        url = self.assemble_url("post/read", blogName=self.blog, postId=post_id)

        r = requests.get(url)
        res = json.loads(r.text)
        if r.status_code != 200:
            raise TispoonError(
                dotget(res, "tistory.error_message") or "unexpected error"
            )
        return dotget(res, "tistory.item")

    def post_write(self, post):
        url = self.assemble_url(
            "post/write",
            blogName=self.blog,
            title=post.get("title"),
            content=post.get("content"),
            visibility=post.get("visibility"),
            category=post.get("category"),
            published=post.get("published"),
            slogan=post.get("slogan"),
            tag=post.get("tag"),
            acceptComment=post.get("accept_comment"),
            password=post.get("password"),
        )
        r = requests.post(url)
        res = json.loads(r.text)
        if r.status_code != 200:
            raise TispoonError(
                dotget(res, "tistory.error_message") or "unexpected error"
            )

        return {
            "post_id": dotget(res, "tistory.postId"),
            "url": dotget(res, "tistory.url"),
        }

    def post_modify(self, post_id, post):
        url = self.assemble_url(
            "post/modify",
            blogName=self.blog,
            postId=post_id,
            title=post.get("title"),
            content=post.get("content"),
            visibility=post.get("visibility"),
            category=post.get("category"),
            published=post.get("published"),
            slogan=post.get("slogan"),
            tag=post.get("tag"),
            acceptComment=post.get("accept_comment"),
            password=post.get("password"),
        )
        r = requests.post(url)
        res = json.loads(r.text)
        if r.status_code != 200:
            raise TispoonError(
                dotget(res, "tistory.error_message") or "unexpected error"
            )

        return {
            "post_id": dotget(res, "tistory.postId"),
            "url": dotget(res, "tistory.url"),
        }

    def post_attach(self, path=None, fp=None):
        if not path and not fp:
            raise TispoonError("path or fp required")
        files = {"uploadedfile": fp or open(path, "rb")}

        url = self.assemble_url("post/attach", blogName=self.blog)

        r = requests.post(url, files=files)
        res = json.loads(r.text)
        if r.status_code != 200:
            raise TispoonError(
                dotget(res, "tistory.error_message") or "unexpected error"
            )

        return {
            "url": dotget(res, "tistory.url"),
            "replacer": dotget(res, "tistory.replacer"),
        }

    def post_demo(self):
        post = self.markdown_to_post(DEMO_MARKDOWN)
        return self.post_write(post)
        # return self.post_write(
        #     {
        #         "title": "Tispoon 테스트",
        #         "content": markdown(DEMO_MARKDOWN),
        #         "visibility": VISIBILITY_PUBLISHED,
        #     }
        # )

    def markdown_to_post(self, md):
        metadata = re.match("""^---\s(.+?)\s---""", md, flags=re.S)
        if metadata:
            post = yaml.load(metadata.group(1), Loader=yaml.BaseLoader)
            content = re.sub("""^---\s(.+?)\s---\s*""", "", md, flags=re.S)
            post["content"] = markdown(content)
            return post
        return {"content": markdown(md)}

    def category_list(self):
        url = self.assemble_url("category/list", blogName=self.blog)

        if self.cache:
            r = self.cache.get(url, requests.get)
        else:
            r = requests.get(url)
        res = json.loads(r.text)
        if r.status_code != 200:
            raise TispoonError(
                dotget(res, "tistory.error_message") or "unexpected error"
            )

        return dotget(res, "tistory.item.categories")

    def comment_newest(self, page=1, count=10):
        url = self.assemble_url(
            "comment/newest", blogName=self.blog, page=page, count=count
        )
        if self.cache:
            r = self.cache.get(url, requests.get)
        else:
            r = requests.get(url)
        res = json.loads(r.text)
        if r.status_code != 200:
            raise TispoonError(
                dotget(res, "tistory.error_message") or "unexpected error"
            )

        return dotget(res, "tistory.item.comments.comment")

    def comment_list(self, post_id):
        url = self.assemble_url("comment/list", blogName=self.blog, postId=post_id)
        r = requests.get(url)
        res = json.loads(r.text)
        if r.status_code != 200:
            raise TispoonError(
                dotget(res, "tistory.error_message") or "unexpected error"
            )

        return dotget(res, "tistory.item.comments.comment")

    def comment_write(self, post_id, comment):
        url = self.assemble_url(
            "comment/write",
            blogName=self.blog,
            postId=post_id,
            parentId=comment.get("parent_id"),
            content=comment.get("content"),
            secret=comment.get("secret"),
        )
        r = requests.post(url)
        res = json.loads(r.text)
        if r.status_code != 200:
            raise TispoonError(
                dotget(res, "tistory.error_message") or "unexpected error"
            )

        return dotget(res, "tistory.commentUrl")

    def comment_modify(self, post_id, comment):
        url = self.assemble_url(
            "comment/modify",
            blogName=self.blog,
            postId=post_id,
            parentId=comment.get("parent_id"),
            commentId=comment.get("comment_id"),
            content=comment.get("content"),
            secret=comment.get("secret"),
        )
        r = requests.post(url)
        res = json.loads(r.text)
        if r.status_code != 200:
            raise TispoonError(
                dotget(res, "tistory.error_message") or "unexpected error"
            )

        return dotget(res, "tistory.commentUrl")

    def comment_delete(self, post_id, comment):
        url = self.assemble_url(
            "comment/delete",
            blogName=self.blog,
            postId=post_id,
            commentId=comment.get("comment_id"),
        )
        r = requests.post(url)
        res = json.loads(r.text)
        if r.status_code != 200:
            # raise TispoonError(res.get('error_message') or 'unexpected error')
            logger.error(dotget(res, "tistory.error_message") or "unexpected error")
            return False

        return True


def main():
    try:
        import dotenv

        dotenv.load_dotenv()
    except ImportError:
        pass

    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--token", "-t")
    parser.add_argument("--client-id", "-u")
    parser.add_argument("--client-secret", "-p")
    parser.add_argument(
        "--list", "-l", action="store_true", help="list blog informations"
    )
    parser.add_argument("--file", "-f", action="append", help="markdown file to post")
    parser.add_argument(
        "--blog", "-b", help="specify blog name. (i.e. [blogName].tistory.com)"
    )
    parser.add_argument(
        "--demo", "-d", action="store_true", help="posting demo article to blog."
    )
    parser.add_argument("--verbose", "-v", action="count", default=0)
    parser.add_argument("--version", "-V", action="version", version=VERSION)
    args = parser.parse_args()

    try:
        t = Tispoon(token=args.token, blog=args.blog)
        if args.demo:
            t.post_demo()
        elif args.file:
            for mdfile in args.file:
                print("Posting %s..." % mdfile)
                with open(mdfile, "r") as f:
                    t.post_write(t.markdown_to_post(f.read()))
        else:
            for blog in t.blogs:
                print(
                    textwrap.dedent(
                        """\
                    - name: %s
                      title: %s
                      url: %s
                """
                        % (blog.get("name"), blog.get("title"), blog.get("url"))
                    )
                )
    except Exception as err:
        if args.verbose > 0:
            print(traceback.format_exc(), file=sys.stderr)
        parser.error(u(err))
        parser.print_help()


if __name__ == "__main__":
    main()
