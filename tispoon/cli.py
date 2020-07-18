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
Tispoon 라이브러리를 터미널에서 직접 호출하여 사용이 가능한 커맨드라인 클라이언트입니다.
"""

import os
import sys
import textwrap

import traceback
import logging

from bs4 import BeautifulSoup

# Get version info
from .__about__ import __version__

from .core import (
    Tispoon,
    u,
    unquote,
    VISIBILITY_PRIVATE,
    VISIBILITY_PROTECTED,
    VISIBILITY_PUBLISHED,
)

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())


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

    for file_path in files:
        client.post_file_path(file_path)


def _posts_command(args):
    client = Tispoon(args)

    def transform(url):
        if not args.encode_url:
            return unquote(url)
        return url

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
        html = BeautifulSoup(post_detail.get("content"), "html.parser")
        content += html.prettify()
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
        version=__version__,
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
    post_parser.add_argument("files", nargs="+")
    post_parser.set_defaults(func=_post_command)

    posts_parser = subparsers.add_parser(
        "posts", parents=[common_parser], help="포스트 목록을 가져옵니다."
    )
    posts_parser.add_argument(
        "--encode-url",
        "-e",
        action="store_true",
        help="포스트 주소를 URL 인코딩 형태로 보여줍니다.",
    )
    posts_parser.set_defaults(func=_posts_command)

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
