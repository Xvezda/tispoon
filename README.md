# Tispoon
[![Version](https://img.shields.io/pypi/v/tispoon)](https://pypi.org/project/tispoon)
[![License](https://img.shields.io/pypi/l/tispoon)](https://pypi.org/project/tispoon)
[![Platform](https://img.shields.io/pypi/pyversions/tispoon)](https://pypi.org/project/tispoon)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

[티스토리 오픈 API](https://www.tistory.com/guide/api/manage/register)를 활용한 파이썬 라이브러리 입니다.

# Installation

```sh
pip install tispoon
```

# Usage

```
usage: tispoon [-h] [--token TOKEN] [--client-id CLIENT_ID]
               [--client-secret CLIENT_SECRET] [--blog BLOG] [--verbose]
               [--version]
               {info,post,category,comment,import} ...

positional arguments:
  {info,post,category,comment,import}
    info                자신의 블로그 정보를 가져오는 API
                        입니다.
    post                블로그 글을 관리하는 API 입니다.
    category            블로그 카테고리를 정보를 가져오는 API
                        입니다.
    comment             블로그 댓글을 관리하는 API 입니다.
    import              게시된 게시글을 불러오는
                        명령어입니다.

optional arguments:
  -h, --help            show this help message and exit
  --token TOKEN, -t TOKEN
                        인증 토큰을 설정합니다.
  --client-id CLIENT_ID, -u CLIENT_ID
                        Open API의 client id값을 설정합니다.
  --client-secret CLIENT_SECRET, -p CLIENT_SECRET
                        Open API의 client secret값을 설정합니다.
  --blog BLOG, -b BLOG  블로그 이름을 설정합니다. 예)
                        `xvezda.tistory.com` 의 경우 `xvezda`
  --verbose, -v         로그의 정보량을 설정합니다. `v`의
                        갯수에 따라 정보량이 달라집니다.
  --version, -V         버전 정보를 출력하고 종료합니다.
                        `xvezda.tistory.com` 의 경우 `xvezda`
  --verbose, -v
  --version, -V         show program's version number and exit
```

블로그 정보

```sh
tispoon info
```

게시글 작성

```sh
# 마크다운 파일로 블로그 포스팅하기
cat <<EOD > test.md
---
title: 테스트
visibility: 3
slogan: /안녕하세요
---

테스트 게시글 입니다. :)
EOD

tispoon post test.md
```

게시글 마크다운 파일로 불러오기

```sh
tispoon import
```

# Copyright

[MIT License](LICENSE)

# Reference

Tispoon은 [티스토리](https://tistory.com/)와 관련이 없는 서드파티 라이브러리 입니다.

티스토리와 티스토리 Open API는 [Kakao Corp.](http://www.kakaocorp.com/) 의 상표 또는 등록상표 입니다.

- [티스토리 오픈 API 가이드](https://tistory.github.io/document-tistory-apis/)

