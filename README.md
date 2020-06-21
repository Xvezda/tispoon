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
               {info,post,category,comment} ...

positional arguments:
  {info,post,category,comment}
    info                자신의 블로그 정보를 가져오는 API
                        입니다.

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
cat << EOD > test.md
---
title: 테스트
visibility: 3
slogan: /안녕하세요
---

테스트 게시글 입니다. :)
EOD

tispoon post test.md
```

# Copyright

[MIT License](LICENSE)

# Reference

Tispoon은 [티스토리](https://tistory.com/)와 관련이 없는 서드파티 라이브러리 입니다.

티스토리와 티스토리 Open API는 [Kakao Corp.](http://www.kakaocorp.com/) 의 상표 또는 등록상표 입니다.

- [티스토리 오픈 API 가이드](https://tistory.github.io/document-tistory-apis/)

