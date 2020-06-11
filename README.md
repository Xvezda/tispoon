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
               [--client-secret CLIENT_SECRET] [--file FILE] [--list]
               [--blog BLOG] [--demo] [--verbose] [--version]
               [files [files ...]]

positional arguments:
  files

optional arguments:
  -h, --help            show this help message and exit
  --token TOKEN, -t TOKEN
  --client-id CLIENT_ID, -u CLIENT_ID
  --client-secret CLIENT_SECRET, -p CLIENT_SECRET
  --file FILE, -f FILE  markdown or json file to post, set '-' to read from
                        stdin.
  --list, -l            list blog informations
  --blog BLOG, -b BLOG  specify blog name. (i.e. [blogName].tistory.com)
  --demo, -d            posting demo article to blog.
  --verbose, -v
  --version, -V         show program's version number and exit
```

# Copyright

[MIT License](LICENSE)

# Reference

Tispoon은 [티스토리](https://tistory.com/)와 관련이 없는 서드파티 라이브러리 입니다.

티스토리와 티스토리 Open API는 [Kakao Corp.](http://www.kakaocorp.com/) 의 상표 또는 등록상표 입니다.

- [티스토리 오픈 API 가이드](https://tistory.github.io/document-tistory-apis/)

