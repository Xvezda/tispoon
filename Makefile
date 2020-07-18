.PHONY: test build clean check


PY2 = python
PY3 = ./venv/bin/python
PY = $(PY2)
TWINE = twine

TR = tr
RM = rm
SED = sed
FIND = find
GREP = grep
XARGS = xargs
PKG_NAME = tispoon
METADATA_FILE = $(PKG_NAME)/__about__.py
PKG_VERSION = $(shell \
	$(SED) -n -E "s/__version__ = [\"']([^\"']+)[\"']/\1/p" $(METADATA_FILE))
DIST_DIR = dist
DIST_FILES = $(wildcard $(DIST_DIR)/$(PKG_NAME)-$(PKG_VERSION)*)
TEST_DIR = tests


all: clean build

build: py2dist py3dist

py2dist:
	$(PY2) setup.py sdist bdist_wheel

py3dist:
	$(PY3) setup.py sdist bdist_wheel

test: py2test py3test

py2test:
	$(PY) -m pytest -v -s --cov-report html --cov-report term \
		--cov=$(PKG_NAME) $(TEST_DIR)

py3test:
	$(PY3) -m pytest -v -s --cov-append --cov-report html --cov-report term \
		--cov=$(PKG_NAME) $(TEST_DIR)

check:
	$(TWINE) check $(DIST_DIR)/$(PKG_NAME)-$(PKG_VERSION)*

publish: all check
	$(TWINE) upload $(DIST_FILES)

pkg_version:
	@echo $(PKG_VERSION)

clean:
	$(GREP) '/$$' .gitignore \
		| $(XARGS) -I{} echo "\\! -path '*/{}*'" \
		| $(TR) $$'\n' ' ' | $(XARGS) $(FIND) . -name '*.pyc' \
		| $(XARGS) -n1 $(RM)
	$(PY) setup.py clean

