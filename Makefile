-include Makefile.local

PYTEST?=py.test
PYTEST_OPTIONS+=-v -s
PYTEST_INPUT?=test
PYTEST_COVERAGE_OPTIONS+=--cov-report=term-missing --cov-report=html:test/coverage --cov=tracker

ISORT?=isort
ISORT_OPTIONS+=--recursive
ISORT_CHECK_OPTIONS+=--check-only --diff

.PHONY: update test

all: update

setup: submodule
	./trackerctl setup bootstrap

submodule:
	git submodule update --recursive --init --rebase

update: setup
	./trackerctl update env

user: setup
	./trackerctl setup user

run: setup
	./trackerctl run

shell: setup
	./trackerctl shell

check: setup
	./trackerctl setup check

test: test-py test-isort

test-py coverage: setup
	PYTHONPATH=".:${PYTHONPATH}" ${PYTEST} ${PYTEST_INPUT} ${PYTEST_OPTIONS} ${PYTEST_COVERAGE_OPTIONS}

test-isort:
	@if [[ -n "$$(which colordiff 2>/dev/null)" ]]; then \
		DIFF="$$(${ISORT} ${ISORT_OPTIONS} ${ISORT_CHECK_OPTIONS} .)"; EXIT=$$?; \
		cat <<< $$DIFF|colordiff; if [[ 0 -ne "$$EXIT" ]]; then exit $$EXIT; fi; \
	else \
		${ISORT} ${ISORT_OPTIONS} ${ISORT_CHECK_OPTIONS} .; \
	fi
	@echo "Checking isort...ok"

open-coverage: coverage
	${BROWSER} test/coverage/index.html

isort:
	${ISORT} --recursive .
