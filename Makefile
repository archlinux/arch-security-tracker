PYTEST?=py.test
PYTEST_OPTIONS+=-v -s
PYTEST_INPUT?=test
PYTEST_COVERAGE_OPTIONS+=--cov-report=term-missing --cov-report=html:test/coverage --cov=app

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

test coverage: setup
	PYTHONPATH=".:${PYTHONPATH}" ${PYTEST} ${PYTEST_INPUT} ${PYTEST_OPTIONS} ${PYTEST_COVERAGE_OPTIONS}

open-coverage: coverage
	${BROWSER} test/coverage/index.html
