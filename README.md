# Arch Linux Security Tracker [![Build Status](https://travis-ci.com/archlinux/arch-security-tracker.svg?branch=master)](https://travis-ci.com/archlinux/arch-security-tracker)

The **Arch Linux Security Tracker** is a lightweight flask based panel
for tracking vulnerabilities in Arch Linux packages, displaying
vulnerability details and generating security advisories.

## Features

* Issue tracking
* Issue grouping
* libalpm support
* Todo lists
* Advisory scheduling
* Advisory generation

## Dependencies

### Application

* python >= 3.4
* python-sqlalchemy
* python-sqlalchemy-continuum
* python-flask
* python-flask-sqlalchemy
* python-flask-talisman
* python-flask-wtf
* python-flask-login
* python-flask-migrate
* python-requests
* python-scrypt
* pyalpm
* sqlite

### Tests

* python-isort
* python-pytest
* python-pytest-cov

### Virtualenv

Python dependencies can be installed in a virtual environment (`virtualenv`), by running:

```
virtualenv .virtualenv
. .virtualenv/bin/activate
pip install -r requirements.txt
```

For running tests:
```
pip install -r test-requirements.txt
```

## Setup

```
make
```

run debug mode:

```
make run
```

adding a new user:

```
make user
```

run tests:

```
make test
```

For production run it through ```uwsgi```

## Command line interface

The ```trackerctl``` script provides access to the command line interface
that controls and operates different parts of the tracker. All commands
and subcommands provide a ```--help``` option that describes the operation
and all its available options.

## Configuration

The configurations are all placed into the ```config``` directory and
applied as a sorted cascade.

The default values in the ```00-default.conf``` file should not be
altered for customization. If some tweaking is required, simply create
a new configuration file with a ```.local.conf``` suffix and some non
zero prefix like ```20-user.local.conf```. Files using this suffix are
on the ```.gitignore``` and not handled as untracked or dirty.

## Contribution

Help is appreciated, for some guidelines and recommendations check our
[Contribution](https://github.com/archlinux/arch-security-tracker/blob/master/CONTRIBUTING.md)
file.
