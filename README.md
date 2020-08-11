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
* SSO or local users

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
* python-authlib
* python-email-validator
* python-requests
* python-scrypt
* python-feedgen
* python-pytz
* pyalpm
* sqlite

### Tests

* python-isort
* python-pytest
* python-pytest-cov

### Virtualenv

Python dependencies can be installed in a virtual environment (`venv`), by running:

```
python -m venv .virtualenv
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

## SSO setup

A simple test environment for SSO can be configured using Keycloak:

1. Run a local Keycloak installation via docker as [described
   upstream](https://www.keycloak.org/getting-started/getting-started-docker).

2. Create an ```arch-securiy-tracker``` client in Keycloak like in
   [test/data/openid-client.json](test/data/openid-client.json).
   Make sure the client contains a mapper for the group memberships called
   ```groups``` which is included as a claim.

3. Create a local tracker config file with enabled SSO and configure OIDC
   secrets, groups and metadata url accordingly.

## Contribution

Help is appreciated, for some guidelines and recommendations check our
[Contribution](CONTRIBUTING.md) file.
