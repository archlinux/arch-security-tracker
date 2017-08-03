# Arch Linux Security Tracker [![Build Status](https://travis-ci.org/archlinux/arch-security-tracker.svg?branch=master)](https://travis-ci.org/archlinux/arch-security-tracker)

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
* python-flask
* python-flask-sqlalchemy
* python-flask-talisman
* python-flask-wtf
* python-flask-login
* python-requests
* python-scrypt
* pyalpm
* sqlite
* expac

### Tests

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
./run.py
```

adding a new user:

```
./update --create-user
```

run tests:

```
make test
```

For production run it through ```uwsgi```

## Configuration

The configurations are all placed into the ```config``` directory and
applied as a sorted cascade.

The default values in the ```00-default.conf``` file should not be
altered for customization. If some tweaking is required, simply create
a new configuration file with a ```.local.conf``` suffix and some non
zero prefix like ```20-user.local.conf```. Files using this suffix are
on the ```.gitignore``` and not handled as untracked or dirty.
