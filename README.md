# Arch Linux Security Tracker

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

* python-flask
* python-sqlalchemy
* python-flask-sqlalchemy
* python-flask-wtf
* pyalpm
* sqlite
* expac

## Setup

```
make
```

run debug mode:

```
./run.py
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
