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

## Setup

```
make
```

run debug mode:

```
./run.py
```

For production run it through ```uwsgi```

## License

