from os import path
basedir = path.abspath(path.dirname(__file__))

SQLALCHEMY_DATABASE_URI = 'sqlite:///' + path.join(basedir, 'app.db')
SQLALCHEMY_MIGRATE_REPO = path.join(basedir, 'db_repository')
SQLALCHEMY_ECHO = True
SQLALCHEMY_TRACK_MODIFICATIONS = False

CSRF_ENABLED = True
SECRET_KEY = 'changeme_iddqd'

PACMAN_HANDLE_CACHE_TIME = 2 * 60
