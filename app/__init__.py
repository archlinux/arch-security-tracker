from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql.expression import ClauseElement
from werkzeug.routing import BaseConverter
from types import MethodType
from sqlalchemy.engine import Engine
from sqlalchemy import event
from config import SQLITE_JOURNAL_MODE, SQLITE_TEMP_STORE, SQLITE_SYNCHRONOUS, SQLITE_MMAP_SIZE, SQLITE_CACHE_SIZE


@event.listens_for(Engine, 'connect')
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute('PRAGMA temp_store = {}'.format(SQLITE_TEMP_STORE))
    cursor.execute('PRAGMA journal_mode = {}'.format(SQLITE_JOURNAL_MODE))
    cursor.execute('PRAGMA synchronous = {}'.format(SQLITE_SYNCHRONOUS))
    cursor.execute('PRAGMA mmap_size = {}'.format(SQLITE_MMAP_SIZE))
    cursor.execute('PRAGMA cache_size = {}'.format(SQLITE_CACHE_SIZE))
    cursor.close()

app = Flask(__name__)
app.config.from_object('config')
db = SQLAlchemy(app)


class RegexConverter(BaseConverter):
    def __init__(self, url_map, *items):
        super(RegexConverter, self).__init__(url_map)
        self.regex = items[0]


app.url_map.converters['regex'] = RegexConverter

from app.view import *
from app.model import *


def get(self, model, defaults=None, **kwargs):
    return self.session.query(model).filter_by(**kwargs).first()


def create(self, model, defaults=None, **kwargs):
    params = dict((k, v) for k, v in kwargs.items() if not isinstance(v, ClauseElement))
    params.update(defaults or {})
    instance = model(**params)
    self.session.add(instance)
    self.session.flush()
    return instance


def get_or_create(self, model, defaults=None, **kwargs):
    instance = self.get(model, defaults, **kwargs)
    if instance:
        return instance
    return self.create(model, defaults, **kwargs)

db.get = MethodType(get, db)
db.create = MethodType(create, db)
db.get_or_create = MethodType(get_or_create, db)
