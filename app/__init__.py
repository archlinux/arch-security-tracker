from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql.expression import ClauseElement
from werkzeug.routing import BaseConverter

from types import MethodType

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
