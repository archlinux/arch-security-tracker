from flask import Flask, Blueprint
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_talisman import Talisman
from werkzeug.routing import BaseConverter
from types import MethodType
from sqlalchemy.engine import Engine
from sqlalchemy import event
from sqlalchemy.sql.expression import ClauseElement
from config import atom_feeds, SQLITE_JOURNAL_MODE, SQLITE_TEMP_STORE, SQLITE_SYNCHRONOUS, SQLITE_MMAP_SIZE, SQLITE_CACHE_SIZE, FLASK_SESSION_PROTECTION


@event.listens_for(Engine, 'connect')
def set_sqlite_pragma(dbapi_connection, connection_record):
    isolation_level = dbapi_connection.isolation_level
    dbapi_connection.isolation_level = None
    cursor = dbapi_connection.cursor()
    cursor.execute('PRAGMA temp_store = {}'.format(SQLITE_TEMP_STORE))
    cursor.execute('PRAGMA journal_mode = {}'.format(SQLITE_JOURNAL_MODE))
    cursor.execute('PRAGMA synchronous = {}'.format(SQLITE_SYNCHRONOUS))
    cursor.execute('PRAGMA mmap_size = {}'.format(SQLITE_MMAP_SIZE))
    cursor.execute('PRAGMA cache_size = {}'.format(SQLITE_CACHE_SIZE))
    cursor.execute('PRAGMA foreign_keys = ON')
    cursor.close()
    dbapi_connection.isolation_level = isolation_level


class RegexConverter(BaseConverter):
    def __init__(self, url_map, *items):
        super(RegexConverter, self).__init__(url_map)
        self.regex = items[0]


csp = {
    'default-src': '\'self\'',
    'style-src': '\'self\'',
    'font-src': '\'self\'',
    'form-action': '\'self\''
}

db = SQLAlchemy()
talisman = Talisman()
login_manager = LoginManager()
main = Blueprint('main', __name__)


def create_app(script_info=None):
    app = Flask(__name__)
    app.config.from_object('config')

    db.init_app(app)

    talisman.init_app(app,
                      force_https=False,
                      session_cookie_secure=False,
                      content_security_policy=csp,
                      referrer_policy='no-referrer')

    login_manager.init_app(app)
    login_manager.session_protection = FLASK_SESSION_PROTECTION
    login_manager.login_view = 'main.login'

    app.url_map.converters['regex'] = RegexConverter
    app.jinja_env.globals['ATOM_FEEDS'] = atom_feeds

    from app.view.error import error_handlers
    for error_handler in error_handlers:
        app.register_error_handler(error_handler['code_or_exception'], error_handler['func'])

    from app.view.blueprint import blueprint
    app.register_blueprint(main)
    app.register_blueprint(blueprint)

    import app.view
    import app.model

    return app


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
