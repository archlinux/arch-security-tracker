from tracker import tracker
from flask import render_template
from random import randint
from logging import error
from os import urandom
from binascii import hexlify
from tracker.symbol import smileys_sad
from werkzeug.exceptions import NotFound, Forbidden, MethodNotAllowed, Gone, InternalServerError
from functools import wraps
from config import get_debug_flag


error_handlers = []


def errorhandler(code_or_exception):
    def decorator(func):
        error_handlers.append({'func': func, 'code_or_exception': code_or_exception})

        @wraps(func)
        def wrapped(*args, **kwargs):
            return func(*args, **kwargs)
        return wrapped
    return decorator


def handle_error(e, code, json=False):
    if json:
        return {'message': e}, code
    return render_template('error.html',
                           smiley=smileys_sad[randint(0, len(smileys_sad) - 1)],
                           text=e,
                           title='{}'.format(code)), code


@errorhandler(NotFound.code)
def not_found(e='404: Not Found', json=False):
    return handle_error(e if 'check your spelling' not in '{}'.format(e) else '404: Not Found', NotFound.code, json)


@errorhandler(Forbidden.code)
def forbidden(e='403: Forbidden', json=False):
    return handle_error(e, Forbidden.code, json)


@errorhandler(MethodNotAllowed.code)
def method_not_allowed(e='405: Method Not Allowed', json=False):
    return handle_error(e, MethodNotAllowed.code, json)


@errorhandler(Gone.code)
def gone(e='410: Gone', json=False):
    return handle_error(e, Gone.code, json)


@errorhandler(Exception)
@errorhandler(InternalServerError.code)
def internal_error(e):
    if get_debug_flag():
        raise e
    code = hexlify(urandom(4)).decode()
    error(Exception("Code: {}".format(code), e), exc_info=True)
    text = '500: Deep Shit\n{}'.format(code)
    return handle_error(text, InternalServerError.code)
