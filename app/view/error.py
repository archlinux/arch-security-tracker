from app import app
from flask import render_template
from random import randint
from logging import error
from os import urandom
from binascii import hexlify
from app.symbol import smileys_sad
from werkzeug.exceptions import NotFound, Forbidden, MethodNotAllowed, Gone, InternalServerError


def handle_error(e, code, json=False):
    if json:
        return {'message': e}, code
    return render_template('error.html',
                           smiley=smileys_sad[randint(0, len(smileys_sad) - 1)],
                           text=e,
                           title='{}'.format(code)), code


@app.errorhandler(NotFound.code)
def not_found(e='404: Not Found', json=False):
    return handle_error(e, NotFound.code, json)


@app.errorhandler(Forbidden.code)
def forbidden(e='403: Forbidden', json=False):
    return handle_error(e, Forbidden.code, json)


@app.errorhandler(MethodNotAllowed.code)
def method_not_allowed(e='405: Method Not Allowed', json=False):
    return handle_error(e, MethodNotAllowed.code, json)


@app.errorhandler(Gone.code)
def gone(e='410: Gone', json=False):
    return handle_error(e, Gone.code, json)


@app.errorhandler(Exception)
@app.errorhandler(InternalServerError.code)
def internal_error(e):
    if app.debug:
        raise e
    code = hexlify(urandom(4)).decode()
    error(Exception("Code: {}".format(code), e), exc_info=True)
    text = '500: Deep Shit\n{}'.format(code)
    return handle_error(text, InternalServerError.code)
