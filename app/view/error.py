from app import app
from flask import render_template
from random import randint
from logging import error
from os import urandom
from binascii import hexlify


smileys = [u'😐', u'😑', u'😒', u'😓', u'😔', u'😕', u'😖', u'😝', u'😞', u'😟',
           u'😠', u'😡', u'😢', u'😣', u'😥', u'😦', u'😧', u'😨', u'😩', u'😪',
           u'😫', u'😭', u'😮', u'😯', u'😰', u'😱', u'😲', u'😵', u'😶', u'😾',
           u'😿', u'🙀']


def handle_error(e, code):
    return render_template('error.html', smiley=smileys[randint(0, len(smileys) - 1)], text=e), code


@app.errorhandler(404)
def not_found(e='404: Not Found'):
    return handle_error(e, 404)


@app.errorhandler(403)
def forbidden(e='403: Forbidden'):
    return handle_error(e, 403)


@app.errorhandler(410)
def gone(e='410: Gone'):
    return handle_error(e, 410)


@app.errorhandler(Exception)
@app.errorhandler(500)
def internal_error(e):
    if app.debug:
        raise e
    code = hexlify(urandom(4)).decode()
    error(Exception("Code: {}".format(code), e), exc_info=True)
    text = '500: Deep Shit\n{}'.format(code)
    return handle_error(text, 500)
