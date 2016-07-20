from app import app
from flask import render_template
from random import randint
from logging import error


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
def internal_error(e='500: Deep Shit'):
    if app.debug:
        raise e
    error(e, exc_info=True)
    return handle_error(e if e is str else '500: Deep Shit', 500)
