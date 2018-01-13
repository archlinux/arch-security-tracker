from wtforms import SubmitField

from .base import BaseForm


class ConfirmForm(BaseForm):
    confirm = SubmitField(u'confirm')
    abort = SubmitField(u'abort')
