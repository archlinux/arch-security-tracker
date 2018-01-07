from .base import BaseForm
from wtforms import SubmitField


class ConfirmForm(BaseForm):
    confirm = SubmitField(u'confirm')
    abort = SubmitField(u'abort')
