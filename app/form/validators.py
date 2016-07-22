from wtforms.validators import ValidationError
from app.pacman import get_pkg


class ValidPackageName(object):
    def __init__(self):
        self.message = u'Unknown package.'

    def __call__(self, form, field):
        versions = get_pkg(field.data)
        if not versions:
            raise ValidationError(self.message)
