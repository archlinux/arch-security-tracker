from .base import BaseForm
from wtforms import SelectField, SubmitField
from wtforms.validators import DataRequired
from app.model.advisory import advisory_types


class AdvisoryForm(BaseForm):
    advisory_type = SelectField(u'Type', choices=[(item, item.capitalize()) for item in advisory_types], validators=[DataRequired()])
    submit = SubmitField(u'schedule')
