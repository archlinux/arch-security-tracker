from .base import BaseForm
from wtforms import StringField, SelectField, SubmitField
from wtforms.validators import DataRequired, Regexp
from app.model.cve import cve_id_regex
from app.model.advisory import advisory_types


class AdvisoryForm(BaseForm):
    id = StringField(u'ASA', validators=[DataRequired(), Regexp(cve_id_regex)])
    advisory_type = SelectField(u'Type', choices=[(item, item.capitalize()) for item in advisory_types], validators=[DataRequired()])
    submit = SubmitField(u'schedule')
