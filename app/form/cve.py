from .base import BaseForm
from wtforms import StringField, SelectField, TextAreaField, SubmitField
from wtforms.validators import DataRequired
from app.form.validators import ValidIssue
from app.model.enum import Severity, Remote


class CVEForm(BaseForm):
    cve = StringField(u'CVE', validators=[DataRequired(), ValidIssue()])
    description = TextAreaField(u'Description', validators=[])
    severity = SelectField(u'Severity', choices=[(e.name, e.label) for e in [*Severity]], validators=[])
    remote = SelectField(u'Remote', choices=[(e.name, e.label) for e in [*Remote]], validators=[])
    notes = TextAreaField(u'Notes', validators=[])
    submit = SubmitField(u'submit')
