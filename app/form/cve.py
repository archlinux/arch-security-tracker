from .base import BaseForm
from wtforms import StringField, SelectField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length, Optional
from app.form.validators import ValidIssue
from app.model.cve import CVE
from app.model.enum import Severity, Remote


class CVEForm(BaseForm):
    cve = StringField(u'CVE', validators=[DataRequired(), ValidIssue()])
    description = TextAreaField(u'Description', validators=[Optional(), Length(max=CVE.DESCRIPTION_LENGTH)])
    severity = SelectField(u'Severity', choices=[(e.name, e.label) for e in [*Severity]], validators=[])
    remote = SelectField(u'Remote', choices=[(e.name, e.label) for e in [*Remote]], validators=[])
    notes = TextAreaField(u'Notes', validators=[Length(max=CVE.NOTES_LENGTH)])
    submit = SubmitField(u'submit')
