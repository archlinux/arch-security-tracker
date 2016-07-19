from flask_wtf import Form
from wtforms import StringField, SelectField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Regexp
from app.model.cve import cve_id_regex
from app.model.enum import Severity, Remote


class CVEForm(Form):
    cve = StringField(u'CVE', validators=[DataRequired(), Regexp(cve_id_regex)])
    description = TextAreaField(u'Description', validators=[])
    severity = SelectField(u'Severity', choices=[(e.name, e.label) for e in [*Severity]], validators=[])
    remote = SelectField(u'Remote', choices=[(e.name, e.label) for e in [*Remote]], validators=[])
    notes = TextAreaField(u'Notes', validators=[])
    submit = SubmitField(u'submit')
