from .base import BaseForm
from wtforms import StringField, SelectField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length, Optional
from app.form.validators import ValidIssue, ValidURLs
from app.model.cve import CVE, issue_types
from app.model.enum import Severity, Remote


class CVEForm(BaseForm):
    cve = StringField(u'CVE', validators=[DataRequired(), ValidIssue()])
    description = TextAreaField(u'Description', validators=[Optional(), Length(max=CVE.DESCRIPTION_LENGTH)])
    issue_type = SelectField(u'Type', choices=[(item, item.capitalize()) for item in issue_types], validators=[DataRequired()])
    severity = SelectField(u'Severity', choices=[(e.name, e.label) for e in [*Severity]], validators=[DataRequired()])
    remote = SelectField(u'Remote', choices=[(e.name, e.label) for e in [*Remote]], validators=[DataRequired()])
    reference = TextAreaField(u'References', validators=[Optional(), Length(max=CVE.REFERENCES_LENGTH), ValidURLs()])
    notes = TextAreaField(u'Notes', validators=[Optional(), Length(max=CVE.NOTES_LENGTH)])
    submit = SubmitField(u'submit')

    def __init__(self, edit=False):
        super().__init__()
        self.edit = edit
        if edit:
            self.cve.render_kw = {'readonly': True}
