from wtforms import SelectField
from wtforms import StringField
from wtforms import SubmitField
from wtforms import TextAreaField
from wtforms.validators import DataRequired
from wtforms.validators import Length
from wtforms.validators import Optional

from tracker.form.validators import ValidIssue
from tracker.form.validators import ValidURLs
from tracker.model.cve import CVE
from tracker.model.cve import issue_types
from tracker.model.enum import Remote
from tracker.model.enum import Severity

from .base import BaseForm


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
