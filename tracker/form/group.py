from .base import BaseForm
from wtforms import StringField, SelectField, TextAreaField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Optional, Regexp, Length
from tracker.model.cvegroup import pkgver_regex, CVEGroup
from tracker.model.enum import Affected
from tracker.form.validators import ValidPackageNames, SamePackageBase, ValidIssues, ValidURLs
from pyalpm import vercmp


class GroupForm(BaseForm):
    cve = TextAreaField(u'CVE', validators=[DataRequired(), ValidIssues()])
    pkgnames = TextAreaField(u'Package', validators=[DataRequired(), ValidPackageNames(), SamePackageBase()])
    affected = StringField(u'Affected', validators=[DataRequired(), Regexp(pkgver_regex)])
    fixed = StringField(u'Fixed', validators=[Optional(), Regexp(pkgver_regex)])
    status = SelectField(u'Status', choices=[(e.name, e.label) for e in [*Affected]], validators=[DataRequired()])
    bug_ticket = StringField('Bug ticket', validators=[Optional(), Regexp(r'^\d+$')])
    reference = TextAreaField(u'References', validators=[Optional(), Length(max=CVEGroup.REFERENCES_LENGTH), ValidURLs()])
    notes = TextAreaField(u'Notes', validators=[Optional(), Length(max=CVEGroup.NOTES_LENGTH)])
    advisory_qualified = BooleanField(u'Advisory qualified', default=True, validators=[Optional()])
    force_submit = BooleanField(u'Force creation', default=False, validators=[Optional()])
    submit = SubmitField(u'submit')

    def __init__(self, packages=[]):
        super().__init__()
        self.packages = packages

    def validate(self):
        rv = BaseForm.validate(self)
        if not rv:
            return False
        if self.fixed.data and 0 <= vercmp(self.affected.data, self.fixed.data):
            self.fixed.errors.append('Version must be newer.')
            return False
        return True
