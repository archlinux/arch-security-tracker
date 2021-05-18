from pyalpm import vercmp
from wtforms import BooleanField
from wtforms import HiddenField
from wtforms import SelectField
from wtforms import StringField
from wtforms import SubmitField
from wtforms import TextAreaField
from wtforms.validators import DataRequired
from wtforms.validators import Length
from wtforms.validators import Optional
from wtforms.validators import Regexp

from tracker.form.validators import SamePackageBase
from tracker.form.validators import ValidIssues
from tracker.form.validators import ValidPackageNames
from tracker.form.validators import ValidURLs
from tracker.model.cvegroup import CVEGroup
from tracker.model.cvegroup import pkgver_regex
from tracker.model.enum import Affected

from .base import BaseForm


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
    changed = HiddenField(u'Changed', validators=[Optional()])
    changed_latest = HiddenField(u'Latest Changed', validators=[Optional()])
    force_update = BooleanField(u'Force update', default=False, validators=[Optional()])
    force_creation = BooleanField(u'Force creation', default=False, validators=[Optional()])
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
