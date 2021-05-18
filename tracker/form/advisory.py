from wtforms import BooleanField
from wtforms import HiddenField
from wtforms import SelectField
from wtforms import SubmitField
from wtforms import TextAreaField
from wtforms import URLField
from wtforms.validators import URL
from wtforms.validators import DataRequired
from wtforms.validators import Length
from wtforms.validators import Optional

from tracker.form.validators import ValidAdvisoryReference
from tracker.model.advisory import Advisory
from tracker.model.advisory import advisory_types

from .base import BaseForm


class AdvisoryForm(BaseForm):
    advisory_type = SelectField(u'Type', choices=[(item, item.capitalize()) for item in advisory_types], validators=[DataRequired()])
    submit = SubmitField(u'schedule')


class AdvisoryPublishForm(BaseForm):
    advisory_content = None
    reference = URLField(u'Reference', validators=[DataRequired(), URL(), Length(max=Advisory.REFERENCE_LENGTH), ValidAdvisoryReference()])
    submit = SubmitField(u'publish')

    def __init__(self, advisory_id):
        super().__init__()
        self.advisory_id = advisory_id


class AdvisoryEditForm(BaseForm):
    advisory_content = None
    reference = URLField(u'Reference', validators=[Optional(), URL(), Length(max=Advisory.REFERENCE_LENGTH), ValidAdvisoryReference()])
    workaround = TextAreaField(u'Workaround', validators=[Optional(), Length(max=Advisory.WORKAROUND_LENGTH)])
    impact = TextAreaField(u'Impact', validators=[Optional(), Length(max=Advisory.IMPACT_LENGTH)])
    changed = HiddenField(u'Changed', validators=[Optional()])
    changed_latest = HiddenField(u'Latest Changed', validators=[Optional()])
    force_submit = BooleanField(u'Force update', default=False, validators=[Optional()])
    edit = SubmitField(u'edit')

    def __init__(self, advisory_id):
        super().__init__()
        self.advisory_id = advisory_id
