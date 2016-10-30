from .base import BaseForm
from wtforms import SelectField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Optional, URL, Length
from wtforms.fields.html5 import URLField
from app.model.advisory import advisory_types, Advisory
from app.form.validators import ValidAdvisoryReference


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
    edit = SubmitField(u'edit')

    def __init__(self, advisory_id):
        super().__init__()
        self.advisory_id = advisory_id
