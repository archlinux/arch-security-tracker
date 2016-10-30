from .base import BaseForm
from wtforms import SelectField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Optional, URL, Length
from wtforms.fields.html5 import URLField
from app.model.advisory import advisory_types, Advisory


class AdvisoryForm(BaseForm):
    advisory_type = SelectField(u'Type', choices=[(item, item.capitalize()) for item in advisory_types], validators=[DataRequired()])
    submit = SubmitField(u'schedule')


class AdvisoryPublishForm(BaseForm):
    reference = URLField(u'Reference', validators=[DataRequired(), URL(), Length(max=Advisory.REFERENCE_LENGTH)])
    submit = SubmitField(u'publish')


class AdvisoryEditForm(BaseForm):
    reference = URLField(u'Reference', validators=[Optional(), URL(), Length(max=Advisory.REFERENCE_LENGTH)])
    workaround = TextAreaField(u'Workaround', validators=[Optional(), Length(max=Advisory.WORKAROUND_LENGTH)])
    impact = TextAreaField(u'Impact', validators=[Optional(), Length(max=Advisory.IMPACT_LENGTH)])
    edit = SubmitField(u'edit')
