from flask import Blueprint
from app import app

blueprint = Blueprint('filters', __name__)


@blueprint.app_template_filter()
def smartindent(s, width=1, indentfirst=False, indentchar=u'\t'):
    """Return a copy of the passed string, each line indented by
    1 tab. The first line is not indented. If you want to
    change the number of tabs or indent the first line too
    you can pass additional parameters to the filter:

    .. sourcecode:: jinja

        {{ mytext|indent(2, true, 'x') }}
            indent by two 'x' and indent the first line too.
    """
    indention = indentchar * width
    rv = (u'\n' + indention).join(s.splitlines())
    if indentfirst:
        rv = indention + rv
    return rv

app.register_blueprint(blueprint)
