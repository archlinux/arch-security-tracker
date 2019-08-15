from difflib import ndiff
from re import sub

from flask import Blueprint
from flask import request
from flask import url_for
from jinja2.filters import do_urlize
from jinja2.filters import evalcontextfilter
from jinja2.utils import Markup
from jinja2.utils import _punctuation_re
from jinja2.utils import _word_split_re
from jinja2.utils import escape

from tracker.model.cve import cve_id_regex
from tracker.model.cvegroup import vulnerability_group_regex
from tracker.util import issue_to_numeric

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


@evalcontextfilter
@blueprint.app_template_filter()
def urlize(ctx, text, trim_url_limit=None, rel=None, target=None):
    """Converts any URLs in text into clickable links. Works on http://,
    https:// and www. links. Links can have trailing punctuation (periods,
    commas, close-parens) and leading punctuation (opening parens) and
    it'll still do the right thing.
    Aditionally it will populate the input with application context related
    links linke issues and groups.

    If trim_url_limit is not None, the URLs in link text will be limited
    to trim_url_limit characters.

    If nofollow is True, the URLs in link text will get a rel="nofollow"
    attribute.

    If target is not None, a target attribute will be added to the link.
    """

    words = _word_split_re.split(escape(text))
    for i, word in enumerate(words):
        match = _punctuation_re.match(word)
        if match:
            lead, word, trail = match.groups()
            word = sub('({})'.format(cve_id_regex), '<a href="/\\1" rel="noopener">\\1</a>', word)
            word = sub('({})'.format(vulnerability_group_regex), '<a href="/\\1" rel="noopener">\\1</a>', word)
            words[i] = '{}{}{}'.format(lead, word, trail)

    text = ''.join(words)
    if ctx.autoescape:
        text = Markup(text)

    text = do_urlize(ctx, text, trim_url_limit=trim_url_limit, target=target, rel=rel)
    return text


@blueprint.app_template_filter()
def diff(previous, current):
    # handle None explicitly to allow diff of False against True
    return ndiff(str(previous).splitlines() if previous is not None else '',
                 str(current).splitlines() if current is not None else '')


@blueprint.app_template_filter()
def issuesort(issues):
    return sorted(issues, key=issue_to_numeric)


@blueprint.app_template_global()
def url_for_page(page):
    args = request.view_args.copy()
    args['page'] = page
    return url_for(request.endpoint, **args)


@blueprint.app_template_global()
def diff_content(model, field):
    return field if model.operation_type != 2 else None
