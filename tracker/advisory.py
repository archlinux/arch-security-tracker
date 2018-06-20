from datetime import date
from datetime import datetime
from html import unescape
from re import IGNORECASE
from re import escape
from re import search
from re import sub

from requests import get

from config import TRACKER_MAILMAN_URL
from tracker.util import chunks
from tracker.util import issue_to_numeric


def advisory_fetch_from_mailman(url):
    try:
        response = get(url)
        if 200 != response.status_code:
            return None
        asa = unescape(sub('</?A[^<]*?>', '', response.text))
        start = '<PRE>'
        start_marker = '{}Arch Linux Security Advisory'.format(start)
        end = '\n-------------- next part --------------'
        asa = asa[asa.index(start_marker) + len(start):asa.index(end)]
        return asa.strip()
    except Exception:
        return None


def advisory_fetch_reference_url_from_mailman(advisory):
    try:
        year = advisory.id[4:8]
        month = advisory.id[8:10]
        publish_date = date(int(year), int(month), 1)
        mailman_url = '{}{}-{}/'.format(TRACKER_MAILMAN_URL, year, publish_date.strftime('%B'))
        response = get(mailman_url)
        if 200 != response.status_code:
            return None
        for line in response.text.split('\n'):
            if not '[{}]'.format(advisory.id) in line:
                continue
            match = search('HREF="(\d+.html)"', line)
            if not match:
                continue
            return '{}{}'.format(mailman_url, match.group(1))
        return None
    except Exception:
        return None


def advisory_get_impact_from_text(advisory):
    start = '\nImpact\n======\n\n'
    end = '\n\nReferences\n'
    if start not in advisory or end not in advisory:
        return None
    start_index = advisory.index(start)
    end_index = advisory.index(end)
    impact = advisory[start_index + len(start):end_index]
    impact = sub('([^.\n])\\n', '\\1 ', impact)
    return impact


def advisory_get_workaround_from_text(advisory):
    start = '\nWorkaround\n==========\n\n'
    end = '\n\nDescription\n'
    if start not in advisory or end not in advisory:
        return None
    start_index = advisory.index(start)
    end_index = advisory.index(end)
    workaround = advisory[start_index + len(start):end_index]
    if 'None.' == workaround:
        return None
    return workaround


def advisory_extend_html(advisory, issues, package):
    advisory = sub(r'(\b({0})\b)'.format(escape(package.pkgname)), '<a href="/package/{0}">\g<1></a>'.format(package.pkgname), advisory, flags=IGNORECASE)
    return advisory


def advisory_extend_model_from_advisory_text(advisory):
    if not advisory.content:
        return advisory
    advisory.impact = advisory_get_impact_from_text(advisory.content)
    advisory.workaround = advisory_get_workaround_from_text(advisory.content)
    return advisory


def advisory_get_date_label(utctimetuple=None):
    now = utctimetuple if utctimetuple else datetime.utcnow().utctimetuple()
    return '{}{:02}'.format(now.tm_year, now.tm_mon)


def advisory_get_label(date_label=None, number=1):
    date_label = date_label if date_label else advisory_get_date_label()
    return 'ASA-{}-{}'.format(date_label, number)


def advisory_format_issue_listing(issues, columns=4, rjust_left=len('CVE-ID  : ')):
    # split sorted issues into chunks
    issue_chunks = list(chunks(sorted(issues, key=issue_to_numeric), columns))
    # insert padding to make last chunk have uniform size
    issue_chunks[-1].extend([None] * (len(issue_chunks[0]) - len(issue_chunks[-1])))
    # zip all row chunks to columns
    issue_columns = list(zip(*issue_chunks))
    # calc max length of each column
    issue_column_length = list(map(lambda column: max(map(len, filter(lambda e: e, column))),
                                   issue_columns))
    # ljust elements per column to longest element
    issue_columns = [[element.ljust(issue_column_length[index])
                     if element and index < len(issue_column_length) - 1
                     else element
                     for element in chunk]
                     for index, chunk in enumerate(issue_columns)]
    # zip all column chunks to rows
    issue_chunks = zip(*issue_columns)
    # filter out empty padding elements
    issue_chunks = map(lambda column: filter(lambda e: e, column), issue_chunks)
    # join each row into an own line and rjust left sides
    return '\n{}'.format(' ' * rjust_left).join(list(map(' '.join, issue_chunks)))
