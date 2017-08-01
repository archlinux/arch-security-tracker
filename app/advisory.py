from config import TRACKER_MAILMAN_URL
from re import sub, search
from requests import get
from html import unescape
from datetime import date, datetime


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
    for issue in issues:
        advisory = advisory.replace(' {}'.format(issue.id), ' <a href="/{0}">{0}</a>'.format(issue.id))
    advisory = advisory.replace(' {}'.format(package.pkgname), ' <a href="/package/{0}">{0}</a>'.format(package.pkgname))
    advisory = advisory.replace(';{}'.format(package.pkgname), ';<a href="/package/{0}">{0}</a>'.format(package.pkgname))
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
