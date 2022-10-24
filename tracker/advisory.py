from datetime import datetime
from html import unescape
from os.path import join
from re import IGNORECASE
from re import escape
from re import search
from re import sub
from urllib.parse import urlparse

from flask import render_template
from markupsafe import escape as html_escape
from requests import get

from config import TRACKER_ADVISORY_URL
from config import TRACKER_BUGTRACKER_URL
from config import TRACKER_GROUP_URL
from config import TRACKER_ISSUE_URL
from config import TRACKER_MAILMAN_URL
from tracker import db
from tracker.model import CVE
from tracker.model import Advisory
from tracker.model import CVEGroup
from tracker.model import CVEGroupEntry
from tracker.model import CVEGroupPackage
from tracker.model import Package
from tracker.model.enum import Publication
from tracker.model.enum import Remote
from tracker.user import user_can_handle_advisory
from tracker.util import chunks
from tracker.util import issue_to_numeric
from tracker.util import multiline_to_list


def generate_advisory(advisory_id, with_subject=True, raw=True):
    entries = (db.session.query(Advisory, CVEGroup, CVEGroupPackage, CVE)
               .filter(Advisory.id == advisory_id)
               .join(CVEGroupPackage, Advisory.group_package)
               .join(CVEGroup, CVEGroupPackage.group)
               .join(CVEGroupEntry, CVEGroup.issues)
               .join(CVE, CVEGroupEntry.cve)
               .order_by(CVE.id)
               ).all()
    if not entries:
        return None

    advisory = entries[0][0]
    group = entries[0][1]
    package = entries[0][2]
    issues = sorted([issue for (advisory, group, package, issue) in entries])
    severity_sorted_issues = sorted(issues, key=lambda issue: issue.issue_type)
    severity_sorted_issues = sorted(severity_sorted_issues, key=lambda issue: issue.severity)
    remote = any([issue.remote is Remote.remote for issue in issues])
    issue_listing_formatted = advisory_format_issue_listing([issue.id for issue in issues])

    link = TRACKER_ADVISORY_URL.format(advisory.id, group.id)
    upstream_released = group.affected.split('-')[0].split('+')[0] != group.fixed.split('-')[0].split('+')[0]
    upstream_version = group.fixed.split('-')[0].split('+')[0]
    if ':' in upstream_version:
        upstream_version = upstream_version[upstream_version.index(':') + 1:]
    unique_issue_types = []
    for issue in severity_sorted_issues:
        if issue.issue_type not in unique_issue_types:
            unique_issue_types.append(issue.issue_type)

    references = []
    if group.bug_ticket:
        references.append(TRACKER_BUGTRACKER_URL.format(group.bug_ticket))
    references.extend([ref for ref in multiline_to_list(group.reference)
                       if ref not in references])
    list(map(lambda issue: references.extend(
        [ref for ref in multiline_to_list(issue.reference) if ref not in references]), issues))

    raw_asa = render_template('advisory.txt',
                              advisory=advisory,
                              group=group,
                              package=package,
                              issues=issues,
                              remote=remote,
                              issue_listing_formatted=issue_listing_formatted,
                              link=link,
                              workaround=advisory.workaround,
                              impact=advisory.impact,
                              upstream_released=upstream_released,
                              upstream_version=upstream_version,
                              unique_issue_types=unique_issue_types,
                              references=references,
                              with_subject=with_subject,
                              TRACKER_ISSUE_URL=TRACKER_ISSUE_URL,
                              TRACKER_GROUP_URL=TRACKER_GROUP_URL)
    if raw:
        return raw_asa

    raw_asa = '\n'.join(raw_asa.split('\n')[2:])
    raw_asa = str(html_escape(raw_asa))
    raw_asa = advisory_extend_html(raw_asa, issues, package)
    return render_html_advisory(advisory=advisory, package=package, group=group, raw_asa=raw_asa, generated=True)


def render_html_advisory(advisory, package, group, raw_asa, generated):
    return render_template('advisory.html',
                           title='[{}] {}: {}'.format(advisory.id, package.pkgname, advisory.advisory_type),
                           advisory=advisory,
                           package=package,
                           raw_asa=raw_asa,
                           generated=generated,
                           can_handle_advisory=user_can_handle_advisory(),
                           Publication=Publication)


def advisory_fetch_from_mailman(url):
    try:
        response = get(url)
        if 200 != response.status_code:
            return None

        return response.text
    except Exception:
        return None


def advisory_fetch_reference_url_from_mailman(advisory):
    try:
        year = advisory.id[4:8]
        month = advisory.id[8:10]
        mailman_monthly = '{}{}/{}/?count=100'.format(TRACKER_MAILMAN_URL, year, month)

        response = get(mailman_monthly)
        if 200 != response.status_code:
            return None

        mailman_url = urlparse(TRACKER_MAILMAN_URL)
        thread_url_base = join(mailman_url.path, 'thread')

        message_url = None
        for line in response.text.split('\n'):
            if thread_url_base in line:
                match = search(r'href="{}/([/a-zA-Z0-9]+)"'.format(thread_url_base), line)
                if not match:
                    continue

                thread = match.group(1)
                message_url = join(TRACKER_MAILMAN_URL, 'message', thread)

            if not '[{}]'.format(advisory.id) in line:
                continue

            return message_url
        return None
    except Exception:
        return None


def advisory_get_section_from_text(advisory, start, end):
    if start not in advisory or end not in advisory:
        return None
    start_index = advisory.index(start)
    end_index = advisory.index(end)
    section = advisory[start_index + len(start):end_index]
    return section


def advisory_get_impact_from_text(advisory):
    start = '\nImpact\n======\n\n'
    end = '\n\nReferences\n==========\n\n'
    impact = advisory_get_section_from_text(advisory, start, end)
    if not impact:
        return None
    return sub('([^.\n])\\n', '\\1 ', impact)


def advisory_get_workaround_from_text(advisory):
    start = '\nWorkaround\n==========\n\n'
    end = '\n\nDescription\n===========\n\n'
    workaround = advisory_get_section_from_text(advisory, start, end)
    if 'None.' == workaround:
        return None
    return workaround


def advisory_escape_html(advisory):
    start = '\nWorkaround\n==========\n\n'
    end = '\n\nReferences\n==========\n\n'
    if start not in advisory or end not in advisory:
        return None
    start_index = advisory.index(start) + len(start)
    end_index = advisory.index(end)
    advisory = advisory[:start_index] + str(html_escape(advisory[start_index:end_index])) + advisory[end_index:]
    return advisory


def advisory_extend_html(advisory, issues, package):
    advisory = sub('({}) '.format(escape(package.pkgname)), '<a href="/package/{0}" rel="noopener">\\g<1></a> '.format(package.pkgname), advisory, flags=IGNORECASE)
    advisory = sub(' ({})'.format(escape(package.pkgname)), ' <a href="/package/{0}" rel="noopener">\\g<1></a>'.format(package.pkgname), advisory, flags=IGNORECASE)
    advisory = sub(';({})'.format(escape(package.pkgname)), ';<a href="/package/{0}" rel="noopener">\\g<1></a>'.format(package.pkgname), advisory, flags=IGNORECASE)
    advisory = sub('"({})'.format(escape(package.pkgname)), '"<a href="/package/{0}" rel="noopener">\\g<1></a>'.format(package.pkgname), advisory, flags=IGNORECASE)
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
