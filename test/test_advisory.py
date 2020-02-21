
from collections import namedtuple

from flask import url_for
from jinja2.utils import escape
from pytest import mark
from werkzeug.exceptions import Forbidden
from werkzeug.exceptions import NotFound

from tracker.advisory import advisory_extend_html
from tracker.advisory import advisory_format_issue_listing
from tracker.advisory import advisory_get_impact_from_text
from tracker.advisory import advisory_get_label
from tracker.advisory import advisory_get_workaround_from_text
from tracker.model.advisory import Advisory
from tracker.model.cve import issue_types
from tracker.model.cvegroup import CVEGroup
from tracker.model.enum import Publication
from tracker.model.enum import UserRole
from tracker.view.advisory import ERROR_ADVISORY_ALREADY_EXISTS
from tracker.view.advisory import ERROR_ADVISORY_GROUP_NOT_FIXED
from tracker.view.edit import WARNING_ADVISORY_ALREADY_PUBLISHED

from .conftest import DEFAULT_ADVISORY_CONTENT
from .conftest import DEFAULT_ADVISORY_ID
from .conftest import DEFAULT_GROUP_ID
from .conftest import DEFAULT_GROUP_NAME
from .conftest import DEFAULT_ISSUE_ID
from .conftest import ERROR_LOGIN_REQUIRED
from .conftest import advisory_count
from .conftest import create_advisory
from .conftest import create_advisory_content
from .conftest import create_group
from .conftest import create_issue
from .conftest import create_package
from .conftest import default_group_dict
from .conftest import default_issue_dict
from .conftest import get_advisory
from .conftest import logged_in


def assert_advisory_data(advisory_id=DEFAULT_ADVISORY_ID, group_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1],
                         publication=Publication.scheduled, workaround=None, impact=None, reference=None):
    advisory = Advisory.query.get(advisory_id)
    assert advisory is not None
    assert advisory_id == advisory.id
    assert advisory.group_package.group == CVEGroup.query.get(group_id)
    assert advisory_type == advisory.advisory_type
    assert publication == advisory.publication
    assert workaround == advisory.workaround
    assert impact == advisory.impact
    assert reference == advisory.reference


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@logged_in
def test_schedule_advisory(db, client):
    resp = client.post(url_for('tracker.schedule_advisory', avg=DEFAULT_GROUP_NAME), follow_redirects=True, data={'advisory_type': issue_types[1]})
    assert 200 == resp.status_code
    assert_advisory_data(DEFAULT_ADVISORY_ID)
    assert 1 == advisory_count()


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@logged_in
def test_schedule_advisory_invalid(db, client):
    resp = client.post(url_for('tracker.schedule_advisory', avg=DEFAULT_GROUP_NAME), data={'advisory_type': 'fooo'})
    assert 302 == resp.status_code
    assert url_for('tracker.show_group', avg=DEFAULT_GROUP_NAME, _external=True) == resp.location


@create_package(name='foo', base='yay', version='1.2.3-4')
@create_package(name='foo2', base='yay', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foo', 'foo2'], affected='1.2.3-3', fixed='1.2.3-4')
@logged_in
def test_schedule_multiple_pkgs_advisory(db, client):
    resp = client.post(url_for('tracker.schedule_advisory', avg=DEFAULT_GROUP_NAME), follow_redirects=True, data={'advisory_type': issue_types[1]})
    assert 200 == resp.status_code
    assert_advisory_data(advisory_get_label(number=1))
    assert_advisory_data(advisory_get_label(number=2))
    assert 2 == advisory_count()


@logged_in
def test_cant_schedule_advisory_with_missing_group(db, client):
    resp = client.post(url_for('tracker.schedule_advisory', avg=DEFAULT_GROUP_NAME), follow_redirects=True, data={'advisory_type': issue_types[1]})
    assert NotFound.code == resp.status_code
    assert 0 == advisory_count()


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
def test_schedule_advisory_needs_login(db, client):
    resp = client.post(url_for('tracker.schedule_advisory', avg=DEFAULT_GROUP_NAME), follow_redirects=True, data={'advisory_type': issue_types[1]})
    assert 200 == resp.status_code
    assert ERROR_LOGIN_REQUIRED in resp.data.decode()
    assert 0 == advisory_count()


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@logged_in(role=UserRole.reporter)
def test_cant_schedule_advisory_as_reporter(db, client):
    resp = client.post(url_for('tracker.schedule_advisory', avg=DEFAULT_GROUP_NAME), follow_redirects=True, data={'advisory_type': issue_types[1]})
    assert Forbidden.code == resp.status_code
    assert 0 == advisory_count()


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foo'], affected='1.2.3-3', fixed='1.2.3-5')
@logged_in
def test_cant_schedule_advisory_if_not_fixed(db, client):
    resp = client.post(url_for('tracker.schedule_advisory', avg=DEFAULT_GROUP_NAME), follow_redirects=True, data={'advisory_type': issue_types[1]})
    assert 200 == resp.status_code
    assert ERROR_ADVISORY_GROUP_NOT_FIXED in resp.data.decode()
    assert 0 == advisory_count()


@create_issue(id='CVE-1111-1111', issue_type=issue_types[1])
@create_issue(id='CVE-1111-2222', issue_type=issue_types[2])
@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=['CVE-1111-1111', 'CVE-1111-2222'], packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, advisory_type='multiple issues')
@logged_in
def test_switch_issue_type_changes_multiple_issues_advisory_to_single(db, client):
    data = default_issue_dict(dict(issue_type=issue_types[1]))
    resp = client.post(url_for('tracker.edit_cve', cve='CVE-1111-2222'), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert_advisory_data(DEFAULT_ADVISORY_ID, advisory_type=issue_types[1])
    assert 1 == advisory_count()


@create_issue(id='CVE-1111-1111', issue_type=issue_types[1])
@create_issue(id='CVE-1111-2222', issue_type=issue_types[1])
@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=['CVE-1111-1111', 'CVE-1111-2222'], packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, advisory_type=issue_types[1])
@logged_in
def test_switch_issue_type_changes_single_issue_advisory_to_multiple(db, client):
    data = default_issue_dict(dict(issue_type=issue_types[2]))
    resp = client.post(url_for('tracker.edit_cve', cve='CVE-1111-2222'), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert_advisory_data(DEFAULT_ADVISORY_ID, advisory_type='multiple issues')
    assert 1 == advisory_count()


@create_issue(id='CVE-1111-1111', issue_type=issue_types[2])
@create_issue(id='CVE-1111-2222', issue_type=issue_types[3])
@create_package(name='foo', base='lol', version='1.2.3-4')
@create_package(name='bar', base='lol', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=['CVE-1111-1111'], packages=['foo', 'bar'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=advisory_get_label(number=1), group_package_id=1, advisory_type=issue_types[2])
@create_advisory(id=advisory_get_label(number=2), group_package_id=2, advisory_type=issue_types[2])
@logged_in
def test_switch_issue_type_changes_multi_package_advisory_to_multiple(db, client):
    data = default_group_dict(dict(
        cve='\n'.join(['CVE-1111-1111', 'CVE-1111-2222']),
        pkgnames='\n'.join(['foo', 'bar']),
    ))
    resp = client.post(url_for('tracker.edit_group', avg=DEFAULT_GROUP_NAME), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert_advisory_data(advisory_get_label(number=1), advisory_type='multiple issues')
    assert_advisory_data(advisory_get_label(number=2), advisory_type='multiple issues')
    assert 2 == advisory_count()


@create_issue(id='CVE-1111-1111', issue_type=issue_types[2])
@create_issue(id='CVE-1111-2222', issue_type=issue_types[3])
@create_package(name='foo', base='lol', version='1.2.3-4')
@create_package(name='bar', base='lol', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=['CVE-1111-1111', 'CVE-1111-2222'], packages=['foo', 'bar'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=advisory_get_label(number=1), group_package_id=1, advisory_type='multiple issues')
@create_advisory(id=advisory_get_label(number=2), group_package_id=2, advisory_type='multiple issues')
@logged_in
def test_switch_issue_type_changes_multi_package_advisory_to_single_type(db, client):
    data = default_group_dict(dict(
        cve='\n'.join(['CVE-1111-1111']),
        pkgnames='\n'.join(['foo', 'bar']),
    ))
    resp = client.post(url_for('tracker.edit_group', avg=DEFAULT_GROUP_NAME), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert_advisory_data(advisory_get_label(number=1), advisory_type=issue_types[2])
    assert_advisory_data(advisory_get_label(number=2), advisory_type=issue_types[2])
    assert 2 == advisory_count()


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1])
@logged_in
def test_cant_schedule_already_existing_advisory(db, client):
    resp = client.post(url_for('tracker.schedule_advisory', avg=DEFAULT_GROUP_NAME), follow_redirects=True, data={'advisory_type': issue_types[1]})
    assert 200 == resp.status_code
    assert ERROR_ADVISORY_ALREADY_EXISTS in resp.data.decode()
    assert None is get_advisory(advisory_get_label(number=2))
    assert 1 == advisory_count()


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1])
@logged_in
def test_edit_advisory(db, client):
    workaround = 'the cake is a lie'
    impact = 'Big shit and deep trouble!'
    resp = client.post(url_for('tracker.edit_advisory', advisory_id=DEFAULT_ADVISORY_ID), follow_redirects=True,
                       data={'workaround': workaround, 'impact': impact})
    assert 200 == resp.status_code
    assert_advisory_data(DEFAULT_ADVISORY_ID, workaround=workaround, impact=impact)
    assert 1 == advisory_count()


@logged_in
def test_edit_advisory_not_found(db, client):
    resp = client.post(url_for('tracker.edit_advisory', advisory_id=DEFAULT_ADVISORY_ID), follow_redirects=True,
                       data={'workaround': 'nothing', 'impact': 'nothing'})
    assert resp.status_code == NotFound.code


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1], reference='https://security.archlinux.org', publication=Publication.published)
@logged_in
def test_warn_if_advisory_already_published(db, client):
    resp = client.get(url_for('tracker.edit_advisory', advisory_id=DEFAULT_ADVISORY_ID), follow_redirects=True)
    assert 200 == resp.status_code
    assert WARNING_ADVISORY_ALREADY_PUBLISHED in resp.data.decode()
    assert 1 == advisory_count()


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1], impact='meh', workaround='yay')
@logged_in(role=UserRole.reporter)
def test_reporter_cant_edit_advisory(db, client):
    workaround = 'the cake is a lie'
    impact = 'Big shit and deep trouble!'
    resp = client.post(url_for('tracker.edit_advisory', advisory_id=DEFAULT_ADVISORY_ID), follow_redirects=True,
                       data={'workaround': workaround, 'impact': impact})
    assert Forbidden.code == resp.status_code
    assert_advisory_data(DEFAULT_ADVISORY_ID, workaround='yay', impact='meh')
    assert 1 == advisory_count()


def test_advisory_get_impact_from_text(db, client):
    impact = advisory_get_impact_from_text(DEFAULT_ADVISORY_CONTENT)
    assert 'Robots will take over' == impact
    assert 'Impact' not in impact
    assert 'References' not in impact


def test_advisory_get_impact_from_text_invalid(db, client):
    assert advisory_get_impact_from_text('test') is None


def test_advisory_get_workaround_from_text(db, client):
    impact = advisory_get_workaround_from_text(DEFAULT_ADVISORY_CONTENT)
    assert 'Update your machine' in impact
    assert 'Workaround' not in impact
    assert 'Description' not in impact


def test_advisory_get_workaround_from_text_no_workaround(db, client):
    workaround = advisory_get_workaround_from_text(create_advisory_content(workaround='None.'))
    assert workaround is None


def test_advisory_get_workaround_from_text_invalid(db, client):
    assert advisory_get_workaround_from_text('test') is None


def test_generated_advisory_not_found(db, client):
    resp = client.get(url_for('tracker.show_generated_advisory', advisory_id=DEFAULT_ADVISORY_ID), follow_redirects=True)
    assert NotFound.code == resp.status_code


@create_package(name='foo', version='1.2.3-4')
@create_issue(description='foo is broken and foo.')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4', issues=[DEFAULT_ISSUE_ID])
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1])
def test_advisory_html_replace_package_name(db, client):
    resp = client.get(url_for('tracker.show_generated_advisory', advisory_id=DEFAULT_ADVISORY_ID), follow_redirects=True)
    assert 200 == resp.status_code
    data = resp.data.decode()
    assert '<a href="/package/foo" rel="noopener">foo</a> is broken' in data
    assert 'and <a href="/package/foo" rel="noopener">foo</a>' in data


@create_package(name='foo', version='1.2.3-4')
@create_issue(description='FoO is broken and fOO.')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4', issues=[DEFAULT_ISSUE_ID])
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1])
def test_advisory_html_replace_package_name_case_insensitive(db, client):
    resp = client.get(url_for('tracker.show_generated_advisory', advisory_id=DEFAULT_ADVISORY_ID), follow_redirects=True)
    assert 200 == resp.status_code
    data = resp.data.decode()
    assert '<a href="/package/foo" rel="noopener">FoO</a> is broken' in data
    assert 'and <a href="/package/foo" rel="noopener">fOO</a>.' in data


@create_package(name='foo', version='1.2.3-4')
@create_issue(id='CVE-1234-1234', description='foo is broken and foo.')
@create_issue(id='CVE-1234-12345', description='foo is broken and foo.')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4', issues=['CVE-1234-1234', 'CVE-1234-12345'])
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1])
def test_advisory_html_overlapping_cve_link(db, client):
    resp = client.get(url_for('tracker.show_generated_advisory', advisory_id=DEFAULT_ADVISORY_ID), follow_redirects=True)
    assert 200 == resp.status_code
    data = resp.data.decode()
    assert '<a href="/{0}" rel="noopener">{0}</a>'.format('CVE-1234-1234') in data
    assert '<a href="/{0}" rel="noopener">{0}</a>'.format('CVE-1234-12345') in data


@create_package(name='crypto++', version='1.2.3-4')
@create_issue(description='crypto++ is broken and crypto++.')
@create_group(id=DEFAULT_GROUP_ID, packages=['crypto++'], affected='1.2.3-3', fixed='1.2.3-4', issues=[DEFAULT_ISSUE_ID])
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1])
def test_advisory_html_regex_keyword_in_package_name(db, client):
    resp = client.get(url_for('tracker.show_generated_advisory', advisory_id=DEFAULT_ADVISORY_ID), follow_redirects=True)
    assert 200 == resp.status_code
    data = resp.data.decode()
    assert '<a href="/package/crypto++" rel="noopener">crypto++</a> is broken' in data
    assert 'and <a href="/package/crypto++" rel="noopener">crypto++</a>' in data


@create_package(name='foo', version='1.2.3-4')
@create_issue(id='CVE-1234-1234')
@create_issue(id='CVE-1234-12345')
@create_issue(id='CVE-1111-12345')
@create_issue(id='CVE-1234-11111')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4',
              issues=['CVE-1234-1234', 'CVE-1234-12345', 'CVE-1111-12345', 'CVE-1234-11111'])
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1])
def test_advisory_cve_listing_sorted_numerically(db, client):
    resp = client.get(url_for('tracker.show_generated_advisory_raw', advisory_id=DEFAULT_ADVISORY_ID), follow_redirects=True)
    assert 200 == resp.status_code
    data = resp.data.decode()
    assert '\n'.join(['CVE-1111-12345', 'CVE-1234-1234', 'CVE-1234-11111', 'CVE-1234-12345']) in data.replace('https://security.archlinux.org/', '')


def test_advisory_atom_no_data(db, client):
    resp = client.get(url_for('tracker.advisory_atom'), follow_redirects=True)
    assert 404 == resp.status_code
    # TODO: re-enable feed test
    # data = resp.data.decode()
    # assert DEFAULT_ADVISORY_ID not in data


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1], reference='https://security.archlinux.org', publication=Publication.published)
def test_advisory_atom(db, client):
    resp = client.get(url_for('tracker.advisory_atom'), follow_redirects=True)
    assert 404 == resp.status_code
    # TODO: re-enable feed test
    # data = resp.data.decode()
    # assert DEFAULT_ADVISORY_ID in data


def test_advisory_json_no_data(db, client):
    resp = client.get(url_for('tracker.advisory_json', postfix='/json'), follow_redirects=True)
    assert 200 == resp.status_code
    data = resp.get_json()
    assert data == []


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1], reference='https://security.archlinux.org', publication=Publication.published)
def test_advisory_json(db, client):
    resp = client.get(url_for('tracker.advisory_json', postfix='/json'), follow_redirects=True)
    assert 200 == resp.status_code
    data = resp.get_json()
    assert len(data) == 1
    assert data[0]['name'] == DEFAULT_ADVISORY_ID
    assert data[0]['group'] == DEFAULT_GROUP_NAME


@create_package(name='foo', version='1.2.3-4')
@create_issue(id='CVE-1234-1234', description='qux AVG-1 is broken and foo.')
@create_issue(id='CVE-1234-12345', description='bar https://foo.bar is broken and lol CVE-1111-2222.')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4', issues=['CVE-1234-1234', 'CVE-1234-12345'])
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1])
def test_advisory_html_urlize_description(db, client):
    resp = client.get(url_for('tracker.show_generated_advisory', advisory_id=DEFAULT_ADVISORY_ID), follow_redirects=True)
    assert 200 == resp.status_code
    data = resp.data.decode()
    assert 'qux <a href="/{0}" rel="noopener">{0}</a> is'.format('AVG-1') in data
    assert 'bar <a href="{0}" rel="noopener">{0}</a> is'.format('https://foo.bar') in data
    assert 'lol <a href="/{0}" rel="noopener">{0}</a>.'.format('CVE-1111-2222') in data


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4',
              issues=['CVE-1111-1234', 'CVE-1234-12345', 'CVE-1111-12345', 'CVE-1234-11111',
                      'CVE-1234-11112', 'CVE-1234-123456'])
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1])
def test_advisory_format_issue_listing_raw(db, client):
    resp = client.get(url_for('tracker.show_generated_advisory_raw',
                              advisory_id=DEFAULT_ADVISORY_ID),
                      follow_redirects=True)
    assert 200 == resp.status_code
    data = resp.data.decode()
    assert 'CVE-ID  : CVE-1111-1234  CVE-1111-12345  CVE-1234-11111 CVE-1234-11112\n' + \
           '          CVE-1234-12345 CVE-1234-123456\n' in data


def test_advisory_format_issue_listing():
    listing = advisory_format_issue_listing(
        ['CVE-1111-1234', 'CVE-1111-12345', 'CVE-1234-11111', 'CVE-1234-11112',
         'CVE-1234-12345', 'CVE-1234-123456'])
    assert 'CVE-1111-1234  CVE-1111-12345  CVE-1234-11111 CVE-1234-11112\n          ' + \
           'CVE-1234-12345 CVE-1234-123456' == listing


def test_advisory_format_issue_listing_single_row():
    listing = advisory_format_issue_listing(
        ['CVE-1111-1234', 'CVE-1111-12345', 'CVE-1234-11111', 'CVE-1234-11112'])
    assert 'CVE-1111-1234 CVE-1111-12345 CVE-1234-11111 CVE-1234-11112' == listing


def test_advisory_format_issue_listing_single_issue():
    listing = advisory_format_issue_listing(['CVE-1111-1234'])
    assert 'CVE-1111-1234' == listing


@mark.parametrize('patch_get', [404], indirect=True)
@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1])
@logged_in
def test_advisory_publish_advisory_not_found(db, client, patch_get):
    resp = client.post(url_for('tracker.publish_advisory', asa=DEFAULT_ADVISORY_ID), follow_redirects=True,
                       data=dict(reference='https://archlinux.org', confirm=True))
    assert 200 == resp.status_code
    assert 'Failed to fetch advisory' in resp.data.decode()


@mark.parametrize('patch_get', ['No advisory'], indirect=True)
@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1])
@logged_in
def test_advisory_publish_advisory_text_wrong(db, client, patch_get):
    resp = client.post(url_for('tracker.publish_advisory', asa=DEFAULT_ADVISORY_ID), follow_redirects=True,
                       data=dict(reference='https://archlinux.org', confirm=True))
    assert 200 == resp.status_code
    assert 'Failed to fetch advisory' in resp.data.decode()


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1])
@logged_in
def test_advisory_publish_advisory(db, client, patch_get):
    resp = client.post(url_for('tracker.publish_advisory', asa=DEFAULT_ADVISORY_ID), follow_redirects=True,
                       data=dict(reference=f'https://security.archlinux.org/{DEFAULT_ADVISORY_ID}', confirm=True))
    assert 200 == resp.status_code
    assert 'Published {}'.format(DEFAULT_ADVISORY_ID) in resp.data.decode()


@create_issue(id='CVE-1234-1234', description='qux AVG-1 is broken and foo.')
@create_issue(id='CVE-1234-12345', description='bar https://foo.bar is broken and lol CVE-1111-2222.')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4', issues=['CVE-1234-1234', 'CVE-1234-12345'])
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1])
def test_advisory_raw(db, client):
    resp = client.get(url_for('tracker.show_advisory_raw', advisory_id=DEFAULT_ADVISORY_ID), follow_redirects=True)
    assert 200 == resp.status_code
    data = resp.data.decode()
    assert 'Arch Linux Security Advisory {}'.format(DEFAULT_ADVISORY_ID) in data


@logged_in
def test_show_advisory_not_found(db, client, patch_get):
    resp = client.get(url_for('tracker.show_advisory', advisory_id=DEFAULT_ADVISORY_ID), follow_redirects=True)
    assert NotFound.code == resp.status_code


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1],
                 content=create_advisory_content(description='<description>', impact='<impact>', workaround='<workaround>'))
@logged_in
def test_advisory_published_html_content_escaped(db, client, patch_get):
    resp = client.get(url_for('tracker.show_advisory', advisory_id=DEFAULT_ADVISORY_ID), follow_redirects=True)
    assert 200 == resp.status_code
    data = resp.data.decode()
    assert '<description>' not in data
    assert '<impact>' not in data
    assert '<workaround>' not in data


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1],
                 content=create_advisory_content(description='<description>', impact='<impact>', workaround='<workaround>'))
@logged_in
def test_advisory_published_raw_content_unescaped(db, client, patch_get):
    resp = client.get(url_for('tracker.show_advisory_raw', advisory_id=DEFAULT_ADVISORY_ID), follow_redirects=True)
    assert 200 == resp.status_code
    data = resp.data.decode()
    assert '<description>' in data
    assert '<impact>' in data
    assert '<workaround>' in data


@create_package(name='foo', version='1.2.3-4')
@create_issue(description='foo is broken and <snafu>.')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4', issues=[DEFAULT_ISSUE_ID])
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1], impact='<omg>', workaround='<uninstall>')
def test_advisory_html_content_escaped(db, client):
    resp = client.get(url_for('tracker.show_generated_advisory', advisory_id=DEFAULT_ADVISORY_ID), follow_redirects=True)
    assert 200 == resp.status_code
    data = resp.data.decode()
    assert '<snafu>' not in data
    assert '<img>' not in data
    assert '<uninstall>' not in data


@create_package(name='foo', version='1.2.3-4')
@create_issue(description='foo is broken and <snafu>.')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4', issues=[DEFAULT_ISSUE_ID])
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1], impact='<omg>', workaround='<uninstall>')
def test_advisory_raw_content_unescaped(db, client):
    resp = client.get(url_for('tracker.show_generated_advisory_raw', advisory_id=DEFAULT_ADVISORY_ID), follow_redirects=True)
    assert 200 == resp.status_code
    data = resp.data.decode()
    assert '<snafu>' in data
    assert '<omg>' in data
    assert '<uninstall>' in data


@logged_in
def test_delete_advisory_not_found(db, client):
    resp = client.get(url_for('tracker.delete_advisory', advisory_id=9999), follow_redirects=True)
    assert NotFound.code == resp.status_code


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1], publication=Publication.published)
@logged_in
def test_delete_advisory_published(db, client):
    resp = client.get(url_for('tracker.delete_advisory', advisory_id=DEFAULT_ADVISORY_ID), follow_redirects=True)
    assert Forbidden.code == resp.status_code

def test_advisory_extend_html():
    package = namedtuple('package', 'pkgname')
    pkgname = 'foo'
    pkg = package(pkgname)
    id = DEFAULT_ADVISORY_ID
    cve = 'CVE-1111-2222'
    group = DEFAULT_GROUP_NAME
    pkgver = '1.0-1'
    references = f'https://security.{pkgname}.com/{pkgname}'
    workaround = f"""{pkgname} yap
A {pkgname} yap
Foo {pkgname}."""
    description = ''
    impact = ''
    advisory_text = create_advisory_content(id=id, cve=cve, group=group, pkgname=pkgname, pkgver=pkgver, workaround=workaround, description=description, impact=impact, references=references)
    expected = f"""Arch Linux Security Advisory {id}
==========================================

Severity: Critical
Date    : 2012-12-21
CVE-ID  : {cve}
Package : <a href="/package/{pkgname}" rel="noopener">{pkgname}</a>
Type    : arbitrary code execution
Remote  : Yes
Link    : https://security.archlinux.org/{group}

Summary
=======

The package <a href="/package/{pkgname}" rel="noopener">{pkgname}</a> before version {pkgver} is vulnerable to arbitrary
code execution.

Resolution
==========

Upgrade to {pkgver}.

# pacman -Syu "<a href="/package/{pkgname}" rel="noopener">{pkgname}</a>>={pkgver}"

The problem has been fixed upstream in version {pkgver}.

Workaround
==========

<a href="/package/{pkgname}" rel="noopener">{pkgname}</a> yap
A <a href="/package/{pkgname}" rel="noopener">{pkgname}</a> yap
<a href="/package/{pkgname}" rel="noopener">Foo</a> <a href="/package/{pkgname}" rel="noopener">{pkgname}</a>.

Description
===========

{description}

Impact
======

{impact}

References
==========

https://security.archlinux.org/{group}
{references}
"""

    assert expected == advisory_extend_html(advisory_text, [], pkg)


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1],
                 content=create_advisory_content(description='<description>', impact='<impact>', workaround='<workaround>'),
                 publication=Publication.published)
@logged_in
def test_advisory_published_content_not_overescaped(db, client, patch_get):
    resp = client.get(url_for('tracker.show_advisory', advisory_id=DEFAULT_ADVISORY_ID), follow_redirects=True)
    assert 200 == resp.status_code
    data = resp.data.decode()
    assert str(escape('<a href>')) not in data


@create_package(name='foo', version='1.2.3-4')
@create_issue(description='foo is broken and <snafu>.')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4', issues=[DEFAULT_ISSUE_ID])
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1], impact='<omg>', workaround='<uninstall>')
def test_advisory_generated_content_not_over_escaped(db, client):
    resp = client.get(url_for('tracker.show_generated_advisory', advisory_id=DEFAULT_ADVISORY_ID), follow_redirects=True)
    assert 200 == resp.status_code
    data = resp.data.decode()
    assert str(escape('<a href')) not in data


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1])
@logged_in
def test_advisory_published_content_not_over_escaped(db, client, patch_get):
    resp = client.post(url_for('tracker.publish_advisory', asa=DEFAULT_ADVISORY_ID), follow_redirects=True,
                       data=dict(reference=f'https://security.archlinux.org/{DEFAULT_ADVISORY_ID}', confirm=True))
    assert 200 == resp.status_code
    assert 'Published {}'.format(DEFAULT_ADVISORY_ID) in resp.data.decode()

    resp = client.get(url_for('tracker.show_advisory', advisory_id=DEFAULT_ADVISORY_ID), follow_redirects=True)
    assert 200 == resp.status_code
    data = resp.data.decode()
    assert str(escape('<a href')) not in data


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1], impact='', workaround='')
@logged_in
def test_edit_advisory_non_relational_field_updates_changed_date(db, client):
    advisory_changed_old = Advisory.query.get(DEFAULT_ADVISORY_ID).changed

    data = dict(impact='everything beyond repair', workaround='set computer on fire')
    resp = client.post(url_for('tracker.edit_advisory', advisory_id=DEFAULT_ADVISORY_ID), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert f'Edited {DEFAULT_ADVISORY_ID}' in resp.data.decode()

    advisory = Advisory.query.get(DEFAULT_ADVISORY_ID)
    assert advisory.changed > advisory_changed_old


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1], impact='everything beyond repair', workaround='set computer on fire')
@logged_in
def test_edit_advisory_does_nothing_when_data_is_same(db, client):
    advisory_changed_old = Advisory.query.get(DEFAULT_ADVISORY_ID).changed

    data = dict(impact='everything beyond repair', workaround='set computer on fire')
    resp = client.post(url_for('tracker.edit_advisory', advisory_id=DEFAULT_ADVISORY_ID), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert f'Edited {DEFAULT_ADVISORY_ID}' not in resp.data.decode()

    advisory = Advisory.query.get(DEFAULT_ADVISORY_ID)
    assert advisory.changed == advisory_changed_old
