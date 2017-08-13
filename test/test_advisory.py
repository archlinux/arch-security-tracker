from werkzeug.exceptions import NotFound, Forbidden
from flask import url_for

from .conftest import logged_in, create_issue, create_package, create_group, create_advisory, advisory_count, get_advisory, DEFAULT_GROUP_ID, DEFAULT_GROUP_NAME, DEFAULT_ISSUE_ID, DEFAULT_ADVISORY_ID, ERROR_LOGIN_REQUIRED, default_issue_dict, DEFAULT_ADVISORY_CONTENT
from app.advisory import advisory_get_label, advisory_get_impact_from_text, advisory_get_workaround_from_text
from app.model.enum import UserRole, Publication
from app.model.cve import issue_types
from app.model.cvegroup import CVEGroup
from app.model.advisory import Advisory
from app.view.advisory import ERROR_ADVISORY_GROUP_NOT_FIXED, ERROR_ADVISORY_ALREADY_EXISTS
from app.view.edit import WARNING_ADVISORY_ALREADY_PUBLISHED


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
    resp = client.post(url_for('schedule_advisory', avg=DEFAULT_GROUP_NAME), follow_redirects=True, data={'advisory_type': issue_types[1]})
    assert 200 == resp.status_code
    assert_advisory_data(DEFAULT_ADVISORY_ID)
    assert 1 == advisory_count()


@create_package(name='foo', base='yay', version='1.2.3-4')
@create_package(name='foo2', base='yay', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foo', 'foo2'], affected='1.2.3-3', fixed='1.2.3-4')
@logged_in
def test_schedule_multiple_pkgs_advisory(db, client):
    resp = client.post(url_for('schedule_advisory', avg=DEFAULT_GROUP_NAME), follow_redirects=True, data={'advisory_type': issue_types[1]})
    assert 200 == resp.status_code
    assert_advisory_data(advisory_get_label(number=1))
    assert_advisory_data(advisory_get_label(number=2))
    assert 2 == advisory_count()


@logged_in
def test_cant_schedule_advisory_with_missing_group(db, client):
    resp = client.post(url_for('schedule_advisory', avg=DEFAULT_GROUP_NAME), follow_redirects=True, data={'advisory_type': issue_types[1]})
    assert NotFound.code == resp.status_code
    assert 0 == advisory_count()


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
def test_schedule_advisory_needs_login(db, client):
    resp = client.post(url_for('schedule_advisory', avg=DEFAULT_GROUP_NAME), follow_redirects=True, data={'advisory_type': issue_types[1]})
    assert 200 == resp.status_code
    assert ERROR_LOGIN_REQUIRED in resp.data.decode()
    assert 0 == advisory_count()


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@logged_in(role=UserRole.reporter)
def test_cant_schedule_advisory_as_reporter(db, client):
    resp = client.post(url_for('schedule_advisory', avg=DEFAULT_GROUP_NAME), follow_redirects=True, data={'advisory_type': issue_types[1]})
    assert Forbidden.code == resp.status_code
    assert 0 == advisory_count()


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foo'], affected='1.2.3-3', fixed='1.2.3-5')
@logged_in
def test_cant_schedule_advisory_if_not_fixed(db, client):
    resp = client.post(url_for('schedule_advisory', avg=DEFAULT_GROUP_NAME), follow_redirects=True, data={'advisory_type': issue_types[1]})
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
    resp = client.post(url_for('edit_cve', cve='CVE-1111-2222'), follow_redirects=True, data=data)
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
    resp = client.post(url_for('edit_cve', cve='CVE-1111-2222'), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert_advisory_data(DEFAULT_ADVISORY_ID, advisory_type='multiple issues')
    assert 1 == advisory_count()


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1])
@logged_in
def test_cant_schedule_already_existing_advisory(db, client):
    resp = client.post(url_for('schedule_advisory', avg=DEFAULT_GROUP_NAME), follow_redirects=True, data={'advisory_type': issue_types[1]})
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
    resp = client.post(url_for('edit_advisory', advisory_id=DEFAULT_ADVISORY_ID), follow_redirects=True,
                       data={'workaround': workaround, 'impact': impact})
    assert 200 == resp.status_code
    assert_advisory_data(DEFAULT_ADVISORY_ID, workaround=workaround, impact=impact)
    assert 1 == advisory_count()


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1], reference='https://security.archlinux.org', publication=Publication.published)
@logged_in
def test_warn_if_advisory_already_published(db, client):
    resp = client.get(url_for('edit_advisory', advisory_id=DEFAULT_ADVISORY_ID), follow_redirects=True)
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
    resp = client.post(url_for('edit_advisory', advisory_id=DEFAULT_ADVISORY_ID), follow_redirects=True,
                       data={'workaround': workaround, 'impact': impact})
    assert Forbidden.code == resp.status_code
    assert_advisory_data(DEFAULT_ADVISORY_ID, workaround='yay', impact='meh')
    assert 1 == advisory_count()


def test_advisory_get_impact_from_text(db, client):
    impact = advisory_get_impact_from_text(DEFAULT_ADVISORY_CONTENT)
    assert 'Robots will take over' in impact
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
    content = '\nWorkaround\n==========\n\nNone.\n\nDescription\n'
    impact = advisory_get_workaround_from_text(content)
    assert impact is None


def test_advisory_get_workaround_from_text_invalid(db, client):
    assert advisory_get_workaround_from_text('test') is None
