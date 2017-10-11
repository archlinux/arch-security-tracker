import json
from werkzeug.exceptions import NotFound, Forbidden
from flask import url_for

from .conftest import logged_in, create_issue, create_package, create_group, create_advisory, DEFAULT_GROUP_ID, DEFAULT_ISSUE_ID, DEFAULT_ADVISORY_ID, ERROR_LOGIN_REQUIRED, ERROR_INVALID_CHOICE, default_issue_dict
from app.model.enum import Remote, Severity, UserRole
from app.model.cve import issue_types, CVE
from app.form import CVEForm
from app.form.validators import ERROR_ISSUE_ID_INVALID, ERROR_INVALID_URL
from app.view.add import CVE_MERGED, CVE_MERGED_PARTIALLY


def set_and_assert_cve_data(db, client, cve_id, route):
    issue_type = issue_types[1]
    remote = Remote.remote
    severity = Severity.critical
    description = 'very important description\nstuff'
    notes = 'foobar\n1234'
    reference = 'https://security.archlinux.org/'
    resp = client.post(route, follow_redirects=True,
                       data=dict(cve=cve_id,
                                 issue_type=issue_type,
                                 remote=remote.name,
                                 severity=severity.name,
                                 description=description,
                                 notes=notes,
                                 reference=reference))
    assert 200 == resp.status_code

    cve = CVE.query.get(cve_id)
    assert cve_id == cve.id
    assert issue_type == cve.issue_type
    assert remote == cve.remote
    assert severity == cve.severity
    assert description == cve.description
    assert notes == cve.notes
    assert reference == cve.reference


@logged_in
def test_add_cve(db, client):
    set_and_assert_cve_data(db, client, 'CVE-1122-0042', url_for('add_cve'))


@logged_in(role=UserRole.reporter)
def test_reporter_can_add(db, client):
    resp = client.post(url_for('add_cve'), follow_redirects=True, data=default_issue_dict())
    assert 200 == resp.status_code
    cve = CVE.query.get(DEFAULT_ISSUE_ID)
    assert DEFAULT_ISSUE_ID == cve.id


@create_issue
def test_add_needs_login(db, client):
    resp = client.post(url_for('add_cve'), follow_redirects=True,
                       data=default_issue_dict())
    assert ERROR_LOGIN_REQUIRED in resp.data.decode()


@logged_in
def test_add_invalid_cve_id(db, client):
    cve_id = 'LOL'
    data = default_issue_dict()
    data.update(dict(cve=cve_id))
    resp = client.post(url_for('add_cve'), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert ERROR_ISSUE_ID_INVALID in resp.data.decode()


@logged_in
def test_cve_id_suffix_too_short(db, client):
    cve_id = 'CVE-1234-123'
    data = default_issue_dict()
    data.update(dict(cve=cve_id))
    resp = client.post(url_for('add_cve'), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert ERROR_ISSUE_ID_INVALID in resp.data.decode()


@logged_in
def test_cve_id_suffix_long(db, client):
    cve_id = 'CVE-1234-12345678'
    data = default_issue_dict()
    data.update(dict(cve=cve_id))
    resp = client.post(url_for('add_cve'), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert ERROR_ISSUE_ID_INVALID not in resp.data.decode()


@logged_in
def test_add_invalid_reference(db, client):
    reference = 'OMG'
    data = default_issue_dict()
    data.update(dict(reference=reference))
    resp = client.post(url_for('add_cve'), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert ERROR_INVALID_URL.format(reference) in resp.data.decode()


@logged_in
def test_add_invalid_severity(db, client):
    data = default_issue_dict()
    data.update(dict(severity='OMG'))
    resp = client.post(url_for('add_cve'), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert ERROR_INVALID_CHOICE in resp.data.decode()
    assert 1 == resp.data.decode().count(ERROR_INVALID_CHOICE)


@logged_in
def test_add_invalid_remote(db, client):
    data = default_issue_dict()
    data.update(dict(remote='OMG'))
    resp = client.post(url_for('add_cve'), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert ERROR_INVALID_CHOICE in resp.data.decode()
    assert 1 == resp.data.decode().count(ERROR_INVALID_CHOICE)


@logged_in
def test_add_invalid_type(db, client):
    data = default_issue_dict()
    data.update(dict(issue_type='OMG'))
    resp = client.post(url_for('add_cve'), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert ERROR_INVALID_CHOICE in resp.data.decode()
    assert 1 == resp.data.decode().count(ERROR_INVALID_CHOICE)


@create_issue
@logged_in
def test_edit_cve(db, client):
    set_and_assert_cve_data(db, client, DEFAULT_ISSUE_ID, url_for('edit_cve', cve=DEFAULT_ISSUE_ID))


@create_issue
@logged_in(role=UserRole.reporter)
def test_reporter_can_edit(db, client):
    description = 'LOLWUT'
    data = default_issue_dict()
    data.update(dict(description=description))
    resp = client.post(url_for('edit_cve', cve=DEFAULT_ISSUE_ID), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    cve = CVE.query.get(DEFAULT_ISSUE_ID)
    assert description == cve.description


@create_issue
@logged_in(role=UserRole.reporter)
def test_reporter_can_delete(db, client):
    resp = client.post(url_for('delete_issue', issue=DEFAULT_ISSUE_ID), follow_redirects=True,
                       data=dict(confirm=True))
    assert 200 == resp.status_code
    cve = CVE.query.get(DEFAULT_ISSUE_ID)
    assert cve is None


@create_issue
@logged_in(role=UserRole.reporter)
def test_reporter_can_copy(db, client):
    resp = client.get(url_for('copy_issue', issue=DEFAULT_ISSUE_ID), follow_redirects=True)
    assert 200 == resp.status_code
    assert ERROR_LOGIN_REQUIRED not in resp.data.decode()


@create_issue
@logged_in(role=UserRole.reporter)
def test_abort_delete(db, client):
    resp = client.post(url_for('delete_issue', issue=DEFAULT_ISSUE_ID), follow_redirects=True,
                       data=dict(abort=True))
    assert 200 == resp.status_code
    cve = CVE.query.get(DEFAULT_ISSUE_ID)
    assert DEFAULT_ISSUE_ID == cve.id


@create_issue
def test_edit_needs_login(db, client):
    resp = client.post(url_for('edit_cve', cve=DEFAULT_ISSUE_ID), follow_redirects=True)
    assert ERROR_LOGIN_REQUIRED in resp.data.decode()


@create_issue
def test_delete_needs_login(db, client):
    resp = client.post(url_for('delete_issue', issue=DEFAULT_ISSUE_ID), follow_redirects=True)
    assert ERROR_LOGIN_REQUIRED in resp.data.decode()


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1])
@logged_in
def test_forbid_delete_with_advisory(db, client):
    resp = client.post(url_for('delete_issue', issue=DEFAULT_ISSUE_ID), follow_redirects=True)
    assert Forbidden.code == resp.status_code


@create_issue
def test_copy_needs_login(db, client):
    resp = client.get(url_for('copy_issue', issue=DEFAULT_ISSUE_ID), follow_redirects=True)
    assert ERROR_LOGIN_REQUIRED in resp.data.decode()


@create_issue
def test_show_issue(db, client):
    resp = client.get(url_for('show_cve', cve=DEFAULT_ISSUE_ID, path=''))
    assert 200 == resp.status_code
    assert DEFAULT_ISSUE_ID in resp.data.decode()


@logged_in
def test_show_issue_not_found(db, client):
    resp = client.get(url_for('show_cve', cve='CVE-2011-0000', path=''), follow_redirects=True)
    assert resp.status_code == NotFound.code


@logged_in
def test_edit_issue_not_found(db, client):
    resp = client.post(url_for('edit_cve', cve='CVE-2011-0000'), follow_redirects=True,
                       data=default_issue_dict())
    assert resp.status_code == NotFound.code


@logged_in
def test_copy_issue_not_found(db, client):
    resp = client.get(url_for('copy_issue', issue='CVE-2011-0000', path=''), follow_redirects=True)
    assert resp.status_code == NotFound.code


@logged_in
def test_delete_issue_not_found(db, client):
    resp = client.post(url_for('delete_issue', issue='CVE-2011-0000'), follow_redirects=True)
    assert resp.status_code == NotFound.code


@create_issue
def test_issue_json(db, client):
    resp = client.get(url_for('show_cve_json', cve=DEFAULT_ISSUE_ID, path='', suffix='.json'), follow_redirects=True)
    assert 200 == resp.status_code

    data = json.loads(resp.data)
    assert DEFAULT_ISSUE_ID == data['name']


@create_issue
@logged_in
def test_add_cve_overwrites_existing_but_empty_cve(db, client):
    issue_type = issue_types[1]
    severity = Severity.critical
    remote = Remote.remote
    description = 'much wow'
    reference = 'https://security.archlinux.org'
    notes = 'very secret'
    resp = client.post(url_for('add_cve'), follow_redirects=True, data=default_issue_dict(dict(
                       cve=DEFAULT_ISSUE_ID,
                       issue_type=issue_type,
                       severity=severity.name,
                       remote=remote.name,
                       description=description,
                       reference=reference,
                       notes=notes)))
    assert 200 == resp.status_code
    assert CVE_MERGED.format(DEFAULT_ISSUE_ID) in resp.data.decode()
    assert CVE_MERGED_PARTIALLY.format(DEFAULT_ISSUE_ID, '') not in resp.data.decode()

    cve = CVE.query.get(DEFAULT_ISSUE_ID)
    assert DEFAULT_ISSUE_ID == cve.id
    assert issue_type == cve.issue_type
    assert severity == cve.severity
    assert remote == cve.remote
    assert description == cve.description
    assert reference == cve.reference
    assert notes == cve.notes


@create_issue(issue_type=issue_types[3], severity=Severity.low, remote=Remote.local,
              description='foobar', reference='https://archlinux.org', notes='the cake is a lie')
@logged_in
def test_add_cve_does_not_overwrite_existing_cve(db, client):
    resp = client.post(url_for('add_cve'), follow_redirects=True, data=default_issue_dict(dict(
                       cve=DEFAULT_ISSUE_ID,
                       issue_type=issue_types[1],
                       severity=Severity.critical.name,
                       remote=Remote.remote.name,
                       description='deadbeef',
                       reference='https://security.archlinux.org',
                       notes='very secret')))
    assert 200 == resp.status_code

    assert CVE_MERGED.format(DEFAULT_ISSUE_ID) in resp.data.decode()
    form = CVEForm()
    unmerged_fields = [form.issue_type.label.text,
                       form.severity.label.text,
                       form.remote.label.text,
                       form.description.label.text,
                       form.notes.label.text]
    assert CVE_MERGED_PARTIALLY.format(DEFAULT_ISSUE_ID, ', '.join(unmerged_fields)) in resp.data.decode()

    cve = CVE.query.get(DEFAULT_ISSUE_ID)
    assert DEFAULT_ISSUE_ID == cve.id
    assert issue_types[3] == cve.issue_type
    assert Severity.low == cve.severity
    assert Remote.local == cve.remote
    assert 'foobar' == cve.description
    assert 'https://archlinux.org\nhttps://security.archlinux.org' == cve.reference
    assert 'the cake is a lie' == cve.notes
