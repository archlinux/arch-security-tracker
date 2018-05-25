from flask import url_for

from tracker.advisory import advisory_get_label
from tracker.model.cve import issue_types
from tracker.model.enum import Publication
from tracker.model.enum import Remote
from tracker.model.enum import Severity
from tracker.model.enum import Status

from .conftest import DEFAULT_ADVISORY_ID
from .conftest import DEFAULT_GROUP_ID
from .conftest import DEFAULT_GROUP_NAME
from .conftest import create_advisory
from .conftest import create_group
from .conftest import create_issue
from .conftest import create_package


@create_issue(id='CVE-1111-1111', issue_type=issue_types[2])
@create_issue(id='CVE-1111-2222', issue_type=issue_types[2])
@create_package(name='foo', base='lol', version='1.2.3-4')
@create_package(name='bar', base='lol', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=['CVE-1111-1111'], packages=['foo', 'bar'], affected='1.2.3-3', fixed='1.2.3-4')
def test_todo_success(db, client):
    resp = client.get(url_for('tracker.todo'))
    assert 200 == resp.status_code


@create_issue(id='CVE-1111-1111', issue_type=issue_types[2])
@create_issue(id='CVE-1111-2222', issue_type=issue_types[2])
@create_issue(id='CVE-1111-3333', issue_type=issue_types[2], remote=Remote.local, description='w00t', severity=Severity.high)
@create_package(name='foo', base='lol', version='1.2.3-4')
@create_package(name='bar', base='lol', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=['CVE-1111-1111'], packages=['foo', 'bar'], affected='1.2.3-3', fixed='1.2.3-4')
@create_group(id=123, issues=['CVE-1111-2222'], packages=['foo', 'bar'], affected='1.2.3-3', fixed='1.2.3-4')
@create_group(id=456, issues=['CVE-1111-2222'], packages=['foo', 'bar'], affected='1.2.3-3')
@create_group(id=789, issues=['CVE-1111-2222'], packages=['foo', 'bar'], affected='1.2.3-3', status=Status.unknown)
@create_group(id=4242, issues=['CVE-1111-2222'], packages=['foo', 'bar'], affected='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, advisory_type='multiple issues')
@create_advisory(id=advisory_get_label(number=2), group_package_id=2, advisory_type='multiple issues', publication=Publication.published)
def test_todo_json_success(db, client):
    resp = client.get(url_for('tracker.todo_json', postfix='.json'))
    assert 200 == resp.status_code

    data = resp.get_json()
    assert data['advisories']['scheduled']
    assert data['advisories']['incomplete']
    assert data['advisories']['unhandled']

    assert data['groups']['unknown']
    assert data['groups']['bumped']

    assert data['issues']['orphan_issues']
    assert data['issues']['unknown_issues']


def test_todo_json_empty(db, client):
    resp = client.get(url_for('tracker.todo_json', postfix='.json'))
    assert 200 == resp.status_code

    data = resp.get_json()
    assert not data['advisories']['scheduled']
    assert not data['advisories']['incomplete']
    assert not data['advisories']['unhandled']

    assert not data['groups']['unknown']
    assert not data['groups']['bumped']

    assert not data['issues']['orphan_issues']
    assert not data['issues']['unknown_issues']


@create_issue(id='CVE-1111-1111', issue_type=issue_types[2])
@create_package(name='foo', base='lol', version='1.2.3-4')
@create_package(name='bar', base='lol', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=['CVE-1111-1111'], packages=['foo', 'bar'], affected='1.2.3-3', fixed='1.2.3-4')
def test_todo_advisory_unhandled(db, client):
    resp = client.get(url_for('tracker.todo_json', postfix='.json'))
    assert 200 == resp.status_code

    data = resp.get_json()
    assert 1 == len(data['advisories']['unhandled'])

    advisory = next(iter(data['advisories']['unhandled']))
    assert advisory['name'] == DEFAULT_GROUP_NAME
    assert advisory['status'] == Status.fixed


@create_issue(id='CVE-1111-1111', issue_type=issue_types[2])
@create_package(name='foo', base='lol', version='1.2.3-4')
@create_package(name='bar', base='lol', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=['CVE-1111-1111'], packages=['foo', 'bar'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=2, publication=Publication.scheduled)
def test_todo_advisory_scheduled(db, client):
    resp = client.get(url_for('tracker.todo_json', postfix='.json'))
    assert 200 == resp.status_code

    data = resp.get_json()
    assert 1 == len(data['advisories']['scheduled'])

    advisory = next(iter(data['advisories']['scheduled']))
    assert advisory['name'] == DEFAULT_ADVISORY_ID
    assert advisory['package'] == 'bar'


@create_issue(id='CVE-1111-1111', issue_type=issue_types[2])
@create_package(name='foo', base='lol', version='1.2.3-4')
@create_package(name='bar', base='lol', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=['CVE-1111-1111'], packages=['foo', 'bar'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=2, publication=Publication.published)
def test_todo_advisory_incomplete(db, client):
    resp = client.get(url_for('tracker.todo_json', postfix='.json'))
    assert 200 == resp.status_code

    data = resp.get_json()
    assert 1 == len(data['advisories']['incomplete'])

    advisory = next(iter(data['advisories']['incomplete']))
    assert advisory['name'] == DEFAULT_ADVISORY_ID
    assert advisory['package'] == 'bar'


@create_issue(id='CVE-1111-1111', issue_type=issue_types[2])
@create_package(name='foo', base='lol', version='1.2.3-4')
@create_package(name='bar', base='lol', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=['CVE-1111-1111'], packages=['foo', 'bar'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=2, publication=Publication.published, content='broken!', impact='snafu', reference='https://foo.bar')
def test_todo_advisory_not_incomplete_with_data(db, client):
    resp = client.get(url_for('tracker.todo_json', postfix='.json'))
    assert 200 == resp.status_code

    data = resp.get_json()
    assert not data['advisories']['incomplete']


@create_issue(id='CVE-1111-1111', issue_type=issue_types[0])
@create_package(name='foo', base='lol', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=['CVE-1111-1111'], packages=['foo'], status=Status.unknown, affected='1.2.3-3', fixed='1.2.3-4')
def test_todo_group_unknown_by_status(db, client):
    resp = client.get(url_for('tracker.todo_json', postfix='.json'))
    assert 200 == resp.status_code

    data = resp.get_json()
    assert 1 == len(data['groups']['unknown'])

    group = next(iter(data['groups']['unknown']))
    assert DEFAULT_GROUP_NAME == group['name']
    assert ['foo'] == group['packages']


@create_issue(id='CVE-1111-1111', issue_type=issue_types[1], severity=Severity.high)
@create_package(name='foo', base='lol', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=['CVE-1111-1111'], packages=['foo'], status=Status.vulnerable, affected='1.2.3-3', fixed='1.2.3-4')
def test_todo_group_not_unknown_with_data(db, client):
    resp = client.get(url_for('tracker.todo_json', postfix='.json'))
    assert 200 == resp.status_code

    data = resp.get_json()
    assert not data['groups']['unknown']


@create_issue(id='CVE-1111-1111', issue_type=issue_types[1])
@create_package(name='foo', base='lol', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=['CVE-1111-1111'], packages=['foo'], status=Status.vulnerable, affected='1.2.3-3')
def test_todo_group_bumped(db, client):
    resp = client.get(url_for('tracker.todo_json', postfix='.json'))
    assert 200 == resp.status_code

    data = resp.get_json()
    assert 1 == len(data['groups']['bumped'])

    group = next(iter(data['groups']['bumped']))
    assert DEFAULT_GROUP_NAME == group['name']
    assert ['foo'] == group['packages']
    assert '1.2.3-4' in group['current'].values()


@create_issue(id='CVE-1111-1111', issue_type=issue_types[1])
@create_package(name='foo', base='lol', version='1.2.3-3')
@create_group(id=DEFAULT_GROUP_ID, issues=['CVE-1111-1111'], packages=['foo'], status=Status.vulnerable, affected='1.2.3-3')
def test_todo_group_not_bumped_when_same(db, client):
    resp = client.get(url_for('tracker.todo_json', postfix='.json'))
    assert 200 == resp.status_code

    data = resp.get_json()
    assert not data['groups']['bumped']


@create_issue(id='CVE-1111-1111', issue_type=issue_types[2])
def test_todo_issues_orphan(db, client):
    resp = client.get(url_for('tracker.todo_json', postfix='.json'))
    assert 200 == resp.status_code

    data = resp.get_json()
    assert 1 == len(data['issues']['orphan_issues'])

    issue = next(iter(data['issues']['orphan_issues']))
    assert 'CVE-1111-1111' == issue['name']


@create_issue(id='CVE-1111-1111', issue_type=issue_types[2])
@create_package(name='foo', base='lol', version='1.2.3-3')
@create_group(id=DEFAULT_GROUP_ID, issues=['CVE-1111-1111'], packages=['foo'], status=Status.vulnerable, affected='1.2.3-3')
def test_todo_issues_referenced_not_orphan(db, client):
    resp = client.get(url_for('tracker.todo_json', postfix='.json'))
    assert 200 == resp.status_code

    data = resp.get_json()
    assert not data['issues']['orphan_issues']


@create_issue(id='CVE-1111-1111', issue_type=issue_types[2], remote=Remote.remote, severity=Severity.low, description='yay')
def test_todo_issues_not_unknown_with_data(db, client):
    resp = client.get(url_for('tracker.todo_json', postfix='.json'))
    assert 200 == resp.status_code

    data = resp.get_json()
    assert not data['issues']['unknown_issues']


@create_issue(id='CVE-1111-1111', issue_type=issue_types[0], remote=Remote.remote, severity=Severity.low, description='yay')
def test_todo_issues_unknown_without_type(db, client):
    resp = client.get(url_for('tracker.todo_json', postfix='.json'))
    assert 200 == resp.status_code

    data = resp.get_json()
    assert 1 == len(data['issues']['unknown_issues'])

    issue = next(iter(data['issues']['unknown_issues']))
    assert 'CVE-1111-1111' == issue['name']


@create_issue(id='CVE-1111-1111', issue_type=issue_types[1], remote=Remote.unknown, severity=Severity.low, description='yay')
def test_todo_issues_unknown_without_remote(db, client):
    resp = client.get(url_for('tracker.todo_json', postfix='.json'))
    assert 200 == resp.status_code

    data = resp.get_json()
    assert 1 == len(data['issues']['unknown_issues'])

    issue = next(iter(data['issues']['unknown_issues']))
    assert 'CVE-1111-1111' == issue['name']


@create_issue(id='CVE-1111-1111', issue_type=issue_types[0], remote=Remote.remote, severity=Severity.unknown, description='yay')
def test_todo_issues_unknown_without_severity(db, client):
    resp = client.get(url_for('tracker.todo_json', postfix='.json'))
    assert 200 == resp.status_code

    data = resp.get_json()
    assert 1 == len(data['issues']['unknown_issues'])

    issue = next(iter(data['issues']['unknown_issues']))
    assert 'CVE-1111-1111' == issue['name']


@create_issue(id='CVE-1111-1111', issue_type=issue_types[1], remote=Remote.remote, severity=Severity.low, description='')
def test_todo_issues_unknown_without_description(db, client):
    resp = client.get(url_for('tracker.todo_json', postfix='.json'))
    assert 200 == resp.status_code

    data = resp.get_json()
    assert 1 == len(data['issues']['unknown_issues'])

    issue = next(iter(data['issues']['unknown_issues']))
    assert 'CVE-1111-1111' == issue['name']
