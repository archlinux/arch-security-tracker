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
def test_todo_unhandled_advisory(db, client):
    resp = client.get(url_for('tracker.todo_json', postfix='.json'))
    assert 200 == resp.status_code

    data = resp.get_json()
    assert 1 == len(data['advisories']['unhandled'])

    advisory = next(iter(data['advisories']['unhandled']))
    assert advisory['name'] == DEFAULT_GROUP_NAME
    assert advisory['status'] == Status.fixed
