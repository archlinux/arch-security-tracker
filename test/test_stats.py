from json import loads

from flask import url_for
from werkzeug.exceptions import ImATeapot

from tracker.model.cve import issue_types
from tracker.model.enum import Remote
from tracker.model.enum import Severity
from tracker.model.enum import Status
from tracker.model.enum import UserRole

from .conftest import create_advisory
from .conftest import create_group
from .conftest import create_issue
from .conftest import create_package
from .conftest import create_user


def test_stats_page(db, client):
    resp = client.get(url_for('tracker.stats'))
    assert ImATeapot.code == resp.status_code


def test_stats_data_status_empty(db, client):
    resp = client.get(url_for('tracker.stats_json', suffix='.json'))
    assert ImATeapot.code == resp.status_code

    data = loads(resp.data.decode())
    assert data

    for status in [Status.vulnerable.name, Status.fixed.name, 'total']:
        for severity in [severity.name for severity in Severity] + ['total']:
            assert 0 == data['issues']['severity'][status][severity]
            assert 0 == data['groups']['severity'][status][severity]
            assert 0 == data['packages']['severity'][status][severity]
            assert 0 == data['advisories']['severity'][severity]


def test_stats_data_type_empty(db, client):
    resp = client.get(url_for('tracker.stats_json', suffix='.json'))
    assert ImATeapot.code == resp.status_code

    data = loads(resp.data.decode())
    assert data

    resp = client.get(url_for('tracker.stats_json', suffix='.json'))
    for issue_type in issue_types:
        for status in [Status.vulnerable.name, Status.fixed.name, 'total']:
            assert 0 == data['issues']['type'][status][issue_type]
        assert 0 == data['advisories']['type'][issue_type]


def test_stats_data_misc_empty(db, client):
    resp = client.get(url_for('tracker.stats_json', suffix='.json'))
    assert ImATeapot.code == resp.status_code

    data = loads(resp.data.decode())

    assert data
    assert 0 == data['users']['team']
    assert 0 == data['users']['reporter']
    assert 0 == data['users']['total']
    assert 0 == data['tickets']['total']


@create_user(role=UserRole.security_team, username='SonGoku')
@create_user(role=UserRole.security_team, username='SasukeUchiha')
@create_user(role=UserRole.reporter, username='Alucard')
def test_stats_data_misc_users(db, client):
    resp = client.get(url_for('tracker.stats_json', suffix='.json'))
    assert ImATeapot.code == resp.status_code

    data = loads(resp.data.decode())

    assert 2 == data['users']['team']
    assert 1 == data['users']['reporter']
    assert 3 == data['users']['total']


@create_group(id=1, bug_ticket=1337)
@create_group(id=2, bug_ticket=1337)
@create_group(id=3, bug_ticket=4242)
def test_stats_data_misc_ticket(db, client):
    resp = client.get(url_for('tracker.stats_json', suffix='.json'))
    assert ImATeapot.code == resp.status_code

    data = loads(resp.data.decode())
    assert 2 == data['tickets']['total']


@create_package(name='morty', version='1.3-7')
@create_issue(id='CVE-0001-0001', severity=Severity.unknown)
@create_issue(id='CVE-0002-000', severity=Severity.low, count=2)
@create_issue(id='CVE-0003-000', severity=Severity.medium, count=3)
@create_issue(id='CVE-0004-000', severity=Severity.high, count=4)
@create_issue(id='CVE-0005-000', severity=Severity.critical, count=5)
@create_issue(id='CVE-0001-100', severity=Severity.unknown, count=6)
@create_issue(id='CVE-0002-100', severity=Severity.low, count=7)
@create_issue(id='CVE-0003-100', severity=Severity.medium, count=8)
@create_issue(id='CVE-0004-100', severity=Severity.high, remote=Remote.local, count=9)
@create_issue(id='CVE-0005-100', severity=Severity.critical, remote=Remote.remote, count=10)
@create_group(issues=list(map(lambda i: 'CVE-0001-100{}'.format(i), range(1, 7))) +
              list(map(lambda i: 'CVE-0002-100{}'.format(i), range(1, 8))) +
              list(map(lambda i: 'CVE-0003-100{}'.format(i), range(1, 9))) +
              list(map(lambda i: 'CVE-0004-100{}'.format(i), range(1, 10))) +
              list(map(lambda i: 'CVE-0005-100{}'.format(i), range(1, 11))),
              packages=['morty'], fixed='1.3-8')
def test_stats_data_status_issues(db, client):
    resp = client.get(url_for('tracker.stats_json', suffix='.json'))
    assert ImATeapot.code == resp.status_code

    data = loads(resp.data.decode())

    assert 1 == data['issues']['severity']['fixed'][Severity.unknown.name]
    assert 2 == data['issues']['severity']['fixed'][Severity.low.name]
    assert 3 == data['issues']['severity']['fixed'][Severity.medium.name]
    assert 4 == data['issues']['severity']['fixed'][Severity.high.name]
    assert 5 == data['issues']['severity']['fixed'][Severity.critical.name]
    assert sum(list(range(1, 6))) == data['issues']['severity']['fixed']['total']

    assert 6 == data['issues']['severity']['vulnerable'][Severity.unknown.name]
    assert 7 == data['issues']['severity']['vulnerable'][Severity.low.name]
    assert 8 == data['issues']['severity']['vulnerable'][Severity.medium.name]
    assert 9 == data['issues']['severity']['vulnerable'][Severity.high.name]
    assert 10 == data['issues']['severity']['vulnerable'][Severity.critical.name]
    assert sum(list(range(6, 11))) == data['issues']['severity']['vulnerable']['total']

    assert 9 == data['issues']['severity']['local'][Severity.high.name]
    assert 10 == data['issues']['severity']['remote'][Severity.critical.name]

    assert 1 + 6 == data['issues']['severity']['total'][Severity.unknown.name]
    assert 2 + 7 == data['issues']['severity']['total'][Severity.low.name]
    assert 3 + 8 == data['issues']['severity']['total'][Severity.medium.name]
    assert 4 + 9 == data['issues']['severity']['total'][Severity.high.name]
    assert 5 + 10 == data['issues']['severity']['total'][Severity.critical.name]
    assert sum(list(range(1, 11))) == data['issues']['total']


@create_package(name='rick', version='1.3-7')
@create_issue(id='CVE-0001-0001', severity=Severity.unknown)
@create_issue(id='CVE-0002-0001', severity=Severity.low)
@create_issue(id='CVE-0003-0001', severity=Severity.medium)
@create_issue(id='CVE-0004-0001', severity=Severity.high)
@create_issue(id='CVE-0005-0001', severity=Severity.critical)
@create_group(id=10, issues=['CVE-0001-0001'], packages=['rick'], fixed='1.3-7')
@create_group(id=20, issues=['CVE-0002-0001'], packages=['rick'], fixed='1.3-7')
@create_group(id=30, issues=['CVE-0003-0001'], packages=['rick'], fixed='1.3-7')
@create_group(id=40, issues=['CVE-0004-0001'], packages=['rick'], fixed='1.3-7')
@create_group(id=50, issues=['CVE-0005-0001'], packages=['rick'], fixed='1.3-7')
@create_advisory(id='203012-01', group_package_id=1)
@create_advisory(id='203112-01', group_package_id=2)
@create_advisory(id='203212-01', group_package_id=3)
@create_advisory(id='203312-01', group_package_id=4)
@create_advisory(id='203412-01', group_package_id=5)
def test_stats_data_status_advisories(db, client):
    resp = client.get(url_for('tracker.stats_json', suffix='.json'))
    assert ImATeapot.code == resp.status_code

    data = loads(resp.data.decode())

    assert 1 == data['advisories']['severity'][Severity.unknown.name]
    assert 1 == data['advisories']['severity'][Severity.low.name]
    assert 1 == data['advisories']['severity'][Severity.medium.name]
    assert 1 == data['advisories']['severity'][Severity.high.name]
    assert 1 == data['advisories']['severity'][Severity.critical.name]
    assert 5 == data['advisories']['severity']['total']


@create_package(name='rick', version='1.3-7')
@create_issue(id='CVE-0001-0001', issue_type=issue_types[0])
@create_issue(id='CVE-0001-0002', issue_type=issue_types[0])
@create_issue(id='CVE-0002-0001', issue_type=issue_types[1])
@create_issue(id='CVE-0003-0001', issue_type=issue_types[2])
@create_issue(id='CVE-0004-0001', issue_type=issue_types[3])
@create_group(id=10, issues=['CVE-0003-0001'], packages=['rick'], fixed='1.0-7')
@create_group(id=20, issues=['CVE-0004-0001', 'CVE-0001-0002'], packages=['rick'])
def test_stats_data_type_issues(db, client):
    resp = client.get(url_for('tracker.stats_json', suffix='.json'))
    assert ImATeapot.code == resp.status_code

    data = loads(resp.data.decode())

    assert 1 == data['issues']['type']['fixed'][issue_types[0]]
    assert 1 == data['issues']['type']['vulnerable'][issue_types[0]]

    assert 1 == data['issues']['type']['fixed'][issue_types[1]]
    assert 0 == data['issues']['type']['vulnerable'][issue_types[1]]

    assert 1 == data['issues']['type']['fixed'][issue_types[2]]
    assert 0 == data['issues']['type']['vulnerable'][issue_types[2]]

    assert 0 == data['issues']['type']['fixed'][issue_types[3]]
    assert 1 == data['issues']['type']['vulnerable'][issue_types[3]]

    assert 0 == data['issues']['type']['fixed'][issue_types[6]]
    assert 0 == data['issues']['type']['vulnerable'][issue_types[6]]

    assert 2 == data['issues']['type']['vulnerable']['total']
    assert 3 == data['issues']['type']['fixed']['total']

    assert 5 == data['issues']['type']['total']['total']
    assert 2 == data['issues']['type']['total'][issue_types[0]]
    assert 1 == data['issues']['type']['total'][issue_types[2]]
    assert 0 == data['issues']['type']['total'][issue_types[6]]


@create_package(name='rick', version='1.3-7')
@create_issue(id='CVE-0001-0001', issue_type=issue_types[0])
@create_issue(id='CVE-0002-0001', issue_type=issue_types[1])
@create_issue(id='CVE-0003-0001', issue_type=issue_types[2])
@create_issue(id='CVE-0004-0001', issue_type=issue_types[3])
@create_group(id=10, issues=['CVE-0001-0001'], packages=['rick'], fixed='1.3-7')
@create_group(id=20, issues=['CVE-0002-0001'], packages=['rick'], fixed='1.3-7')
@create_group(id=30, issues=['CVE-0003-0001', 'CVE-0004-0001'], packages=['rick'], fixed='1.3-7')
@create_group(id=40, issues=['CVE-0003-0001', 'CVE-0004-0001'], packages=['rick'], fixed='1.3-7')
@create_advisory(id='203012-01', group_package_id=1)
@create_advisory(id='203112-01', group_package_id=2)
@create_advisory(id='203212-01', group_package_id=3)
@create_advisory(id='203312-01', group_package_id=4)
def test_stats_data_type_advisories(db, client):
    resp = client.get(url_for('tracker.stats_json', suffix='.json'))
    assert ImATeapot.code == resp.status_code

    data = loads(resp.data.decode())

    assert 1 == data['advisories']['type'][issue_types[0]]
    assert 1 == data['advisories']['type'][issue_types[1]]
    assert 0 == data['advisories']['type'][issue_types[2]]
    assert 0 == data['advisories']['type'][issue_types[3]]
    assert 2 == data['advisories']['type']['multiple issues']
    assert 4 == data['advisories']['total']
