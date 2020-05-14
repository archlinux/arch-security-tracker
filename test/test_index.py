from flask import url_for
from werkzeug.exceptions import NotFound

from tracker.model.enum import Remote
from tracker.model.enum import Severity

from .conftest import DEFAULT_GROUP_ID
from .conftest import DEFAULT_GROUP_NAME
from .conftest import create_group
from .conftest import create_issue
from .conftest import create_package


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
def test_index(db, client):
    resp = client.get(url_for('tracker.index'), follow_redirects=True)
    assert 200 == resp.status_code
    assert DEFAULT_GROUP_NAME not in resp.data.decode()


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3')
def test_index_vulnerable(db, client):
    resp = client.get(url_for('tracker.index_vulnerable'), follow_redirects=True)
    assert 200 == resp.status_code
    assert DEFAULT_GROUP_NAME in resp.data.decode()


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3')
def test_index_all(db, client):
    resp = client.get(url_for('tracker.index_all'), follow_redirects=True)
    assert 200 == resp.status_code
    assert DEFAULT_GROUP_NAME in resp.data.decode()


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3')
def test_index_json(db, client):
    resp = client.get(url_for('tracker.index_json', only_vulernable=False, path='all.json'), follow_redirects=True)
    assert 200 == resp.status_code
    data = resp.get_json()
    assert len(data) == 1
    assert data[0]['name'] == DEFAULT_GROUP_NAME


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3')
def test_index_vulnerable_json(db, client):
    resp = client.get(url_for('tracker.index_vulnerable_json', path='vulnerable.json'), follow_redirects=True)
    assert 200 == resp.status_code
    data = resp.get_json()
    assert len(data) == 1
    assert data[0]['name'] == DEFAULT_GROUP_NAME


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
              list(map(lambda i: 'CVE-0002-i100{}'.format(i), range(1, 8))) +
              list(map(lambda i: 'CVE-0003-100{}'.format(i), range(1, 9))) +
              list(map(lambda i: 'CVE-0004-100{}'.format(i), range(1, 10))) +
              list(map(lambda i: 'CVE-0005-100{}'.format(i), range(1, 11))),
              packages=['morty'], fixed='1.3-8')
def test_index_pagination(db, client):
    CVES_IN_PAGE = [
        ['CVE-0005-1009', 'CVE-0005-1008', 'CVE-0005-1007', 'CVE-0005-1006', 'CVE-0005-1005',
         'CVE-0003-1007', 'CVE-0003-1006', 'CVE-0003-1005', 'CVE-0003-1004', 'CVE-0003-1003'],
        ['CVE-0003-1002', 'CVE-0003-1001', 'CVE-0002-i1007', 'CVE-0002-i1006', 'CVE-0002-i1005',
         'CVE-0001-1005', 'CVE-0001-1004', 'CVE-0001-1003', 'CVE-0001-1002', 'CVE-0001-1001']]

    # we want a valid page
    resp = client.get(url_for('tracker.index'), follow_redirects=True)
    assert 200 == resp.status_code

    # check if pagination elements exist
    data_page_1 = resp.data.decode()
    assert 'issue_top_pagination' in data_page_1
    assert 'issue_bottom_pagination' in data_page_1
    assert  url_for('tracker.index', page=2) in data_page_1

    # check if cves for page 1 are there and those for 2 not
    for cve_of_page_1, cve_of_page_2 in zip(*CVES_IN_PAGE):
        assert cve_of_page_1 in data_page_1
        assert cve_of_page_2 not in data_page_1

    # check if cves on page1 and 2 are different
    resp = client.get(url_for('tracker.index', page=2), follow_redirects=True)
    assert 200 == resp.status_code
    data_page_2 = resp.data.decode()

    # check if cves for page 2 are there and those for 1 not
    for cve_of_page_1, cve_of_page_2 in zip(*CVES_IN_PAGE):
        assert cve_of_page_1 not in data_page_2
        assert cve_of_page_2 in data_page_2

    # we want 404 for non existing pages
    resp = client.get(url_for('tracker.index', page=0xdead), follow_redirects=True)
    assert 404 == resp.status_code
