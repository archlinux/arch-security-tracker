from flask import url_for
from werkzeug.exceptions import NotFound

from tracker.model.cve import issue_types
from tracker.model.enum import Publication

from .conftest import DEFAULT_ADVISORY_ID
from .conftest import DEFAULT_GROUP_ID
from .conftest import create_advisory
from .conftest import create_group
from .conftest import create_package
from .util import AssertionHTMLParser


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1], reference='https://security.archlinux.org', publication=Publication.published)
def test_show_package_json(db, client):
    resp = client.get(url_for('tracker.show_package_json', pkgname='foo', suffix='/json'), follow_redirects=True)
    assert 200 == resp.status_code
    data = resp.get_json()
    assert len(data['groups']) == 1
    assert len(data['versions']) == 1
    assert len(data['advisories']) == 1
    assert len(data['issues']) == 1
    assert data['name'] == 'foo'


def test_show_package_json_not_found(db, client):
    resp = client.get(url_for('tracker.show_package_json', pkgname='foo', suffix='/json'), follow_redirects=True)
    assert NotFound.code == resp.status_code

def test_show_package_not_found(db, client):
    resp = client.get(url_for('tracker.show_package', pkgname='foo'), follow_redirects=True)
    assert NotFound.code == resp.status_code

@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1], reference='https://security.archlinux.org', publication=Publication.published)
def test_show_package(db, client):
    resp = client.get(url_for('tracker.show_package', pkgname='foo'), follow_redirects=True)
    html = AssertionHTMLParser()
    html.feed(resp.data.decode())
    assert 200 == resp.status_code
    assert 'foo' in resp.data.decode()
