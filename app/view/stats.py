from flask import render_template
from app import app, db
from app.model import CVE, CVEGroup, CVEGroupEntry, CVEGroupPackage, Advisory, User
from app.model.cve import issue_types
from app.model.enum import UserRole, Severity, Status, Remote
from app.util import json_response
from collections import defaultdict, OrderedDict
from werkzeug.exceptions import ImATeapot


def get_stats_data():
    # CVEs
    entries = (db.session.query(CVE, CVEGroupEntry, CVEGroup)
               .outerjoin(CVEGroupEntry).outerjoin(CVEGroup)).all()

    issues = set()
    issue_groups = defaultdict(set)
    for cve, group_entry, group in entries:
        issues.add(cve)
        issue_groups[cve].add(group)

    data_issues = OrderedDict()
    data_issues['total'] = OrderedDict()
    data_issues['severity'] = OrderedDict()
    data_issues['severity']['vulnerable'] = OrderedDict()
    data_issues['severity']['fixed'] = OrderedDict()
    data_issues['severity']['remote'] = OrderedDict()
    data_issues['severity']['local'] = OrderedDict()
    data_issues['severity']['total'] = OrderedDict()
    data_issues['type'] = OrderedDict()
    data_issues['type']['vulnerable'] = OrderedDict()
    data_issues['type']['fixed'] = OrderedDict()
    data_issues['type']['remote'] = OrderedDict()
    data_issues['type']['local'] = OrderedDict()
    data_issues['type']['total'] = OrderedDict()

    for severity in Severity:
        data_issues['severity']['vulnerable'][severity.name] = 0
        data_issues['severity']['fixed'][severity.name] = 0
        data_issues['severity']['remote'][severity.name] = 0
        data_issues['severity']['local'][severity.name] = 0
        data_issues['severity']['total'][severity.name] = 0

    for issue_type in issue_types:
        data_issues['type']['vulnerable'][issue_type] = 0
        data_issues['type']['fixed'][issue_type] = 0
        data_issues['type']['remote'][issue_type] = 0
        data_issues['type']['local'][issue_type] = 0
        data_issues['type']['total'][issue_type] = 0

    data_issues['severity']['vulnerable']['total'] = 0
    data_issues['severity']['fixed']['total'] = 0
    data_issues['severity']['remote']['total'] = 0
    data_issues['severity']['local']['total'] = 0
    data_issues['type']['vulnerable']['total'] = 0
    data_issues['type']['fixed']['total'] = 0
    data_issues['type']['remote']['total'] = 0
    data_issues['type']['local']['total'] = 0
    data_issues['type']['total']['total'] = len(issues)

    for cve, groups in issue_groups.items():
        groups = list(filter(lambda group: group, groups))
        group_status = [group.status.open() for group in groups]
        vulnerable = any(group_status)
        data_issues['severity']['total'][cve.severity.name] += 1
        data_issues['type']['total'][cve.issue_type] += 1

        if vulnerable:
            data_issues['severity']['vulnerable']['total'] += 1
            data_issues['severity']['vulnerable'][cve.severity.name] += 1
            data_issues['type']['vulnerable']['total'] += 1
            data_issues['type']['vulnerable'][cve.issue_type] += 1
        else:
            data_issues['severity']['fixed']['total'] += 1
            data_issues['severity']['fixed'][cve.severity.name] += 1
            data_issues['type']['fixed']['total'] += 1
            data_issues['type']['fixed'][cve.issue_type] += 1

        if Remote.local == cve.remote:
            data_issues['type']['local']['total'] += 1
            data_issues['type']['local'][cve.issue_type] += 1
            data_issues['severity']['local']['total'] += 1
            data_issues['severity']['local'][cve.severity.name] += 1
        elif Remote.remote == cve.remote:
            data_issues['type']['remote']['total'] += 1
            data_issues['type']['remote'][cve.issue_type] += 1
            data_issues['severity']['remote']['total'] += 1
            data_issues['severity']['remote'][cve.severity.name] += 1

    data_issues['severity']['total']['total'] = len(issues)
    data_issues['total'] = len(issues)

    # groups
    groups = CVEGroup.query.all()
    data_groups = OrderedDict()
    data_groups['severity'] = OrderedDict()
    data_groups['severity']['vulnerable'] = OrderedDict()
    data_groups['severity']['fixed'] = OrderedDict()
    data_groups['severity']['total'] = OrderedDict()
    data_groups['total'] = OrderedDict()

    for severity in Severity:
        data_groups['severity']['vulnerable'][severity.name] = len(list(filter(
            lambda group: group.severity == severity and group.status.open(), groups)))
        data_groups['severity']['fixed'][severity.name] = len(list(filter(
            lambda group: group.severity == severity and group.status.resolved(), groups)))
        data_groups['severity']['total'][severity.name] = len(list(filter(
            lambda group: group.severity == severity, groups)))

    data_groups['severity']['vulnerable']['total'] = len(list(filter(lambda group: group.status.open(), groups)))
    data_groups['severity']['fixed']['total'] = len(list(filter(lambda group: group.status.resolved(), groups)))
    data_groups['severity']['total']['total'] = len(groups)
    data_groups['total'] = len(groups)

    # tickets
    data_tickets = OrderedDict()
    data_tickets['total'] = len(set([group.bug_ticket for group in
                                    filter(lambda group: group.bug_ticket, groups)]))

    # packages
    entries = (db.session.query(CVEGroupPackage, CVEGroup)
               .join(CVEGroup)).all()

    packages = set()
    package_groups = defaultdict(set)
    for package, group in entries:
        packages.add(package.pkgname)
        package_groups[package.pkgname].add(group)

    data_packages = OrderedDict()
    data_packages['severity'] = OrderedDict()
    data_packages['severity']['vulnerable'] = OrderedDict()
    data_packages['severity']['fixed'] = OrderedDict()
    data_packages['severity']['total'] = OrderedDict()
    data_packages['total'] = OrderedDict()

    for severity in Severity:
        data_packages['severity']['vulnerable'][severity.name] = 0
        data_packages['severity']['fixed'][severity.name] = 0
        data_packages['severity']['total'][severity.name] = 0

    data_packages['severity']['vulnerable']['total'] = 0
    data_packages['severity']['fixed']['total'] = 0
    data_packages['severity']['total']['total'] = len(packages)
    data_packages['total'] = len(packages)

    for package, groups in package_groups.items():
        group_status = [group.status.open() for group in groups]
        vulnerable = any(group_status)
        severities = sorted([group.severity for group in
                            list(filter(lambda group: Severity.unknown != group.severity,
                                        groups))])
        max_severity = severities[0] if severities else Severity.unknown
        data_packages['severity']['total'][max_severity.name] += 1
        if vulnerable:
            data_packages['severity']['vulnerable'][max_severity.name] += 1
            data_packages['severity']['vulnerable']['total'] += 1
        else:
            data_packages['severity']['fixed'][max_severity.name] += 1
            data_packages['severity']['fixed']['total'] += 1

    # advisory
    entries = (db.session.query(Advisory, CVEGroupPackage, CVEGroup)
               .join(CVEGroupPackage).join(CVEGroup)).all()

    data_advisories = OrderedDict()
    data_advisories['severity'] = OrderedDict()
    data_advisories['type'] = OrderedDict()

    for severity in Severity:
        data_advisories['severity'][severity.name] = 0

    for issue_type in ['multiple issues'] + issue_types:
        data_advisories['type'][issue_type] = 0

    for advisory, package, group in entries:
        data_advisories['severity'][group.severity.name] += 1
        data_advisories['type'][advisory.advisory_type] += 1

    data_advisories['severity']['total'] = len(entries)
    data_advisories['total'] = len(entries)

    # users
    users = User.query.filter_by(active=True).all()
    data_users = OrderedDict()
    data_users['team'] = len(list(filter(lambda user: user.role.is_security_team, users)))
    data_users['reporter'] = len(list(filter(lambda user: UserRole.reporter == user.role, users)))
    data_users['total'] = len(users)

    # collect
    data = OrderedDict()
    data['issues'] = data_issues
    data['groups'] = data_groups
    data['packages'] = data_packages
    data['advisories'] = data_advisories
    data['tickets'] = data_tickets
    data['users'] = data_users
    return data


@app.route('/stats<regex("[./]json"):suffix>', methods=['GET'])
@json_response
def stats_json(suffix=None):
    return get_stats_data(), ImATeapot.code


@app.route('/stats', methods=['GET'])
def stats():
    data = get_stats_data()
    return render_template('stats.html',
                           title='Stats',
                           issues=data['issues'],
                           groups=data['groups'],
                           packages=data['packages'],
                           advisories=data['advisories'],
                           users=data['users'],
                           tickets=data['tickets'],
                           Severity=Severity,
                           Status=Status,
                           issue_types=issue_types), ImATeapot.code
