from flask import render_template
from sqlalchemy import and_
from app import app, db
from app.model import CVE, CVEGroup, CVEGroupEntry, CVEGroupPackage, Advisory, Package
from app.model.enum import Publication, Status, Remote
from app.model.cve import cve_id_regex
from app.model.cvegroup import vulnerability_group_regex, pkgname_regex
from app.model.advisory import advisory_regex
from app.model.package import filter_duplicate_packages, sort_packages
from app.form.advisory import AdvisoryForm
from app.view.error import not_found
from app.util import chunks, multiline_to_list
from collections import defaultdict


@app.route('/issue/<regex("{}"):cve>'.format(cve_id_regex[1:]), methods=['GET'])
@app.route('/<regex("{}"):cve>'.format(cve_id_regex[1:]), methods=['GET'])
def show_cve(cve):
    cve_model = CVE.query.get(cve)
    if not cve_model:
        return not_found()

    entries = (db.session.query(CVEGroupEntry, CVEGroup, CVEGroupPackage, Advisory)
               .filter_by(cve=cve_model)
               .join(CVEGroup).join(CVEGroupPackage)
               .outerjoin(Advisory, and_(Advisory.group_package_id == CVEGroupPackage.id,
                                         Advisory.publication == Publication.published))
               .order_by(CVEGroup.created.desc()).order_by(CVEGroupPackage.pkgname)).all()

    group_packages = defaultdict(set)
    advisories = set()
    groups = set()
    for cve, group, pkg, advisory in entries:
        group_packages[group].add(pkg.pkgname)
        groups.add(group)
        if advisory:
            advisories.add(advisory)

    groups = sorted(groups, key=lambda item: item.created, reverse=True)
    groups = sorted(groups, key=lambda item: item.status)
    advisories = sorted(advisories, key=lambda item: item.id, reverse=True)
    group_packages = dict(map(lambda item: (item[0], sorted(item[1])), group_packages.items()))

    return render_template('cve.html',
                           title=cve_model.id,
                           issue=cve_model,
                           groups=groups,
                           group_packages=group_packages,
                           advisories=advisories)


@app.route('/group/<regex("{}"):avg>'.format(vulnerability_group_regex[1:]), methods=['GET'])
@app.route('/<regex("{}"):avg>'.format(vulnerability_group_regex[1:]), methods=['GET'])
def show_group(avg):
    avg_id = avg.replace('AVG-', '')
    entries = (db.session.query(CVEGroup, CVE, CVEGroupPackage, Advisory, Package)
               .filter(CVEGroup.id == avg_id)
               .join(CVEGroupEntry).join(CVE).join(CVEGroupPackage)
               .outerjoin(Package, Package.name == CVEGroupPackage.pkgname)
               .outerjoin(Advisory, and_(Advisory.group_package_id == CVEGroupPackage.id))
               ).all()
    if not entries:
        return not_found()

    group = None
    cves = set()
    pkgs = set()
    advisories = set()
    cve_types = set()
    versions = set()
    for group_entry, cve, pkg, advisory, package in entries:
        group = group_entry
        cves.add(cve)
        cve_types.add(cve.issue_type)
        pkgs.add(pkg)
        versions.add(package)
        if advisory:
            advisories.add(advisory)

    cve_types = list(cve_types)
    cves = sorted(cves, key=lambda item: item.id, reverse=True)
    pkgs = sorted(pkgs, key=lambda item: item.pkgname)
    versions = sort_packages(filter_duplicate_packages(list(versions), True))
    advisories = sorted(advisories, key=lambda item: item.id, reverse=True)
    advisory_pending = group.status == Status.fixed and group.advisory_qualified and len(advisories) <= 0
    advisory_form = AdvisoryForm()
    if 1 == len(cve_types):
        advisory_form.advisory_type.data = cve_types[0]

    out = {
        'detail': group,
        'pkgs': pkgs,
        'versions': versions,
        'cves': cves,
        'advisories': advisories
    }
    return render_template('group.html',
                           title='{}'.format(group.name),
                           group=out,
                           advisory_pending=advisory_pending,
                           form=advisory_form)


@app.route('/package/<regex("{}"):pkgname>'.format(pkgname_regex[1:]), methods=['GET'])
def show_package(pkgname):
    entries = (db.session.query(CVEGroup, CVE, CVEGroupPackage, Advisory, Package)
               .filter(CVEGroupPackage.pkgname == pkgname)
               .join(CVEGroupEntry).join(CVE).join(CVEGroupPackage)
               .outerjoin(Package, Package.name == pkgname)
               .outerjoin(Advisory, and_(Advisory.group_package_id == CVEGroupPackage.id,
                                         Advisory.publication == Publication.published))
               ).all()

    if not entries:
        return not_found()

    groups = set()
    issues = set()
    advisories = set()
    versions = set()
    for group, cve, pkg, advisory, package in entries:
        groups.add(group)
        versions.add(package)
        issues.add((cve, group))
        if advisory:
            advisories.add(advisory)

    issues = [{'cve': e[0], 'group': e[1]} for e in issues]
    issues = sorted(issues, key=lambda item: item['cve'].id, reverse=True)
    issues = sorted(issues, key=lambda item: item['group'].status)
    groups = sorted(groups, key=lambda item: item.id, reverse=True)
    groups = sorted(groups, key=lambda item: item.status)
    advisories = sorted(advisories, key=lambda item: item.id, reverse=True)
    versions = sort_packages(filter_duplicate_packages(list(versions), True))

    package = {
        'pkgname': pkgname,
        'versions': versions,
        'groups': {'open': list(filter(lambda group: group.status.open(), groups)),
                   'resolved': list(filter(lambda group: group.status.resolved(), groups))},
        'issues': {'open': list(filter(lambda issue: issue['group'].status.open(), issues)),
                   'resolved': list(filter(lambda issue: issue['group'].status.resolved(), issues))},
        'advisories': advisories
    }
    return render_template('package.html',
                           title='{}'.format(pkgname),
                           package=package)


@app.route('/advisory/<regex("{}"):advisory_id>/raw'.format(advisory_regex[1:-1]), methods=['GET'])
@app.route('/<regex("{}"):advisory_id>/raw'.format(advisory_regex[1:-1]), methods=['GET'])
def show_advisory_raw(advisory_id):
    result = show_advisory(advisory_id, raw=True)
    if isinstance(result, tuple):
        return result
    return result, 200, {'Content-Type': 'text/plain; charset=utf-8'}


@app.route('/advisory/<regex("{}"):advisory_id>'.format(advisory_regex[1:]), methods=['GET'])
@app.route('/<regex("{}"):advisory_id>'.format(advisory_regex[1:]), methods=['GET'])
def show_advisory(advisory_id, raw=False):
    entries = (db.session.query(Advisory, CVEGroup, CVEGroupPackage, CVE)
               .filter(Advisory.id == advisory_id)
               .join(CVEGroupPackage).join(CVEGroup).join(CVEGroupEntry).join(CVE)
               .order_by(CVE.id)
               ).all()
    if not entries:
        return not_found()

    advisory = entries[0][0]
    group = entries[0][1]
    package = entries[0][2]
    issues = [issue for (advisory, group, package, issue) in entries]
    severity_sorted_issues = sorted(issues, key=lambda issue: issue.issue_type)
    severity_sorted_issues = sorted(severity_sorted_issues, key=lambda issue: issue.severity)

    remote = any([issue.remote is Remote.remote for issue in issues])
    issues_listing_formatted = (('\n{}'.format(' ' * len('CVE-ID  : ')))
                                .join(list(map(' '.join, chunks([issue.id for issue in issues], 4)))))
    link = 'https://wiki.archlinux.org/index.php/CVE'
    upstream_released = group.affected.split('-')[0] != group.fixed.split('-')[0]
    upstream_version = group.fixed.split('-')[0]
    if ':' in upstream_version:
        upstream_version = upstream_version[upstream_version.index(':') + 1:]
    unique_issue_types = []
    for issue in severity_sorted_issues:
        if issue.issue_type not in unique_issue_types:
            unique_issue_types.append(issue.issue_type)
    references = []
    if group.bug_ticket:
        references.append('https://bugs.archlinux.org/task/{}'.format(group.bug_ticket))
    for reference in multiline_to_list(group.reference):
        if reference not in references:
            references.append(reference)
    for issue in issues:
        for reference in multiline_to_list(issue.reference):
            if reference not in references:
                references.append(reference)

    raw_asa = render_template('advisory.txt',
                              advisory=advisory,
                              group=group,
                              package=package,
                              issues=issues,
                              remote=remote,
                              issues_listing_formatted=issues_listing_formatted,
                              link=link,
                              upstream_released=upstream_released,
                              upstream_version=upstream_version,
                              unique_issue_types=unique_issue_types,
                              references=references)
    if raw:
        return raw_asa

    raw_asa = '\n'.join(raw_asa.split('\n')[2:])
    for issue in issues:
        raw_asa = raw_asa.replace(' {}'.format(issue.id), ' <a href="/{0}">{0}</a>'.format(issue.id))
    raw_asa = raw_asa.replace(' {}'.format(package.pkgname), ' <a href="/package/{0}">{0}</a>'.format(package.pkgname))
    raw_asa = raw_asa.replace('"{}'.format(package.pkgname), '"<a href="/package/{0}">{0}</a>'.format(package.pkgname))

    return render_template('advisory.html',
                           title='{}'.format(advisory_id),
                           advisory=advisory,
                           package=package,
                           raw_asa=raw_asa)
