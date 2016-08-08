from flask import render_template, flash, redirect
from sqlalchemy import and_
from app import app, db
from app.model import CVE, CVEGroup, CVEGroupEntry, CVEGroupPackage, Advisory
from app.model.enum import Publication
from app.model.cve import cve_id_regex
from app.model.cvegroup import vulnerability_group_regex, pkgname_regex
from app.view.error import not_found
from app.pacman import get_pkg
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
                                         Advisory.advisory_status == Publication.published))
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

    entry = {
        'cve': cve_model.id,
        'description': cve_model.description,
        'severity': cve_model.severity,
        'remote': cve_model.remote,
        'notes': cve_model.notes,
        'groups': groups,
        'group_packages': group_packages,
        'advisories': advisories
    }
    return render_template('cve.html',
                           title=cve_model.id,
                           entry=entry)


@app.route('/group/<regex("{}"):avg>'.format(vulnerability_group_regex[1:]), methods=['GET'])
@app.route('/<regex("{}"):avg>'.format(vulnerability_group_regex[1:]), methods=['GET'])
def show_group(avg):
    avg_id = avg.replace('AVG-', '')
    entries = (db.session.query(CVEGroup, CVE, CVEGroupPackage, Advisory)
               .filter(CVEGroup.id == avg_id)
               .join(CVEGroupEntry).join(CVE).join(CVEGroupPackage)
               .outerjoin(Advisory, and_(Advisory.group_package_id == CVEGroupPackage.id,
                                         Advisory.advisory_status == Publication.published))
               ).all()
    if not entries:
        return not_found()

    group = None
    cves = set()
    pkgs = set()
    advisories = set()
    for group_entry, cve, pkg, advisory in entries:
        group = group_entry
        cves.add(cve)
        pkgs.add(pkg)
        if advisory:
            advisories.add(advisory)

    cves = sorted(cves, key=lambda item: item.id, reverse=True)
    pkgs = sorted(pkgs, key=lambda item: item.pkgname)
    advisories = sorted(advisories, key=lambda item: item.id, reverse=True)
    versions = get_pkg(pkgs[0].pkgname, filter_arch=True)

    out = {
        'detail': group,
        'pkgs': pkgs,
        'versions': versions,
        'cves': cves,
        'advisories': advisories
    }
    return render_template('group.html',
                           title='{}'.format(group.name),
                           group=out)


@app.route('/package/<regex("{}"):pkgname>'.format(pkgname_regex[1:]), methods=['GET'])
def show_package(pkgname):
    versions = get_pkg(pkgname, filter_arch=True)
    if not versions:
        return not_found()

    entries = (db.session.query(CVEGroup, CVE, CVEGroupPackage, Advisory)
               .filter(CVEGroupPackage.pkgname == pkgname)
               .join(CVEGroupEntry).join(CVE).join(CVEGroupPackage)
               .outerjoin(Advisory, and_(Advisory.group_package_id == CVEGroupPackage.id,
                                         Advisory.advisory_status == Publication.published))
               ).all()
    groups = set()
    issues = []
    advisories = set()
    for group, cve, pkg, advisory in entries:
        groups.add(group)
        issues.append({'cve': cve, 'group': group})
        if advisory:
            advisories.add(advisory)

    issues = sorted(issues, key=lambda item: item['cve'].id, reverse=True)
    issues = sorted(issues, key=lambda item: item['group'].status)
    groups = sorted(groups, key=lambda item: item.id, reverse=True)
    groups = sorted(groups, key=lambda item: item.status)
    advisories = sorted(advisories, key=lambda item: item.id, reverse=True)

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
