from flask import render_template, flash, redirect
from app import app, db
from app.model import CVE, CVEGroup, CVEGroupEntry, CVEGroupPackage
from app.model.cve import cve_id_regex
from app.model.cvegroup import vulnerability_group_regex, pkgname_regex
from app.view.error import not_found
from app.pacman import get_pkg
from sqlalchemy import func


@app.route('/issue/<regex("{}"):cve>'.format(cve_id_regex[1:]), methods=['GET'])
@app.route('/<regex("{}"):cve>'.format(cve_id_regex[1:]), methods=['GET'])
def show_cve(cve):
    cve_model = CVE.query.get(cve)
    if not cve_model:
        return not_found()

    groups = (db.session.query(CVEGroupEntry, CVEGroup, func.group_concat(CVEGroupPackage.pkgname, ' '))
              .filter_by(cve=cve_model).join(CVEGroup).join(CVEGroupPackage)
              .order_by(CVEGroup.created.desc()).order_by(CVEGroupPackage.pkgname)).all()
    groups = [(cve, group, pkgs.split(' ')) for (cve, group, pkgs) in groups]
    groups = sorted(groups, key=lambda item: item[1].created, reverse=True)
    groups = sorted(groups, key=lambda item: item[1].status)

    entry = {
        'cve': cve_model.id,
        'description': cve_model.description,
        'severity': cve_model.severity,
        'remote': cve_model.remote,
        'notes': cve_model.notes,
        'groups': groups,
    }
    return render_template('cve.html',
                           title=cve,
                           entry=entry)


@app.route('/group/<regex("{}"):avg>'.format(vulnerability_group_regex[1:]), methods=['GET'])
@app.route('/<regex("{}"):avg>'.format(vulnerability_group_regex[1:]), methods=['GET'])
def show_group(avg):
    avg_id = avg.replace('AVG-', '')
    entries = (db.session.query(CVEGroup, CVE, CVEGroupPackage).filter(CVEGroup.id == avg_id)
               .join(CVEGroupEntry).join(CVE).join(CVEGroupPackage)).all()
    if not entries:
        return not_found()

    group = None
    cves = set()
    pkgs = set()
    for group_entry, cve, pkg in entries:
        group = group_entry
        cves.add(cve)
        pkgs.add(pkg)

    cves = sorted(cves, key=lambda item: item.id, reverse=True)
    pkgs = sorted(pkgs, key=lambda item: item.pkgname)
    versions = get_pkg(pkgs[0].pkgname, filter_arch=True)

    out = {
        'detail': group,
        'pkgs': pkgs,
        'versions': versions,
        'cves': cves
    }
    return render_template('group.html',
                           title='{}'.format(group.name),
                           group=out)


@app.route('/package/<regex("{}"):pkgname>'.format(pkgname_regex[1:]), methods=['GET'])
def show_package(pkgname):
    versions = get_pkg(pkgname, filter_arch=True)
    if not versions:
        return not_found()

    entries = (db.session.query(CVEGroup, CVE, CVEGroupPackage).filter(CVEGroupPackage.pkgname == pkgname)
               .join(CVEGroupEntry).join(CVE).join(CVEGroupPackage)).all()
    groups = set()
    issues = []
    for group, cve, pkg in entries:
        groups.add(group)
        issues.append({'cve': cve, 'group': group})

    issues = sorted(issues, key=lambda item: item['cve'].id, reverse=True)
    issues = sorted(issues, key=lambda item: item['group'].status)
    groups = sorted(groups, key=lambda item: item.id, reverse=True)
    groups = sorted(groups, key=lambda item: item.status)

    package = {
        'pkgname': pkgname,
        'versions': versions,
        'groups': {'open': list(filter(lambda group: group.status.open(), groups)),
                   'resolved': list(filter(lambda group: group.status.resolved(), groups))},
        'issues': {'open': list(filter(lambda issue: issue['group'].status.open(), issues)),
                   'resolved': list(filter(lambda issue: issue['group'].status.resolved(), issues))}
    }
    return render_template('package.html',
                           title='{}'.format(pkgname),
                           package=package)
