from flask import render_template, flash, redirect
from app import app, db
from app.user import reporter_required, user_can_delete_group, user_can_delete_issue
from app.form.confirm import ConfirmForm
from app.model import CVEGroup, CVE, CVEGroupPackage, CVEGroupEntry, Advisory
from app.model.cvegroup import vulnerability_group_regex
from app.model.cve import cve_id_regex
from app.view.error import not_found, forbidden
from collections import defaultdict


@app.route('/group/<regex("{}"):avg>/delete'.format(vulnerability_group_regex[1:-1]), methods=['GET', 'POST'])
@app.route('/<regex("{}"):avg>/delete'.format(vulnerability_group_regex[1:-1]), methods=['GET', 'POST'])
@reporter_required
def delete_group(avg):
    avg_id = avg.replace('AVG-', '')
    entries = (db.session.query(CVEGroup, CVE, CVEGroupPackage, Advisory)
               .filter(CVEGroup.id == avg_id)
               .join(CVEGroupEntry).join(CVE).join(CVEGroupPackage)
               .outerjoin(Advisory, Advisory.group_package_id == CVEGroupPackage.id)
               ).all()
    if not entries:
        return not_found()

    group = entries[0][0]
    issues = set()
    packages = set()
    advisories = set()
    for group, issue, pkg, advisory in entries:
        issues.add(issue)
        packages.add(pkg)
        if advisory:
            advisories.add(advisory)

    if not user_can_delete_group(advisories):
        return forbidden()

    issues = sorted(issues, key=lambda item: item.id)
    packages = sorted(packages, key=lambda item: item.pkgname)
    advisories = sorted(advisories, key=lambda item: item.id, reverse=True)

    form = ConfirmForm()
    title = 'Delete {}'.format(avg)
    if not form.validate_on_submit():
        return render_template('form/delete_group.html',
                               title=title,
                               heading=title,
                               form=form,
                               group=group,
                               issues=issues,
                               packages=packages)

    if not form.confirm.data:
        return redirect('/{}'.format(group))

    db.session.delete(group)
    db.session.commit()
    flash('Deleted {}'.format(group))
    return redirect('/')


@app.route('/issue/<regex("{}"):issue>/delete'.format(cve_id_regex[1:-1]), methods=['GET', 'POST'])
@app.route('/<regex("{}"):issue>/delete'.format(cve_id_regex[1:-1]), methods=['GET', 'POST'])
@reporter_required
def delete_issue(issue):
    entries = (db.session.query(CVE, CVEGroup, CVEGroupPackage, Advisory)
               .filter(CVE.id == issue)
               .outerjoin(CVEGroupEntry).outerjoin(CVEGroup).outerjoin(CVEGroupPackage)
               .outerjoin(Advisory, Advisory.group_package_id == CVEGroupPackage.id)
               .order_by(CVEGroup.created.desc()).order_by(CVEGroupPackage.pkgname)).all()
    if not entries:
        return not_found()

    issue = entries[0][0]
    advisories = set()
    groups = set()
    group_packages = defaultdict(set)
    for cve, group, pkg, advisory in entries:
        if group:
            groups.add(group)
            group_packages[group].add(pkg.pkgname)
        if advisory:
            advisories.add(advisory)

    if not user_can_delete_issue(advisories):
        return forbidden()

    group_entries = (db.session.query(CVEGroup, CVE)
                     .filter(CVEGroup.id.in_([group.id for group in groups]))
                     .join(CVEGroupEntry).join(CVE)
                     .order_by(CVE.id.desc())).all()

    group_issues = defaultdict(set)
    for group, cve in group_entries:
        group_issues[group].add(cve)

    groups = sorted(groups, key=lambda item: item.created, reverse=True)
    groups = sorted(groups, key=lambda item: item.status)
    group_packages = dict(map(lambda item: (item[0], sorted(item[1])), group_packages.items()))

    form = ConfirmForm()
    title = 'Delete {}'.format(issue)
    if not form.validate_on_submit():
        return render_template('form/delete_cve.html',
                               title=title,
                               heading=title,
                               form=form,
                               issue=issue,
                               groups=groups,
                               group_packages=group_packages,
                               group_issues=group_issues)

    if not form.confirm.data:
        return redirect('/{}'.format(issue))

    # delete groups that only contain this issue
    for group, issues in group_issues.items():
        if 0 == len(list(filter(lambda e: e.id != issue.id, issues))):
            flash('Deleted {}'.format(group))
            db.session.delete(group)

    db.session.delete(issue)
    db.session.commit()
    flash('Deleted {}'.format(issue))
    return redirect('/')
