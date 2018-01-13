from collections import defaultdict

from flask import flash
from flask import redirect
from flask import render_template

from tracker import db
from tracker import tracker
from tracker.form.confirm import ConfirmForm
from tracker.model import CVE
from tracker.model import Advisory
from tracker.model import CVEGroup
from tracker.model import CVEGroupEntry
from tracker.model import CVEGroupPackage
from tracker.model.advisory import advisory_regex
from tracker.model.cve import cve_id_regex
from tracker.model.cvegroup import vulnerability_group_regex
from tracker.model.enum import Publication
from tracker.user import reporter_required
from tracker.user import security_team_required
from tracker.user import user_can_delete_group
from tracker.user import user_can_delete_issue
from tracker.view.error import forbidden
from tracker.view.error import not_found


@tracker.route('/group/<regex("{}"):avg>/delete'.format(vulnerability_group_regex[1:-1]), methods=['GET', 'POST'])
@tracker.route('/<regex("{}"):avg>/delete'.format(vulnerability_group_regex[1:-1]), methods=['GET', 'POST'])
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


@tracker.route('/issue/<regex("{}"):issue>/delete'.format(cve_id_regex[1:-1]), methods=['GET', 'POST'])
@tracker.route('/<regex("{}"):issue>/delete'.format(cve_id_regex[1:-1]), methods=['GET', 'POST'])
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

    group_ids = [group.id for group in groups]

    group_entries = (db.session.query(CVEGroup, CVE)
                     .join(CVEGroupEntry).join(CVE)
                     .order_by(CVE.id.desc()))
    if group_ids:
        group_entries = group_entries.filter(CVEGroup.id.in_(group_ids))
    group_entries = group_entries.all()

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


@tracker.route('/advisory/<regex("{}"):advisory_id>/delete'.format(advisory_regex[1:-1]), methods=['GET', 'POST'])
@tracker.route('/<regex("{}"):advisory_id>/delete'.format(advisory_regex[1:-1]), methods=['GET', 'POST'])
@security_team_required
def delete_advisory(advisory_id):
    advisory, pkg, group = (db.session.query(Advisory, CVEGroupPackage, CVEGroup)
                            .filter(Advisory.id == advisory_id)
                            .join(CVEGroupPackage).join(CVEGroup)).first()

    if not advisory:
        return not_found()

    if Publication.scheduled != advisory.publication:
        return forbidden()

    form = ConfirmForm()
    title = 'Delete {}'.format(advisory.id)
    if not form.validate_on_submit():
        return render_template('form/delete_advisory.html',
                               title=title,
                               heading=title,
                               form=form,
                               advisory=advisory,
                               pkg=pkg,
                               group=group)

    if not form.confirm.data:
        return redirect('/{}'.format(advisory.id))

    db.session.delete(advisory)
    db.session.commit()
    flash('Deleted {}'.format(advisory.id))
    return redirect('/')
