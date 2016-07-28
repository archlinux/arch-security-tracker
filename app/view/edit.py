from flask import render_template, flash, redirect
from app import app, db
from app.form import CVEForm, GroupForm
from app.model import CVE, CVEGroup, CVEGroupEntry, CVEGroupPackage
from app.model.enum import Remote, Severity, Affected, status_to_affected, affected_to_status, highest_severity
from app.model.cve import cve_id_regex
from app.model.cvegroup import vulnerability_group_regex
from app.view.error import not_found
from app.util import multiline_to_list
from sqlalchemy import func
from itertools import chain
from collections import defaultdict


@app.route('/<regex("{}"):cve>/edit'.format(cve_id_regex[1:-1]), methods=['GET', 'POST'])
def edit_cve(cve):
    cve = db.get(CVE, id=cve)
    if cve is None:
        return not_found()
    form = CVEForm()
    if not form.is_submitted():
        form.cve.data = cve.id
        form.description.data = cve.description
        form.severity.data = cve.severity.name
        form.remote.data = cve.remote.name
        form.notes.data = cve.notes
    if not form.validate_on_submit():
        return render_template('form/cve.html',
                               title='Edit {}'.format(cve),
                               form=form)

    severity = Severity.fromstring(form.severity.data)
    severity_changed = cve.severity != severity

    cve.description = form.description.data
    cve.severity = severity
    cve.remote = Remote.fromstring(form.remote.data)
    cve.notes = form.notes.data

    if severity_changed or True:
        # update cached group severity for all goups containing this issue
        groups = (db.session.query(CVEGroupEntry, CVEGroup)
                  .filter_by(cve=cve).join(CVEGroup)).all()
        issues = (db.session.query(CVEGroup, CVE)
                  .filter(CVEGroup.id.in_([group.id for (entry, group) in groups]))
                  .join(CVEGroupEntry).join(CVE)
                  .group_by(CVEGroup.id).group_by(CVE.id)).all()
        group_severity = defaultdict(list)
        for group, cve in issues:
            group_severity[group].append(cve.severity)
        for group, severities in group_severity.items():
            group.severity = highest_severity(severities)

    db.session.commit()
    flash('Edited {}'.format(cve.id))
    return redirect('/{}'.format(cve.id))


@app.route('/<regex("{}"):avg>/edit'.format(vulnerability_group_regex[1:-1]), methods=['GET', 'POST'])
def edit_group(avg):
    group_id = avg.replace('AVG-', '')
    group_data = (db.session.query(CVEGroup, CVE, func.group_concat(CVEGroupPackage.pkgname, ' '))
                  .filter(CVEGroup.id == group_id)
                  .join(CVEGroupEntry).join(CVE).join(CVEGroupPackage)
                  .group_by(CVEGroup.id).group_by(CVE.id)
                  .order_by(CVE.id)).all()
    if not group_data:
        return not_found()
    group = group_data[0][0]

    form = GroupForm()
    if not form.is_submitted():
        form.affected.data = group.affected
        form.fixed.data = group.fixed
        form.pkgnames.data = "\n".join(sorted(set(chain.from_iterable(
                                       [pkg.split(' ') for (group, cve, pkg) in group_data]))))
        form.status.data = status_to_affected(group.status).name
        form.notes.data = group.notes
        form.bug_ticket.data = group.bug_ticket

        issues = [cve.id for (group, cve, pkg) in group_data]
        form.cve.data = "\n".join(issues)
    if not form.validate_on_submit():
        return render_template('form/group.html',
                               title='Edit {}'.format(avg),
                               form=form)

    pkgnames = multiline_to_list(form.pkgnames.data)
    group.affected = form.affected.data
    group.fixed = form.fixed.data
    group.status = affected_to_status(Affected.fromstring(form.status.data), pkgnames[0], group.fixed)
    group.bug_ticket = form.bug_ticket.data
    group.notes = form.notes.data

    cve_ids = [form.cve.data] if '\r\n' not in form.cve.data else form.cve.data.split('\r\n')
    cve_ids = set(filter(lambda s: s.startswith('CVE-'), cve_ids))

    # TODO: check before delete, only add/delete deltas
    db.session.query(CVEGroupEntry).filter(CVEGroupEntry.group_id == group.id).delete()

    severities = []
    for cve_id in cve_ids:
        cve = db.get_or_create(CVE, id=cve_id)
        severities.append(cve.severity)
        flash('Added {}'.format(cve.id))
        db.get_or_create(CVEGroupEntry, group=group, cve=cve)
    group.severity = highest_severity(severities)

    # TODO: check before delete, only add/delete deltas
    db.session.query(CVEGroupPackage).filter(CVEGroupPackage.group_id == group.id).delete()

    for pkgname in pkgnames:
        db.get_or_create(CVEGroupPackage, pkgname=pkgname, group=group)
        flash('Added {}'.format(pkgname))

    db.session.commit()
    flash('Edited {}'.format(group.name))
    return redirect('/{}'.format(group.name))
