from flask import render_template, flash, redirect
from app import app, db
from app.form import CVEForm, GroupForm
from app.model import CVE, CVEGroup, CVEGroupEntry, CVEGroupPackage
from app.model.enum import Remote, Severity, Affected, affected_to_status, highest_severity
from app.util import multiline_to_list


@app.route('/CVE/add', methods=['GET', 'POST'])
def add_cve():
    form = CVEForm()
    if not form.validate_on_submit():
        return render_template('form/cve.html',
                               title='Add CVE',
                               form=form,
                               CVE=CVE)

    cve = db.get(CVE, id=form.cve.data)
    if cve is not None:
        flash('{} already existed, redirected to edit form:'.format(cve.id))
        return redirect('/{}/edit'.format(cve.id))

    cve = db.create(CVE, id=form.cve.data)
    cve.issue_type = form.issue_type.data
    cve.description = form.description.data
    cve.severity = Severity.fromstring(form.severity.data)
    cve.remote = Remote.fromstring(form.remote.data)
    cve.notes = form.notes.data
    db.session.commit()
    flash('Added {}'.format(cve.id))
    return redirect('/{}'.format(cve.id))


@app.route('/AVG/add', methods=['GET', 'POST'])
def add_group():
    form = GroupForm()
    if not form.validate_on_submit():
        return render_template('form/group.html',
                               title='Add AVG',
                               form=form,
                               CVEGroup=CVEGroup)

    issues = []
    cve_ids = multiline_to_list(form.cve.data)
    cve_ids = set(filter(lambda s: s.startswith('CVE-'), cve_ids))

    for cve_id in cve_ids:
        cve = db.get_or_create(CVE, id=cve_id)
        issues.append(cve)
        flash('Added {}'.format(cve.id))

    pkgnames = multiline_to_list(form.pkgnames.data)
    fixed = form.fixed.data
    affected = Affected.fromstring(form.status.data)
    status = affected_to_status(affected, pkgnames[0], fixed)
    severity = highest_severity([issue.severity for issue in issues])

    group = db.create(CVEGroup,
                      affected=form.affected.data,
                      status=status,
                      fixed=fixed,
                      bug_ticket=form.bug_ticket.data,
                      notes=form.notes.data,
                      severity=severity)
    db.session.commit()

    for cve in issues:
        db.create(CVEGroupEntry, group=group, cve=cve)

    for pkgname in pkgnames:
        db.get_or_create(CVEGroupPackage, pkgname=pkgname, group=group)
        flash('Added {}'.format(pkgname))

    db.session.commit()
    flash('Added {}'.format(group.name))
    return redirect('/{}'.format(group.name))
