from flask import render_template, flash, redirect
from app import app, db
from app.form import CVEForm, GroupForm
from app.model import CVE, CVEGroup, CVEGroupEntry
from app.model.enum import Remote, Severity, Affected
from app.model.cve import cve_id_regex
from app.model.cvegroup import vulnerability_group_regex
from app.view.error import not_found
from app.util import status_to_affected, affected_to_status


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
    cve.description = form.description.data
    cve.severity = Severity.fromstring(form.severity.data)
    cve.remote = Remote.fromstring(form.remote.data)
    cve.notes = form.notes.data
    db.session.commit()
    flash('Edited {}'.format(cve.id))
    return redirect('/{}'.format(cve.id))


@app.route('/<regex("{}"):avg>/edit'.format(vulnerability_group_regex[1:-1]), methods=['GET', 'POST'])
def edit_group(avg):
    group = db.get(CVEGroup, id=avg[4:])
    if group is None:
        return not_found()
    form = GroupForm()
    if not form.is_submitted():
        form.affected.data = group.affected
        form.fixed.data = group.fixed
        form.pkgname.data = group.pkgname
        form.status.data = status_to_affected(group.status).name
        form.notes.data = group.notes
        form.bug_ticket.data = group.bug_ticket

        issues = (db.session.query(CVEGroup, CVE).filter_by(id=group.id).join(CVEGroupEntry).join(CVE).order_by(CVEGroup.id)).all()
        issues = [cve.id for (group, cve) in issues]
        form.cve.data = "\n".join(issues)
    if not form.validate_on_submit():
        return render_template('form/group.html',
                               title='Edit {}'.format(avg),
                               form=form)

    group.pkgname = form.pkgname.data
    group.affected = form.affected.data
    group.fixed = form.fixed.data
    group.status = affected_to_status(Affected.fromstring(form.status.data), group.pkgname, group.fixed)
    group.bug_ticket = form.bug_ticket.data
    group.notes = form.notes.data

    cve_ids = [form.cve.data] if '\r\n' not in form.cve.data else form.cve.data.split('\r\n')
    cve_ids = set(filter(lambda s: s.startswith('CVE-'), cve_ids))

    db.session.query(CVEGroupEntry).filter(CVEGroupEntry.group_id == group.id).delete()

    for cve_id in cve_ids:
        cve = db.get_or_create(CVE, id=cve_id)
        flash('Added {}'.format(cve.id))
        db.get_or_create(CVEGroupEntry, group=group, cve=cve)

    db.session.commit()
    flash('Edited {}'.format(group.name))
    return redirect('/{}'.format(group.name))
