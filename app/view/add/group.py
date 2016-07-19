from flask import render_template, flash, redirect
from app import app, db
from app.form import GroupForm
from app.model import CVE, CVEGroup, CVEGroupEntry
from app.model.enum import Status


@app.route('/AVG/add', methods=['GET', 'POST'])
def add_group():
    form = GroupForm()
    if not form.validate_on_submit():
        return render_template('form/group.html',
                               title='Add vulnerability group',
                               form=form)

    group = db.create(CVEGroup, pkgname=form.pkgname.data, affected=form.affected.data, status=Status.fromstring(form.status.data))
    group.fixed = form.fixed.data
    group.bug_ticket = form.bug_ticket.data
    group.notes = form.notes.data
    db.session.commit()

    cve_ids = [form.cve.data] if '\r\n' not in form.cve.data else form.cve.data.split('\r\n')
    cve_ids = set(filter(lambda s: s.startswith('CVE-'), cve_ids))

    for cve_id in cve_ids:
        cve = db.get_or_create(CVE, id=cve_id)
        flash('Added {}'.format(cve.id))
        db.create(CVEGroupEntry, group=group, cve=cve)

    db.session.commit()
    flash('Added AVG-{}'.format(group.id))
    return redirect('/AVG-{}'.format(group.id))
