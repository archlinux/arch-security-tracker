from flask import render_template, flash, redirect
from app import app, db
from app.form.add import AddCVEForm
from app.model import CVE
from app.model.enum import Remote, Severity


@app.route('/CVE/add', methods=['GET', 'POST'])
def add_cve():
    form = AddCVEForm()
    if not form.validate_on_submit():
        return render_template('form/cve.html',
                               title='Add CVE',
                               form=form)

    cve = db.get(CVE, id=form.cve.data)
    if cve is not None:
        flash('{} already existed, redirected to edit form:'.format(cve.id))
        return redirect('/{}/edit'.format(cve.id))

    cve = db.create(CVE, id=form.cve.data)
    cve.description = form.description.data
    cve.severity = Severity.fromstring(form.severity.data)
    cve.remote = Remote.fromstring(form.remote.data)
    cve.notes = form.notes.data
    db.session.commit()
    flash('Added {}'.format(cve.id))
    return redirect('/{}'.format(cve.id))
