from flask import render_template, flash, redirect
from app import app, db
from app.form.add import AddCVEForm
from app.model import CVE
from app.model.enum import Remote, Severity
from app.model.cve import cve_id_regex


@app.route('/<regex("{}"):cve>/edit'.format(cve_id_regex[1:-1]), methods=['GET', 'POST'])
def edit_cve(cve):
    cve = db.get(CVE, id=cve)
    if cve is None:
        return "404"
    form = AddCVEForm()
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
