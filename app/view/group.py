from flask import render_template, flash, redirect
from app import app
from app import db
from app.model import CVE, CVEGroup, CVEGroupEntry


@app.route('/AVG-<group_id>')
@app.route('/group/<group_id>')
def group(group_id):
    entries = (db.session.query(CVEGroup, CVE).filter_by(id=group_id).join(CVEGroupEntry).join(CVE)).all()
    if not entries:
        return '404'

    group = None
    cves = []
    for group_entry, cve in entries:
        group = group_entry
        cves.append(cve)

    cves = sorted(cves, key=lambda item: item.id, reverse=True)

    out = {
        'detail': group,
        'cves': cves
    }
    return render_template('group.html',
                           title='{}'.format(group.name),
                           group=out)
