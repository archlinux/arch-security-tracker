from flask import render_template, flash, redirect
from app import app, db
from app.model import CVE, CVEGroup, CVEGroupEntry
from collections import defaultdict


@app.route('/')
@app.route('/index')
def index():
    entries = (db.session.query(CVEGroup, CVE).join(CVEGroupEntry).join(CVE)
               .order_by(CVEGroup.status.desc()).order_by(CVEGroup.created.desc())).all()
    groups = defaultdict(defaultdict)
    for group, cve in entries:
        group_entry = groups.setdefault(group.id, {})
        group_entry['group'] = group
        group_entry.setdefault('cves', []).append(cve)

    for key, group in groups.items():
        groups[key]['cves'] = sorted(groups[key]['cves'], key=lambda item: item.id, reverse=True)

    groups = groups.values()
    groups = sorted(groups, key=lambda item: item['group'].created, reverse=True)
    groups = sorted(groups, key=lambda item: item['group'].status)

    return render_template('index.html',
                           title='Index',
                           entries=groups)
