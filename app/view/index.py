from flask import render_template, flash, redirect
from app import app, db
from app.model import CVE, CVEGroup, CVEGroupEntry, CVEGroupPackage, Advisory
from app.model.enum import Publication
from collections import defaultdict
from sqlalchemy import func, and_


@app.route('/', methods=['GET'])
@app.route('/index', methods=['GET'])
@app.route('/issue', methods=['GET'])
@app.route('/issues', methods=['GET'])
def index():
    entries = (db.session.query(CVEGroup, CVE, func.group_concat(CVEGroupPackage.pkgname, ' '), func.group_concat(Advisory.id, ' '))
               .join(CVEGroupEntry).join(CVE).join(CVEGroupPackage)
               .outerjoin(Advisory, and_(Advisory.group_package_id == CVEGroupPackage.id,
                                         Advisory.publication == Publication.published))
               .group_by(CVEGroup.id).group_by(CVE.id)
               .order_by(CVEGroup.status.desc()).order_by(CVEGroup.created.desc())).all()

    groups = defaultdict(defaultdict)
    for group, cve, pkgs, advisories in entries:
        group_entry = groups.setdefault(group.id, {})
        group_entry['group'] = group
        group_entry['pkgs'] = pkgs.split(' ')
        group_entry['advisories'] = advisories.split(' ') if advisories else []
        group_entry.setdefault('cves', []).append(cve)

    for key, group in groups.items():
        group['cves'] = sorted(group['cves'], key=lambda item: item.id, reverse=True)

    groups = groups.values()
    groups = sorted(groups, key=lambda item: item['group'].created, reverse=True)
    groups = sorted(groups, key=lambda item: item['group'].status)

    return render_template('index.html',
                           title='Index',
                           entries=groups)
