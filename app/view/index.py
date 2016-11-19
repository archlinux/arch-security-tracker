from flask import render_template
from app import app, db
from app.model import CVE, CVEGroup, CVEGroupEntry, CVEGroupPackage, Advisory
from app.model.enum import Publication, Status
from collections import defaultdict
from sqlalchemy import func, and_


@app.route('/open', methods=['GET'])
@app.route('/index/vulnerable', methods=['GET'])
@app.route('/index/open', methods=['GET'])
@app.route('/issue/vulnerable', methods=['GET'])
@app.route('/issue/open', methods=['GET'])
@app.route('/issues/vulnerable', methods=['GET'])
@app.route('/issues/open', methods=['GET'])
@app.route('/vulnerable', methods=['GET'])
def index_vulnerable():
    return index(only_vulnerable=True)


@app.route('/index', methods=['GET'])
@app.route('/issue', methods=['GET'])
@app.route('/issues', methods=['GET'])
@app.route('/', methods=['GET'])
def index(only_vulnerable=False):
    select = (db.session.query(CVEGroup, CVE, func.group_concat(CVEGroupPackage.pkgname, ' '),
                               func.group_concat(Advisory.id, ' '))
                        .join(CVEGroupEntry).join(CVE).join(CVEGroupPackage)
                        .outerjoin(Advisory, and_(Advisory.group_package_id == CVEGroupPackage.id,
                                                  Advisory.publication == Publication.published)))
    if only_vulnerable:
        select = select.filter(CVEGroup.status.in_([Status.unknown, Status.vulnerable, Status.testing]))

    entries = (select.group_by(CVEGroup.id).group_by(CVE.id)
                     .order_by(CVEGroup.status.desc())
                     .order_by(CVEGroup.created.desc())).all()

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
    groups = sorted(groups, key=lambda item: item['group'].severity)
    groups = sorted(groups, key=lambda item: item['group'].status)

    return render_template('index.html',
                           title='Issues' if not only_vulnerable else 'Vulnerable issues',
                           entries=groups,
                           only_vulnerable=only_vulnerable)
