from flask import render_template
from app import app, db
from app.model import CVE, CVEGroup, CVEGroupPackage, Advisory
from app.form.advisory import AdvisoryPublishForm
from app.model.enum import Status, Remote, Severity, Publication
from app.pacman import get_pkg
from sqlalchemy import func, or_
from pyalpm import vercmp


@app.route('/todo', methods=['GET'])
def todo():
    scheduled_advisories = (db.session.query(Advisory, CVEGroupPackage, CVEGroup)
                            .join(CVEGroupPackage).join(CVEGroup)
                            .filter(Advisory.publication == Publication.scheduled)
                            .group_by(CVEGroupPackage.id)
                            .order_by(Advisory.created.desc())).all()

    unhandled_advisories = (db.session.query(CVEGroup, func.group_concat(CVEGroupPackage.pkgname, ' '))
                            .join(CVEGroupPackage)
                            .outerjoin(Advisory)
                            .filter(CVEGroup.advisory_qualified)
                            .filter(CVEGroup.status == Status.fixed)
                            .group_by(CVEGroup.id)
                            .having(func.count(Advisory.id) == 0)
                            .order_by(CVEGroup.id)).all()
    for index, item in enumerate(unhandled_advisories):
        unhandled_advisories[index] = (item[0], item[1].split(' '))

    unknown_issues = (db.session.query(CVE)
                      .filter(or_(CVE.remote == Remote.unknown,
                                  CVE.severity == Severity.unknown,
                                  CVE.description.is_(None),
                                  CVE.description == '',
                                  CVE.issue_type.is_(None),
                                  CVE.issue_type == 'unknown'))
                      .order_by(CVE.id.desc())).all()

    vulnerable_groups = (db.session.query(CVEGroup, func.group_concat(CVEGroupPackage.pkgname, ' '))
                         .join(CVEGroupPackage)
                         .filter(CVEGroup.status == Status.vulnerable)
                         .filter(or_(CVEGroup.fixed is None, CVEGroup.fixed == ''))
                         .group_by(CVEGroup.id)
                         .order_by(CVEGroup.created.desc())).all()
    bumped_groups = []
    for group, packages in vulnerable_groups:
        packages = packages.split(' ')
        versions = get_pkg(packages[0], filter_arch=True)
        if not versions:
            continue
        if 0 == vercmp(group.affected, versions[0].version):
            continue
        bumped_groups.append((group, packages, versions))

    entries = {
        'scheduled_advisories': scheduled_advisories,
        'unhandled_advisories': unhandled_advisories,
        'unknown_issues': unknown_issues,
        'bumped_groups': bumped_groups
    }
    return render_template('todo.html',
                           title='Todo Lists',
                           entries=entries,
                           publish_form=AdvisoryPublishForm())
