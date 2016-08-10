from flask import render_template, flash, redirect
from app import app, db
from app.model import CVE, CVEGroup, CVEGroupPackage, Advisory
from app.model.enum import Status, Remote, Severity
from sqlalchemy import func, or_


@app.route('/todo', methods=['GET'])
def todo():
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
                                  CVE.description == ''))
                      .order_by(CVE.id.desc())).all()

    entries = {
        'unhandled_advisories': unhandled_advisories,
        'unknown_issues': unknown_issues,
    }
    return render_template('todo.html',
                           title='Todo Lists',
                           entries=entries)
