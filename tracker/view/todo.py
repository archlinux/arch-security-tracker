from collections import defaultdict
from operator import attrgetter
from random import randint

from flask import render_template
from sqlalchemy import and_
from sqlalchemy import func
from sqlalchemy import or_

from pyalpm import vercmp
from tracker import db
from tracker import tracker
from tracker.model import CVE
from tracker.model import Advisory
from tracker.model import CVEGroup
from tracker.model import CVEGroupEntry
from tracker.model import CVEGroupPackage
from tracker.model import Package
from tracker.model.enum import Publication
from tracker.model.enum import Remote
from tracker.model.enum import Severity
from tracker.model.enum import Status
from tracker.model.package import filter_duplicate_packages
from tracker.symbol import smileys_happy
from tracker.user import user_can_edit_group
from tracker.user import user_can_edit_issue
from tracker.user import user_can_handle_advisory
from tracker.util import cmp_to_key


@tracker.route('/todo', methods=['GET'])
def todo():
    incomplete_advisories = (db.session.query(Advisory, CVEGroupPackage, CVEGroup)
                             .join(CVEGroupPackage).join(CVEGroup)
                             .filter(and_(
                                 Advisory.publication == Publication.published,
                                 or_(Advisory.content == '', Advisory.content.is_(None),
                                     Advisory.reference == '', Advisory.reference.is_(None))))
                             .group_by(CVEGroupPackage.id)
                             .order_by(Advisory.created.desc())).all()

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
    unhandled_advisories = sorted(unhandled_advisories, key=lambda item: item[0].id)
    unhandled_advisories = sorted(unhandled_advisories, key=lambda item: item[0].severity)

    unknown_issues = (db.session.query(CVE)
                      .filter(or_(CVE.remote == Remote.unknown,
                                  CVE.severity == Severity.unknown,
                                  CVE.description.is_(None),
                                  CVE.description == '',
                                  CVE.issue_type.is_(None),
                                  CVE.issue_type == 'unknown'))
                      .order_by(CVE.id.desc())).all()

    unknown_groups = CVEGroup.query.filter(CVEGroup.status == Status.unknown).all()
    unknown_groups = (db.session.query(CVEGroup, Package)
                        .join(CVEGroupPackage).join(Package, Package.name == CVEGroupPackage.pkgname)
                        .filter(CVEGroup.status == Status.unknown)
                        .group_by(CVEGroupPackage.id)
                        .order_by(CVEGroup.created.desc())).all()

    unknown_groups_data = defaultdict(list)
    for group, package in unknown_groups:
        unknown_groups_data[group].append(package)
    unknown_groups = []
    for group, packages in unknown_groups_data.items():
        unknown_groups.append((group, packages))
    unknown_groups = sorted(unknown_groups, key=lambda item: item[0].id)

    vulnerable_groups = (db.session.query(CVEGroup, Package)
                         .join(CVEGroupPackage).join(Package, Package.name == CVEGroupPackage.pkgname)
                         .filter(CVEGroup.status == Status.vulnerable)
                         .filter(or_(CVEGroup.fixed is None, CVEGroup.fixed == ''))
                         .group_by(CVEGroup.id).group_by(Package.name, Package.version)
                         .order_by(CVEGroup.created.desc())).all()

    vulnerable_group_data = defaultdict(list)
    for group, package in vulnerable_groups:
        vulnerable_group_data[group].append(package)

    bumped_groups = []
    for group, packages in vulnerable_group_data.items():
        packages = sorted(packages, key=cmp_to_key(vercmp, attrgetter('version')), reverse=True)
        if 0 == vercmp(group.affected, packages[0].version):
            continue
        versions = filter_duplicate_packages(packages, filter_arch=True)
        pkgnames = set([pkg.name for pkg in packages])
        bumped_groups.append((group, pkgnames, versions))
    bumped_groups = sorted(bumped_groups, key=lambda item: item[0].id, reverse=True)
    bumped_groups = sorted(bumped_groups, key=lambda item: item[0].severity)

    orphan_issues = (db.session.query(CVE)
                       .outerjoin(CVEGroupEntry)
                       .group_by(CVE.id)
                       .having(func.count(CVEGroupEntry.id) == 0)
                       .order_by(CVE.id)).all()

    entries = {
        'scheduled_advisories': scheduled_advisories,
        'incomplete_advisories': incomplete_advisories,
        'unhandled_advisories': unhandled_advisories,
        'unknown_issues': unknown_issues,
        'unknown_groups': unknown_groups,
        'bumped_groups': bumped_groups,
        'orphan_issues': orphan_issues
    }
    return render_template('todo.html',
                           title='Todo Lists',
                           entries=entries,
                           smiley=smileys_happy[randint(0, len(smileys_happy) - 1)],
                           can_handle_advisory=user_can_handle_advisory(),
                           can_edit_group=user_can_edit_group(),
                           can_edit_issue=user_can_edit_issue())
