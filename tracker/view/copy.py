from itertools import chain

from flask import render_template
from sqlalchemy import func

from tracker import db
from tracker import tracker
from tracker.form import CVEForm
from tracker.form import GroupForm
from tracker.model import CVE
from tracker.model import CVEGroup
from tracker.model import CVEGroupEntry
from tracker.model import CVEGroupPackage
from tracker.model.cve import cve_id_regex
from tracker.model.cvegroup import vulnerability_group_regex
from tracker.model.enum import status_to_affected
from tracker.user import reporter_required
from tracker.view.error import not_found


@tracker.route('/issue/<regex("{}"):issue>/copy'.format(cve_id_regex[1:-1]), methods=['GET'])
@tracker.route('/cve/<regex("{}"):issue>/copy'.format(cve_id_regex[1:-1]), methods=['GET'])
@tracker.route('/<regex("{}"):issue>/copy'.format(cve_id_regex[1:-1]), methods=['GET'])
@reporter_required
def copy_issue(issue):
    cve = db.get(CVE, id=issue)
    if not cve:
        return not_found()

    form = CVEForm()
    form.cve.data = cve.id
    form.description.data = cve.description
    form.issue_type.data = cve.issue_type
    form.notes.data = cve.notes
    form.reference.data = cve.reference
    form.remote.data = cve.remote.name
    form.severity.data = cve.severity.name

    return render_template('form/cve.html',
                           title='Add CVE',
                           form=form,
                           CVE=CVE,
                           action='/cve/add')


@tracker.route('/group/<regex("{}"):avg>/copy'.format(vulnerability_group_regex[1:-1]), methods=['GET'])
@tracker.route('/avg/<regex("{}"):avg>/copy'.format(vulnerability_group_regex[1:-1]), methods=['GET'])
@tracker.route('/<regex("{}"):avg>/copy'.format(vulnerability_group_regex[1:-1]), methods=['GET'])
@reporter_required
def copy_group(avg):
    group_id = avg.replace('AVG-', '')
    group_data = (db.session.query(CVEGroup, CVE, func.group_concat(CVEGroupPackage.pkgname, ' '))
                  .filter(CVEGroup.id == group_id)
                  .join(CVEGroupEntry).join(CVE).join(CVEGroupPackage)
                  .group_by(CVEGroup.id).group_by(CVE.id)
                  .order_by(CVE.id)).all()
    if not group_data:
        return not_found()

    group = group_data[0][0]
    issues = [cve for (group, cve, pkg) in group_data]
    issue_ids = [cve.id for cve in issues]
    pkgnames = set(chain.from_iterable([pkg.split(' ') for (group, cve, pkg) in group_data]))

    form = GroupForm()
    form.advisory_qualified.data = group.advisory_qualified
    form.affected.data = group.affected
    form.bug_ticket.data = group.bug_ticket
    form.cve.data = '\n'.join(issue_ids)
    form.fixed.data = group.fixed
    form.notes.data = group.notes
    form.pkgnames.data = '\n'.join(sorted(pkgnames))
    form.reference.data = group.reference
    form.status.data = status_to_affected(group.status).name

    return render_template('form/group.html',
                           title='Add AVG',
                           form=form,
                           CVEGroup=CVEGroup,
                           action='/avg/add')
