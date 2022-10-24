from collections import defaultdict
from datetime import datetime
from itertools import chain

from flask import flash
from flask import redirect
from flask import render_template
from sqlalchemy import func
from sqlalchemy.orm import contains_eager
from sqlalchemy_continuum import version_class
from sqlalchemy_continuum import versioning_manager
from werkzeug.exceptions import Conflict

from tracker import db
from tracker import tracker
from tracker.advisory import advisory_fetch_reference_url_from_mailman
from tracker.form import CVEForm
from tracker.form import GroupForm
from tracker.form.advisory import AdvisoryEditForm
from tracker.model import CVE
from tracker.model import Advisory
from tracker.model import CVEGroup
from tracker.model import CVEGroupEntry
from tracker.model import CVEGroupPackage
from tracker.model.advisory import advisory_regex
from tracker.model.cve import cve_id_regex
from tracker.model.cvegroup import vulnerability_group_regex
from tracker.model.enum import Affected
from tracker.model.enum import Publication
from tracker.model.enum import Remote
from tracker.model.enum import Severity
from tracker.model.enum import Status
from tracker.model.enum import affected_to_status
from tracker.model.enum import highest_severity
from tracker.model.enum import status_to_affected
from tracker.user import reporter_required
from tracker.user import security_team_required
from tracker.user import user_can_edit_group
from tracker.user import user_can_edit_issue
from tracker.user import user_can_watch_user_log
from tracker.util import issue_to_numeric
from tracker.util import multiline_to_list
from tracker.view.error import forbidden
from tracker.view.error import not_found

WARNING_ADVISORY_ALREADY_PUBLISHED = 'WARNING: This advisory is already published!'
ERROR_ISSUE_REFERENCED_BY_ADVISORY = 'Insufficient permissions to edit {} that is referenced by an already published advisory!'


@tracker.route('/advisory/<regex("{}"):advisory_id>/edit'.format(advisory_regex[1:-1]), methods=['GET', 'POST'])
@tracker.route('/<regex("{}"):advisory_id>/edit'.format(advisory_regex[1:-1]), methods=['GET', 'POST'])
@security_team_required
def edit_advisory(advisory_id):
    advisory: Advisory = db.get(Advisory, id=advisory_id)
    if not advisory:
        return not_found()

    form = AdvisoryEditForm(advisory.id)
    if not form.is_submitted():
        form.workaround.data = advisory.workaround
        form.impact.data = advisory.impact
        form.reference.data = advisory.reference
        if not advisory.reference and Publication.published == advisory.publication:
            form.reference.data = advisory_fetch_reference_url_from_mailman(advisory)
        form.changed.data = str(advisory.changed)
        form.changed_latest.data = str(advisory.changed)

    concurrent_modification = str(advisory.changed) != form.changed.data

    if not form.validate_on_submit() or (concurrent_modification and not
                                         (form.force_submit.data and str(advisory.changed) == form.changed_latest.data)):
        if advisory.reference:
            flash(WARNING_ADVISORY_ALREADY_PUBLISHED, 'warning')

        code = 200
        advisory_new = None
        if concurrent_modification:
            flash('WARNING: The remote data has changed!', 'warning')
            code = Conflict.code

            advisory_new = Advisory()
            advisory_new.id = form.advisory_id
            advisory_new.workaround = form.workaround.data or None
            advisory_new.workaround_mod = advisory.workaround != advisory_new.workaround
            advisory_new.impact = form.impact.data or None
            advisory_new.impact_mod = advisory.impact != advisory_new.impact
            advisory_new.reference = form.reference.data or None
            advisory_new.reference_mod = advisory.reference != advisory_new.reference

            if form.changed_latest.data != advisory.changed:
                form.force_submit.data = False
            form.changed_latest.data = str(advisory.changed)

            Transaction = versioning_manager.transaction_cls
            VersionClassAdvisory = version_class(Advisory)
            version = (db.session.query(Transaction, VersionClassAdvisory)
                       .outerjoin(VersionClassAdvisory, Transaction.id == VersionClassAdvisory.transaction_id)
                       .filter(VersionClassAdvisory.id == advisory.id)
                       .order_by(Transaction.issued_at.desc())).first()[1]
            advisory_new.transaction = version.transaction
            advisory_new.operation_type = version.operation_type
            advisory_new.previous = advisory

        return render_template('form/advisory.html',
                               title='Edit {}'.format(advisory.id),
                               Advisory=Advisory,
                               advisory=advisory_new,
                               form=form,
                               concurrent_modification=concurrent_modification,
                               can_watch_user_log=user_can_watch_user_log()), code

    advisory.impact = form.impact.data or None
    advisory.workaround = form.workaround.data or None
    if advisory.reference != form.reference.data:
        advisory.content = form.advisory_content
    advisory.reference = form.reference.data or None

    # update changed date on modification
    if db.session.is_modified(advisory):
        advisory.changed = datetime.utcnow()
        flash('Edited {}'.format(advisory.id))

    db.session.commit()
    return redirect('/{}'.format(advisory.id))


@tracker.route('/issue/<regex("{}"):cve>/edit'.format(cve_id_regex[1:-1]), methods=['GET', 'POST'])
@tracker.route('/cve/<regex("{}"):cve>/edit'.format(cve_id_regex[1:-1]), methods=['GET', 'POST'])
@tracker.route('/<regex("{}"):cve>/edit'.format(cve_id_regex[1:-1]), methods=['GET', 'POST'])
@reporter_required
def edit_cve(cve):
    entries = (db.session.query(CVE, CVEGroup, Advisory)
               .filter(CVE.id == cve)
               .outerjoin(CVEGroupEntry, CVEGroupEntry.cve_id == CVE.id)
               .outerjoin(CVEGroup, CVEGroupEntry.group)
               .outerjoin(CVEGroupPackage, CVEGroup.packages)
               .outerjoin(Advisory, Advisory.group_package_id == CVEGroupPackage.id)).all()
    if not entries:
        return not_found()

    cve: CVE = entries[0][0]
    groups = set(group for (cve, group, advisory) in entries if group)
    advisories = set(advisory for (cve, group, advisory) in entries if advisory)

    if not user_can_edit_issue(advisories):
        flash(ERROR_ISSUE_REFERENCED_BY_ADVISORY.format(cve.id), 'error')
        return forbidden()

    form = CVEForm(edit=True)
    if not form.is_submitted():
        form.cve.data = cve.id
        form.issue_type.data = cve.issue_type
        form.description.data = cve.description
        form.severity.data = cve.severity.name
        form.remote.data = cve.remote.name
        form.reference.data = cve.reference
        form.notes.data = cve.notes
        form.changed.data = str(cve.changed)
        form.changed_latest.data = str(cve.changed)

    concurrent_modification = str(cve.changed) != form.changed.data

    if not form.validate_on_submit() or (concurrent_modification and not
                                         (form.force_submit.data and str(cve.changed) == form.changed_latest.data)):
        if advisories:
            flash('WARNING: This is referenced by an already published advisory!', 'warning')

        issue = None
        code = 200
        if concurrent_modification:
            flash('WARNING: The remote data has changed!', 'warning')
            code = Conflict.code

            issue = CVE()
            issue.id = form.cve.data
            issue.issue_type = form.issue_type.data
            issue.issue_type_mod = cve.issue_type != issue.issue_type
            issue.description = form.description.data
            issue.description_mod = cve.description != issue.description
            issue.severity = Severity.fromstring(form.severity.data)
            issue.severity_mod = cve.severity != issue.severity
            issue.remote = Remote.fromstring(form.remote.data)
            issue.remote_mod = cve.remote != issue.remote
            issue.reference = form.reference.data
            issue.reference_mod = cve.reference != issue.reference
            issue.notes = form.notes.data
            issue.notes_mod = cve.notes != issue.notes

            if form.changed_latest.data != cve.changed:
                form.force_submit.data = False
            form.changed_latest.data = str(cve.changed)

            Transaction = versioning_manager.transaction_cls
            VersionClassCVE = version_class(CVE)
            version = (db.session.query(Transaction, VersionClassCVE)
                       .outerjoin(VersionClassCVE, Transaction.id == VersionClassCVE.transaction_id)
                       .filter(VersionClassCVE.id == cve.id)
                       .order_by(Transaction.issued_at.desc())).first()[1]
            issue.transaction = version.transaction
            issue.operation_type = version.operation_type
            issue.previous = cve

        return render_template('form/cve.html',
                               title='Edit {}'.format(cve),
                               form=form,
                               CVE=CVE,
                               issue=issue,
                               concurrent_modification=concurrent_modification,
                               can_watch_user_log=user_can_watch_user_log()), code

    severity = Severity.fromstring(form.severity.data)
    severity_changed = cve.severity != severity
    issue_type_changed = cve.issue_type != form.issue_type.data

    cve.issue_type = form.issue_type.data
    cve.description = form.description.data
    cve.severity = severity
    cve.remote = Remote.fromstring(form.remote.data)
    cve.reference = form.reference.data
    cve.notes = form.notes.data

    if severity_changed or issue_type_changed:
        # update cached group severity for all goups containing this issue
        group_ids = [group.id for group in groups]
        issues = (db.session.query(CVEGroup, CVE)
                  .join(CVEGroupEntry, CVEGroup.issues)
                  .join(CVE, CVEGroupEntry.cve)
                  .group_by(CVEGroup.id).group_by(CVE.id))
        if group_ids:
            issues = issues.filter(CVEGroup.id.in_(group_ids))
        issues = (issues).all()

        if severity_changed:
            group_severity = defaultdict(list)
            for group, issue in issues:
                group_severity[group].append(issue.severity)
            for group, severities in group_severity.items():
                group.severity = highest_severity(severities)

        # update scheduled advisories if the issue type changes
        if advisories and issue_type_changed:
            group_issue_type = defaultdict(set)
            for group, issue in issues:
                group_issue_type[group].add(issue.issue_type)
            for advisory in advisories:
                if Publication.published == advisory.publication:
                    continue
                issue_types = group_issue_type[advisory.group_package.group]
                issue_type = 'multiple issues' if len(issue_types) > 1 else next(iter(issue_types))
                advisory.advisory_type = issue_type

    if db.session.is_modified(cve) or severity_changed or issue_type_changed:
        cve.changed = datetime.utcnow()
        flash('Edited {}'.format(cve.id))

    db.session.commit()
    return redirect('/{}'.format(cve.id))


@tracker.route('/group/<regex("{}"):avg>/edit'.format(vulnerability_group_regex[1:-1]), methods=['GET', 'POST'])
@tracker.route('/avg/<regex("{}"):avg>/edit'.format(vulnerability_group_regex[1:-1]), methods=['GET', 'POST'])
@tracker.route('/<regex("{}"):avg>/edit'.format(vulnerability_group_regex[1:-1]), methods=['GET', 'POST'])
@reporter_required
def edit_group(avg):
    group_id = avg.replace('AVG-', '')
    group_data = (db.session.query(CVEGroup, CVE, func.group_concat(CVEGroupPackage.pkgname, ' '), Advisory)
                  .filter(CVEGroup.id == group_id)
                  .join(CVEGroupEntry, CVEGroup.issues)
                  .join(CVE, CVEGroupEntry.cve)
                  .join(CVEGroupPackage, CVEGroup.packages)
                  .outerjoin(Advisory, Advisory.group_package_id == CVEGroupPackage.id)
                  .group_by(CVEGroup.id).group_by(CVE.id).group_by(CVEGroupPackage.pkgname)
                  .order_by(CVE.id)
                  .options(contains_eager(CVEGroup.issues),
                           contains_eager(CVEGroup.packages))).all()
    if not group_data:
        return not_found()

    group: CVEGroup = group_data[0][0]
    issues = set([cve for (group, cve, pkg, advisory) in group_data])
    issue_ids = set([cve.id for cve in issues])
    pkgnames = set(chain.from_iterable([pkg.split(' ') for (group, cve, pkg, advisory) in group_data]))
    advisories = set(advisory for (group, cve, pkg, advisory) in group_data if advisory)

    if not user_can_edit_group(advisories):
        return forbidden()

    form = GroupForm(pkgnames)
    if not form.is_submitted():
        form.affected.data = group.affected
        form.fixed.data = group.fixed
        form.pkgnames.data = "\n".join(sorted(pkgnames))
        form.status.data = status_to_affected(group.status).name
        form.reference.data = group.reference
        form.notes.data = group.notes
        form.bug_ticket.data = group.bug_ticket
        form.advisory_qualified.data = group.advisory_qualified and group.status is not Status.not_affected
        form.changed.data = str(group.changed)
        form.changed_latest.data = str(group.changed)

        issue_ids = sorted(issue_ids, key=issue_to_numeric)
        form.cve.data = "\n".join(issue_ids)

    concurrent_modification = str(group.changed) != form.changed.data

    if not form.validate_on_submit() or (concurrent_modification and not
                                         (form.force_update.data and str(group.changed) == form.changed_latest.data)):
        if advisories:
            flash('WARNING: This is referenced by an already published advisory!', 'warning')

        group_new = None
        code = 200
        if concurrent_modification:
            flash('WARNING: The remote data has changed!', 'warning')
            code = Conflict.code

            group_new = CVEGroup()
            group_new.id = group.id
            group_new.affected = form.affected.data
            group_new.affected_mod = group.affected != group_new.affected
            group_new.fixed = form.fixed.data
            group_new.fixed_mod = group.fixed != group_new.fixed
            group_new.status = Affected.fromstring(form.status.data)
            group_new.status_mod = group.status != group_new.status
            group_new.reference = form.reference.data
            group_new.reference_mod = group.reference != group_new.reference
            group_new.notes = form.notes.data
            group_new.notes_mod = group.notes != group_new.notes
            group_new.bug_ticket = form.bug_ticket.data
            group_new.bug_ticket_mod = group.bug_ticket != group_new.bug_ticket
            group_new.advisory_qualified = form.advisory_qualified.data
            group_new.advisory_qualified_mod = group.advisory_qualified != group_new.advisory_qualified

            group_new.packages = []
            for pkgname in multiline_to_list(form.pkgnames.data):
                entry = CVEGroupPackage()
                entry.pkgname = pkgname
                group_new.packages.append(entry)

            group_new.issues = []
            for cve in multiline_to_list(form.cve.data):
                entry = CVEGroupEntry()
                entry.cve_id = cve
                group_new.issues.append(entry)

            if form.changed_latest.data != group.changed:
                form.force_update.data = False
            form.changed_latest.data = str(group.changed)

            Transaction = versioning_manager.transaction_cls
            VersionClassCVEGroup = version_class(CVEGroup)
            version = (db.session.query(Transaction, VersionClassCVEGroup)
                       .outerjoin(VersionClassCVEGroup, Transaction.id == VersionClassCVEGroup.transaction_id)
                       .filter(VersionClassCVEGroup.id == group.id)
                       .order_by(Transaction.issued_at.desc())).first()[1]
            group_new.transaction = version.transaction
            group_new.operation_type = version.operation_type
            group_new.previous = group

        return render_template('form/group.html',
                               title='Edit {}'.format(avg),
                               form=form,
                               CVEGroup=CVEGroup,
                               group=group_new,
                               concurrent_modification=concurrent_modification,
                               can_watch_user_log=user_can_watch_user_log()), code

    pkgnames_edited = multiline_to_list(form.pkgnames.data)
    group.affected = form.affected.data
    group.fixed = form.fixed.data
    group.status = affected_to_status(Affected.fromstring(form.status.data), pkgnames_edited[0], group.fixed)
    group.bug_ticket = form.bug_ticket.data
    group.reference = form.reference.data
    group.notes = form.notes.data
    group.advisory_qualified = form.advisory_qualified.data and group.status is not Status.not_affected

    cve_ids = multiline_to_list(form.cve.data)
    cve_ids = set(filter(lambda s: s.startswith('CVE-'), cve_ids))
    issues_removed = set(filter(lambda issue: issue not in cve_ids, issue_ids))
    issues_added = set(filter(lambda issue: issue not in issue_ids, cve_ids))
    issues_final = set(filter(lambda issue: issue.id not in issues_removed, issues))
    issues_changed = any(issues_added) or any(issues_removed)

    # remove old issues
    for issue in filter(lambda issue: issue.cve_id in issues_removed, list(group.issues)):
        group.issues.remove(issue)
        flash('Removed {}'.format(issue.cve_id))

    # add new issues
    severities = [issue.severity for issue in list(filter(lambda issue: issue.id not in issues_removed, issues))]
    for cve_id in issues_added:
        # TODO check if we can avoid this by the latter append call
        cve = db.get(CVE, id=cve_id)
        if not cve:
            cve = CVE.new(id=cve_id)
        db.get_or_create(CVEGroupEntry, group=group, cve=cve)
        flash('Added {}'.format(cve.id))

        severities.append(cve.severity)
        issues_final.add(cve)
    group.severity = highest_severity(severities)

    pkgnames_removed = set(filter(lambda pkgname: pkgname not in pkgnames_edited, pkgnames))
    pkgnames_added = set(filter(lambda pkgname: pkgname not in pkgnames, pkgnames_edited))
    pkgnames_changed = any(pkgnames_removed) or any(pkgnames_added)

    # remove old packages
    for pkg in filter(lambda pkg: pkg.pkgname in pkgnames_removed, list(group.packages)):
        group.packages.remove(pkg)
        flash('Removed {}'.format(pkg.pkgname))

    #  add new packages
    for pkgname in pkgnames_added:
        db.get_or_create(CVEGroupPackage, pkgname=pkgname, group=group)
        flash('Added {}'.format(pkgname))

    # update scheduled advisories
    for advisory in advisories:
        if Publication.published == advisory.publication:
            continue
        issue_type = 'multiple issues' if len(set([issue.issue_type for issue in issues_final])) > 1 else next(iter(issues_final)).issue_type
        advisory.advisory_type = issue_type

    # update changed date on modification
    if pkgnames_changed or issues_changed or db.session.is_modified(group):
        group.changed = datetime.utcnow()
        flash('Edited {}'.format(group.name))

    db.session.commit()
    return redirect('/{}'.format(group.name))
