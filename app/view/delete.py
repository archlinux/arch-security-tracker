from flask import render_template, flash, redirect
from app import app, db
from app.user import security_team_required
from app.form.confirm import ConfirmForm
from app.model import CVEGroup, CVE, CVEGroupPackage, CVEGroupEntry, Advisory
from app.model.cvegroup import vulnerability_group_regex
from app.view.error import not_found, forbidden


@app.route('/group/<regex("{}"):avg>/delete'.format(vulnerability_group_regex[1:-1]), methods=['GET', 'POST'])
@app.route('/<regex("{}"):avg>/delete'.format(vulnerability_group_regex[1:-1]), methods=['GET', 'POST'])
@security_team_required
def delete_group(avg):
    avg_id = avg.replace('AVG-', '')
    entries = (db.session.query(CVEGroup, CVE, CVEGroupPackage, Advisory)
               .filter(CVEGroup.id == avg_id)
               .join(CVEGroupEntry).join(CVE).join(CVEGroupPackage)
               .outerjoin(Advisory, Advisory.group_package_id == CVEGroupPackage.id)
               ).all()
    if not entries:
        return not_found()

    group = entries[0][0]
    issues = set()
    packages = set()
    advisories = set()
    for group, issue, pkg, advisory in entries:
        issues.add(issue)
        packages.add(pkg)
        if advisory:
            advisories.add(advisory)

    if advisories:
        return forbidden()

    issues = sorted(issues, key=lambda item: item.id)
    packages = sorted(packages, key=lambda item: item.pkgname)
    advisories = sorted(advisories, key=lambda item: item.id, reverse=True)

    form = ConfirmForm()
    title = 'Delete {}'.format(avg)
    if not form.validate_on_submit():
        return render_template('form/delete_group.html',
                               title=title,
                               heading=title,
                               form=form,
                               group=group,
                               issues=issues,
                               packages=packages)

    if not form.confirm.data:
        return redirect('/{}'.format(group))

    db.session.delete(group)
    db.session.commit()
    flash('Deleted {}'.format(group))
    return redirect('/')
