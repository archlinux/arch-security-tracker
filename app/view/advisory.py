from flask import render_template, flash, redirect
from app import app, db
from app.model import CVE, CVEGroup, CVEGroupEntry, CVEGroupPackage, Advisory
from app.model.cvegroup import vulnerability_group_regex
from app.model.advisory import advisory_regex
from app.model.enum import Publication
from app.form.advisory import AdvisoryPublishForm
from app.view.error import not_found
from app.form.advisory import AdvisoryForm
from collections import OrderedDict
from sqlalchemy import and_
from datetime import datetime
from re import match


@app.route('/advisory', methods=['GET'])
@app.route('/advisories', methods=['GET'])
def advisory():
    entries = (db.session.query(Advisory, CVEGroupPackage, CVEGroup)
               .join(CVEGroupPackage).join(CVEGroup)
               .group_by(CVEGroupPackage.id)
               .order_by(Advisory.created.desc())).all()

    scheduled = list(filter(lambda item: item[0].publication == Publication.scheduled, entries))
    scheduled = sorted(scheduled, key=lambda item: item[0].created, reverse=True)

    published = list(filter(lambda item: item[0].publication == Publication.published, entries))
    published = sorted(published, key=lambda item: item[0].created, reverse=True)

    monthly_published = OrderedDict()
    for item in published:
        advisory = item[0]
        month = advisory.created.strftime('%B %Y')
        if month not in monthly_published:
            monthly_published[month] = []
        monthly_published[month].append(item)

    entries = {
        'scheduled': scheduled,
        'published': monthly_published
    }
    return render_template('advisory.html',
                           title='Advisories',
                           entries=entries)


@app.route('/group/<regex("{}"):avg>/schedule'.format(vulnerability_group_regex[1:-1]), methods=['PUT', 'POST'])
@app.route('/<regex("{}"):avg>/schedule'.format(vulnerability_group_regex[1:-1]), methods=['PUT', 'POST'])
def schedule_advisory(avg):
    avg_id = avg.replace('AVG-', '')
    form = AdvisoryForm()

    if not form.validate_on_submit():
        flash('Form validation failed', 'error')
        return redirect('/{}'.format(avg))

    entries = (db.session.query(CVEGroup, CVE, CVEGroupPackage, Advisory)
               .filter(CVEGroup.id == avg_id)
               .join(CVEGroupEntry).join(CVE).join(CVEGroupPackage)
               .outerjoin(Advisory, and_(Advisory.group_package_id == CVEGroupPackage.id))
               ).all()
    if not entries:
        return not_found()

    pkgs = set()
    advisories = set()
    for group_entry, cve, pkg, advisory in entries:
        pkgs.add(pkg)
        if advisory:
            advisories.add(advisory)

    if 0 < len(advisories):
        flash('Advisory already exists', 'error')
        return redirect('/{}'.format(avg))

    now = datetime.utcnow().utctimetuple()
    last_advisory_date = '{}{}'.format(now.tm_year, '{}'.format(now.tm_mon).rjust(2, '0'))
    last_advisory_num = 0
    last_advisory = (db.session.query(Advisory).order_by(Advisory.created.desc()).limit(1)).first()
    if last_advisory:
        m = match(advisory_regex, last_advisory.id)
        if last_advisory_date == m.group(2):
            last_advisory_num = int(m.group(3))

    for pkg in pkgs:
        last_advisory_num += 1
        asa = 'ASA-{}-{}'.format(last_advisory_date, last_advisory_num)
        db.create(Advisory,
                  id=asa,
                  advisory_type=form.advisory_type.data,
                  publication=Publication.scheduled,
                  group_package=pkg)
        flash('Scheduled {}'.format(asa))
    db.session.commit()

    return redirect('/{}'.format(avg))


@app.route('/advisory/<regex("{}"):avg>/publish'.format(advisory_regex[1:-1]), methods=['PUT', 'POST'])
@app.route('/<regex("{}"):asa>/publish'.format(advisory_regex[1:-1]), methods=['PUT', 'POST'])
def publish_advisory(asa):
    form = AdvisoryPublishForm()
    if not form.validate_on_submit():
        flash('Form validation failed', 'error')
        return redirect('/{}'.format(asa))

    advisory = (db.session.query(Advisory)
               .filter(Advisory.id == asa)
               ).first()
    if not advisory:
        return not_found()

    if advisory.publication == Publication.published:
        return redirect('/{}'.format(asa))

    advisory.publication = Publication.published
    db.session.commit()
    return redirect('/{}'.format(asa))
