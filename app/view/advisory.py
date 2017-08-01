from flask import render_template, flash, redirect, request
from app import app, db
from app.user import security_team_required
from app.advisory import advisory_get_label, advisory_get_date_label
from app.util import json_response, atom_feed
from app.model import CVE, CVEGroup, CVEGroupEntry, CVEGroupPackage, Advisory
from app.model.cvegroup import vulnerability_group_regex
from app.model.advisory import advisory_regex
from app.model.enum import Publication, Status
from app.view.error import not_found
from app.advisory import advisory_extend_model_from_advisory_text, advisory_fetch_reference_url_from_mailman
from app.form.advisory import AdvisoryForm, AdvisoryPublishForm
from collections import OrderedDict
from sqlalchemy import and_
from re import match
from werkzeug.contrib.atom import AtomFeed
from config import TRACKER_ISSUE_URL


ERROR_ADVISORY_GROUP_NOT_FIXED = 'AVG is not fixed yet.'
ERROR_ADVISORY_ALREADY_EXISTS = 'Advisory already exists.'


def get_advisory_data():
    entries = (db.session.query(Advisory, CVEGroup, CVEGroupPackage)
               .join(CVEGroupPackage).join(CVEGroup)
               .group_by(CVEGroupPackage.id)
               .order_by(Advisory.created.desc())).all()
    entries = [{'advisory': advisory, 'group': group, 'package': package} for advisory, group, package in entries]

    scheduled = list(filter(lambda item: item['advisory'].publication == Publication.scheduled, entries))
    scheduled = sorted(scheduled, key=lambda item: item['advisory'].created, reverse=True)

    published = list(filter(lambda item: item['advisory'].publication == Publication.published, entries))
    published = sorted(published, key=lambda item: item['advisory'].created, reverse=True)

    return {
        'scheduled': scheduled,
        'published': published
    }


@atom_feed('Recent advisories')
@app.route('/advisories/feed.atom', methods=['GET'])
@app.route('/advisory/feed.atom', methods=['GET'])
def advisory_atom():
    last_recent_entries = 15
    data = get_advisory_data()['published'][:last_recent_entries]
    feed = AtomFeed('Arch Linux Security - Recent advisories',
                    feed_url=request.url, url=request.url_root)

    for entry in data:
        advisory = entry['advisory']
        package = entry['package']
        title = '[{}] {}: {}'.format(advisory.id, package.pkgname, advisory.advisory_type)

        feed.add(title=title,
                 content=render_template('feed.html', content=advisory.content),
                 content_type='html',
                 summary=render_template('feed.html', content=advisory.impact),
                 summary_tpe='html',
                 author='Arch Linux Security Team',
                 url=TRACKER_ISSUE_URL.format(advisory.id),
                 published=advisory.created,
                 updated=advisory.created)
    return feed.get_response()


@app.route('/advisory<regex("[./]json"):postfix>', methods=['GET'])
@app.route('/advisories<regex("[./]json"):postfix>', methods=['GET'])
@json_response
def advisory_json(postfix=None):
    data = get_advisory_data()

    def to_json_data(entry):
        advisory = entry['advisory']
        group = entry['group']
        package = entry['package']

        json_entry = OrderedDict()
        json_entry['name'] = advisory.id
        json_entry['date'] = advisory.created.strftime('%Y-%m-%d')
        json_entry['group'] = group.name
        json_entry['package'] = package.pkgname
        json_entry['severity'] = group.severity.label
        json_entry['type'] = advisory.advisory_type
        json_entry['reference'] = advisory.reference if advisory.reference else None
        return json_entry

    return list(map(to_json_data, data['published']))


@app.route('/advisory', methods=['GET'])
@app.route('/advisories', methods=['GET'])
def advisory():
    data = get_advisory_data()

    monthly_published = OrderedDict()
    for item in data['published']:
        advisory = item['advisory']
        month = advisory.created.strftime('%B %Y')
        if month not in monthly_published:
            monthly_published[month] = []
        monthly_published[month].append(item)

    return render_template('advisories.html',
                           title='Advisories',
                           scheduled=data['scheduled'],
                           published=monthly_published)


@app.route('/group/<regex("{}"):avg>/schedule'.format(vulnerability_group_regex[1:-1]), methods=['PUT', 'POST'])
@app.route('/<regex("{}"):avg>/schedule'.format(vulnerability_group_regex[1:-1]), methods=['PUT', 'POST'])
@security_team_required
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

    if Status.fixed != group_entry.status:
        flash(ERROR_ADVISORY_GROUP_NOT_FIXED, 'error')
        return redirect('/{}'.format(avg))

    if 0 < len(advisories):
        flash(ERROR_ADVISORY_ALREADY_EXISTS, 'error')
        return redirect('/{}'.format(avg))

    last_advisory_date = advisory_get_date_label()
    last_advisory_num = 0
    last_advisory = (db.session.query(Advisory).order_by(Advisory.created.desc()).limit(1)).first()
    if last_advisory:
        m = match(advisory_regex, last_advisory.id)
        if last_advisory_date == m.group(2):
            last_advisory_num = int(m.group(3))

    for pkg in pkgs:
        last_advisory_num += 1
        asa = advisory_get_label(last_advisory_date, last_advisory_num)
        db.create(Advisory,
                  id=asa,
                  advisory_type=form.advisory_type.data,
                  publication=Publication.scheduled,
                  group_package=pkg)
    db.session.commit()

    flash('Scheduled {}'.format(asa))
    return redirect('/{}'.format(asa))


@app.route('/advisory/<regex("{}"):avg>/publish'.format(advisory_regex[1:-1]), methods=['PUT', 'POST', 'GET'])
@app.route('/<regex("{}"):asa>/publish'.format(advisory_regex[1:-1]), methods=['PUT', 'POST', 'GET'])
@security_team_required
def publish_advisory(asa):
    advisory = (db.session.query(Advisory)
                .filter(Advisory.id == asa)
                ).first()
    if not advisory:
        return not_found()

    if advisory.publication == Publication.published:
        return redirect('/{}'.format(asa))

    form = AdvisoryPublishForm(advisory.id)
    if not form.is_submitted():
        form.reference.data = advisory.reference
        if not advisory.reference:
            form.reference.data = advisory_fetch_reference_url_from_mailman(advisory)
    if not form.validate_on_submit():
        return render_template('form/publish.html',
                               title='Publish {}'.format(advisory.id),
                               Advisory=Advisory,
                               form=form)

    if advisory.reference != form.reference.data:
        advisory.content = form.advisory_content
        advisory_extend_model_from_advisory_text(advisory)
    advisory.reference = form.reference.data
    advisory.publication = Publication.published
    db.session.commit()

    flash('Published {}'.format(advisory.id))
    return redirect('/advisory')
