from flask import render_template, flash, redirect
from app import app, db
from app.model import CVEGroupPackage, Advisory
from app.model.enum import Publication
from collections import defaultdict


@app.route('/advisory')
def advisory():
    entries = (db.session.query(Advisory, CVEGroupPackage)
               .join(CVEGroupPackage)
               .order_by(Advisory.created.desc())).all()

    scheduled = list(filter(lambda item: item[0].publication == Publication.scheduled, entries))
    scheduled = sorted(scheduled, key=lambda item: item[0].id, reverse=True)

    published = list(filter(lambda item: item[0].publication == Publication.published, entries))
    published = sorted(published, key=lambda item: item[0].id, reverse=True)

    monthly_published = defaultdict(list)
    for item in published:
        advisory = item[0]
        package = item[1]
        monthly_published[advisory.created.strftime('%B %Y')].append((advisory, package))

    entries = {
        'scheduled': scheduled,
        'published': monthly_published
    }
    return render_template('advisory.html',
                           title='Advisories',
                           entries=entries)
