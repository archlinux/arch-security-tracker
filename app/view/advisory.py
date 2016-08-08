from flask import render_template, flash, redirect
from app import app, db
from app.model import CVEGroupPackage, Advisory
from app.model.enum import Publication
from collections import OrderedDict


@app.route('/advisory')
def advisory():
    entries = (db.session.query(Advisory, CVEGroupPackage)
               .join(CVEGroupPackage)
               .order_by(Advisory.created.desc())).all()

    scheduled = list(filter(lambda item: item[0].publication == Publication.scheduled, entries))
    scheduled = sorted(scheduled, key=lambda item: item[0].created, reverse=True)

    published = list(filter(lambda item: item[0].publication == Publication.published, entries))
    published = sorted(published, key=lambda item: item[0].created, reverse=True)

    monthly_published = OrderedDict()
    for item in published:
        advisory = item[0]
        package = item[1]
        month = advisory.created.strftime('%B %Y')
        if month not in monthly_published:
            monthly_published[month] = []
        monthly_published[month].append((advisory, package))

    entries = {
        'scheduled': scheduled,
        'published': monthly_published
    }
    return render_template('advisory.html',
                           title='Advisories',
                           entries=entries)
