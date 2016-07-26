from flask import render_template, flash, redirect
from app import app


@app.route('/advisory')
def advisory():
    entries = [
        {
            'advisory': 'ASA-201512-13',
            'package': 'claws-mail',
            'date': '25 December 2015',
            'type': 'arbitrary code execution'
        },
        {
            'advisory': 'ASA-201512-13',
            'package': 'claws-mail',
            'date': '25 December 2015',
            'type': 'arbitrary code execution'
        }
    ]
    return render_template('advisory.html',
                           title='Advisory',
                           entries=entries)
