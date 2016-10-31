#!/usr/bin/env python
from app import app
from config import FLASK_HOST, FLASK_PORT, FLASK_DEBUG

if __name__ == '__main__':
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG)
