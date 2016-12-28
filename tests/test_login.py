import unittest

from flask_login import current_user

from app import app, db
from app.user import random_string, hash_password
from app.model.user import User
from app.model.enum import UserRole

USERNAME = 'cyberwehr12345678'

class LoginTestCase(unittest.TestCase):

    def setUp(self):
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
        self.client = app.test_client()
        with app.app_context():
            db.create_all()
            self.create_user()

    def tearDown(self):
        db.drop_all()

    def create_user(self):
        user = User()
        user.active = True
        user.name = USERNAME
        user.password = USERNAME
        user.role = UserRole.reporter
        user.email = USERNAME + '@cyber.cyber'
        user.salt = random_string()
        user.password = hash_password(user.password, user.salt)

        db.session.add(user)
        db.session.commit()

    def test_login(self):
        resp = self.client.post(
          '/login',
          data = dict(username=USERNAME, password=USERNAME),
          follow_redirects=True,
        )
        self.assertTrue(b'Issues' in resp.data)

    def test_login_invalid(self):
        resp = self.client.post('/login', data={'username': USERNAME, 'password': 'nein'})
        self.assertTrue(b'Login' in resp.data)
