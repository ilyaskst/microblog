import unittest
from datetime import datetime, timezone, timedelta
from app import create_app, db
from app.models import User
from config import Config
from app.api.auth import basic_auth, token_auth
from flask import json


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite://'
    ELASTICSEARCH_URL = None


class AuthAPICase(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestConfig)
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

        # Create a test user
        self.user = User(username='testuser', email='test@example.com')
        self.user.set_password('testpassword')
        db.session.add(self.user)
        db.session.commit()

        # Create a client for making requests (though not strictly needed for direct auth function calls)
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    # --- Basic Authentication Tests ---

    def test_basic_auth_verify_password_success(self):
        user = basic_auth.verify_password(self.user.username, 'testpassword')
        self.assertEqual(user, self.user)

    def test_basic_auth_verify_password_fail_wrong_password(self):
        user = basic_auth.verify_password(self.user.username, 'wrongpassword')
        self.assertIsNone(user)

    def test_basic_auth_verify_password_fail_no_user(self):
        user = basic_auth.verify_password('nonexistent', 'testpassword')
        self.assertIsNone(user)

    def test_basic_auth_error_handler(self):
        # The error handler returns a Flask Response object.
        # We need to call it within the app context to get a proper response.
        with self.app.test_request_context():
            response = basic_auth.error_handler(401)
            self.assertEqual(response.status_code, 401)
            data = json.loads(response.get_data(as_text=True))
            self.assertEqual(data['error'], 'Unauthorized')
            self.assertEqual(data['message'], 'Authentication required.')

    # --- Token Authentication Tests ---

    def test_token_auth_verify_token_success(self):
        token = self.user.get_token()
        db.session.commit()  # Commit token and expiration to DB
        user = token_auth.verify_token(token)
        self.assertEqual(user, self.user)

    def test_token_auth_verify_token_fail_invalid_token(self):
        user = token_auth.verify_token('invalid_token_string')
        self.assertIsNone(user)

    def test_token_auth_verify_token_fail_expired_token(self):
        # Generate a token, then manually expire it in the DB
        token = self.user.get_token()
        self.user.token_expiration = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.session.commit()
        user = token_auth.verify_token(token)
        self.assertIsNone(user)

    def test_token_auth_verify_token_fail_none_token(self):
        user = token_auth.verify_token(None)
        self.assertIsNone(user)

    def test_token_auth_error_handler(self):
        with self.app.test_request_context():
            response = token_auth.error_handler(401)
            self.assertEqual(response.status_code, 401)
            data = json.loads(response.get_data(as_text=True))
            self.assertEqual(data['error'], 'Unauthorized')
            self.assertEqual(data['message'], 'Authentication required.')

    # --- User Model Token Methods (used by auth.py) ---
    # These are technically model tests, but directly support auth.py logic.

    def test_user_get_token_and_check_token(self):
        token = self.user.get_token()
        db.session.commit()  # Ensure token and expiration are saved
        self.assertIsNotNone(token)
        self.assertIsNotNone(self.user.token_expiration)

        # Check the token
        checked_user = User.check_token(token)
        self.assertEqual(checked_user, self.user)

        # Token should be cleared after use (or after a short period, depending on implementation)
        # The current User.check_token implementation clears the token *if* it's valid.
        # So, if we call it again, it should fail.
        checked_user_again = User.check_token(token)
        self.assertIsNone(checked_user_again)
        self.assertIsNone(self.user.token)  # Verify token is cleared from user object

    def test_user_check_token_expired(self):
        token = self.user.get_token()
        # Manually set expiration to the past
        self.user.token_expiration = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.session.commit()

        checked_user = User.check_token(token)
        self.assertIsNone(checked_user)
        # Token should also be cleared if expired
        self.assertIsNone(self.user.token)

    def test_user_check_token_invalid(self):
        # No token generated for self.user, or use a completely random string
        checked_user = User.check_token('totally_invalid_token_string')
        self.assertIsNone(checked_user)

    def test_user_check_token_no_token_in_db(self):
        # User has no token generated yet
        checked_user = User.check_token('some_token_string')
        self.assertIsNone(checked_user)

    def test_user_revoke_token(self):
        token = self.user.get_token()
        db.session.commit()
        self.assertIsNotNone(self.user.token)
        self.user.revoke_token()
        db.session.commit()
        self.assertIsNone(self.user.token)
        self.assertIsNone(self.user.token_expiration)
        # After revoking, check_token should fail
        checked_user = User.check_token(token)
        self.assertIsNone(checked_user)


if __name__ == '__main__':
    unittest.main(verbosity=2)
