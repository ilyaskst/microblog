import unittest
import json
from app import create_app, db
from app.models import User, Post
from config import Config
import sqlalchemy as sa


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite://'
    ELASTICSEARCH_URL = None


class UserAPICase(unittest.TestCase):
    def setUp(self):
        self.app = create_app(TestConfig)
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def _get_token(self, username, password):
        response = self.client.post(
            '/api/tokens',
            json={'username': username, 'password': password}
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn('token', data)
        return data['token']

    def _create_user(self, username, email, password, commit=True):
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        if commit:
            db.session.commit()
        return user

    def test_create_user(self):
        # Test successful user creation
        response = self.client.post(
            '/api/users',
            json={'username': 'john', 'email': 'john@example.com', 'password': 'cat'}
        )
        self.assertEqual(response.status_code, 201)
        data = response.get_json()
        self.assertEqual(data['username'], 'john')
        self.assertEqual(data['email'], 'john@example.com')
        self.assertIn('Location', response.headers)
        user = db.session.scalar(sa.select(User).where(User.username == 'john'))
        self.assertIsNotNone(user)

        # Test missing fields
        response = self.client.post(
            '/api/users',
            json={'username': 'susan', 'email': 'susan@example.com'}
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn('must include username, email and password fields', response.get_json()['message'])

        # Test duplicate username
        response = self.client.post(
            '/api/users',
            json={'username': 'john', 'email': 'john2@example.com', 'password': 'dog'}
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn('please use a different username', response.get_json()['message'])

        # Test duplicate email
        response = self.client.post(
            '/api/users',
            json={'username': 'susan', 'email': 'john@example.com', 'password': 'dog'}
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn('please use a different email address', response.get_json()['message'])

    def test_get_user(self):
        u1 = self._create_user('john', 'john@example.com', 'cat')
        token = self._get_token('john', 'cat')

        # Test successful get user
        response = self.client.get(
            f'/api/users/{u1.id}',
            headers={'Authorization': f'Bearer {token}'}
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['username'], 'john')
        self.assertEqual(data['email'], 'john@example.com')

        # Test get non-existent user
        response = self.client.get(
            '/api/users/999',
            headers={'Authorization': f'Bearer {token}'}
        )
        self.assertEqual(response.status_code, 404)

        # Test unauthorized access
        response = self.client.get(f'/api/users/{u1.id}')
        self.assertEqual(response.status_code, 401)

    def test_get_users(self):
        u1 = self._create_user('john', 'john@example.com', 'cat')
        u2 = self._create_user('susan', 'susan@example.com', 'dog')
        u3 = self._create_user('mary', 'mary@example.com', 'fish')
        token = self._get_token('john', 'cat')

        # Test successful get users (default pagination)
        response = self.client.get(
            '/api/users',
            headers={'Authorization': f'Bearer {token}'}
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['count'], 3)
        self.assertEqual(len(data['items']), 3)
        self.assertIn('john', [u['username'] for u in data['items']])

        # Test pagination with per_page
        response = self.client.get(
            '/api/users?page=1&per_page=2',
            headers={'Authorization': f'Bearer {token}'}
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['count'], 3)
        self.assertEqual(len(data['items']), 2)
        self.assertIn('next', data['_links'])

        # Test unauthorized access
        response = self.client.get('/api/users')
        self.assertEqual(response.status_code, 401)

    def test_update_user(self):
        u1 = self._create_user('john', 'john@example.com', 'cat')
        u2 = self._create_user('susan', 'susan@example.com', 'dog')
        token_u1 = self._get_token('john', 'cat')
        token_u2 = self._get_token('susan', 'dog')

        # Test successful update of own user
        response = self.client.put(
            f'/api/users/{u1.id}',
            headers={'Authorization': f'Bearer {token_u1}'},
            json={'username': 'john_new', 'email': 'john_new@example.com'}
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['username'], 'john_new')
        self.assertEqual(data['email'], 'john_new@example.com')
        updated_user = db.session.scalar(sa.select(User).where(User.id == u1.id))
        self.assertEqual(updated_user.username, 'john_new')

        # Test update another user (forbidden)
        response = self.client.put(
            f'/api/users/{u2.id}',
            headers={'Authorization': f'Bearer {token_u1}'},
            json={'username': 'susan_new'}
        )
        self.assertEqual(response.status_code, 403)

        # Test update non-existent user
        response = self.client.put(
            '/api/users/999',
            headers={'Authorization': f'Bearer {token_u1}'},
            json={'username': 'non_existent'}
        )
        self.assertEqual(response.status_code, 404)

        # Test duplicate username during update
        response = self.client.put(
            f'/api/users/{u1.id}',
            headers={'Authorization': f'Bearer {token_u1}'},
            json={'username': 'susan'}
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn('please use a different username', response.get_json()['message'])

        # Test duplicate email during update
        response = self.client.put(
            f'/api/users/{u1.id}',
            headers={'Authorization': f'Bearer {token_u1}'},
            json={'email': 'susan@example.com'}
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn('please use a different email address', response.get_json()['message'])

        # Test unauthorized access
        response = self.client.put(f'/api/users/{u1.id}', json={'username': 'anon'})
        self.assertEqual(response.status_code, 401)

    def test_get_followers_and_following(self):
        u1 = self._create_user('john', 'john@example.com', 'cat')
        u2 = self._create_user('susan', 'susan@example.com', 'dog')
        u3 = self._create_user('mary', 'mary@example.com', 'fish')
        token = self._get_token('john', 'cat')

        u1.follow(u2)
        u1.follow(u3)
        u2.follow(u3)
        db.session.commit()

        # Test get following for u1
        response = self.client.get(
            f'/api/users/{u1.id}/following',
            headers={'Authorization': f'Bearer {token}'}
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['count'], 2)
        self.assertEqual(len(data['items']), 2)
        self.assertIn('susan', [u['username'] for u in data['items']])
        self.assertIn('mary', [u['username'] for u in data['items']])

        # Test get followers for u3
        response = self.client.get(
            f'/api/users/{u3.id}/followers',
            headers={'Authorization': f'Bearer {token}'}
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['count'], 2)
        self.assertEqual(len(data['items']), 2)
        self.assertIn('john', [u['username'] for u in data['items']])
        self.assertIn('susan', [u['username'] for u in data['items']])

        # Test get following for non-existent user
        response = self.client.get(
            '/api/users/999/following',
            headers={'Authorization': f'Bearer {token}'}
        )
        self.assertEqual(response.status_code, 404)

        # Test get followers for non-existent user
        response = self.client.get(
            '/api/users/999/followers',
            headers={'Authorization': f'Bearer {token}'}
        )
        self.assertEqual(response.status_code, 404)

        # Test unauthorized access to following
        response = self.client.get(f'/api/users/{u1.id}/following')
        self.assertEqual(response.status_code, 401)

        # Test unauthorized access to followers
        response = self.client.get(f'/api/users/{u1.id}/followers')
        self.assertEqual(response.status_code, 401)


if __name__ == '__main__':
    unittest.main(verbosity=2)
