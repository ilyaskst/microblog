import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

# Import app components
from app import create_app, db
from app.models import User, Post, Message, Notification, Task
from config import Config

# Standard library imports used in models or for testing
import jwt
import json
import secrets
import time

# SQLAlchemy imports for direct queries in tests
import sqlalchemy as sa
import sqlalchemy.orm as so

# RQ/Redis imports for mocking
import redis
import rq.exceptions


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite://'
    ELASTICSEARCH_URL = None
    # Provide a dummy secret key for JWT tests
    SECRET_KEY = 'test-secret-key'
    # Mock Redis for RQ tasks, though actual connection won't be made due to mocking
    REDIS_URL = 'redis://localhost:6379/0'


class ModelUnitTestCase(unittest.TestCase):
    """Base class for model unit tests, setting up and tearing down the app context and database."""
    def setUp(self):
        self.app = create_app(TestConfig)
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def create_users_and_posts(self):
        """Helper to create a set of users and posts for testing relationships."""
        u1 = User(username='john', email='john@example.com')
        u2 = User(username='susan', email='susan@example.com')
        u3 = User(username='mary', email='mary@example.com')
        u4 = User(username='david', email='david@example.com')
        db.session.add_all([u1, u2, u3, u4])

        now = datetime.now(timezone.utc)
        p1 = Post(body="post from john", author=u1,
                  timestamp=now + timedelta(seconds=1))
        p2 = Post(body="post from susan", author=u2,
                  timestamp=now + timedelta(seconds=4))
        p3 = Post(body="post from mary", author=u3,
                  timestamp=now + timedelta(seconds=3))
        p4 = Post(body="post from david", author=u4,
                  timestamp=now + timedelta(seconds=2))
        db.session.add_all([p1, p2, p3, p4])
        db.session.commit()
        return u1, u2, u3, u4, p1, p2, p3, p4


class UserModelCase(ModelUnitTestCase):
    """Tests for the User model."""

    def test_password_hashing(self):
        u = User(username='susan', email='susan@example.com')
        u.set_password('cat')
        self.assertFalse(u.check_password('dog'))
        self.assertTrue(u.check_password('cat'))

    def test_avatar(self):
        u = User(username='john', email='john@example.com')
        self.assertEqual(u.avatar(128), ('https://www.gravatar.com/avatar/'
                                         'd4c74594d841139328695756648b6bd6'
                                         '?d=identicon&s=128'))

    def test_follow(self):
        u1 = User(username='john', email='john@example.com')
        u2 = User(username='susan', email='susan@example.com')
        db.session.add(u1)
        db.session.add(u2)
        db.session.commit()
        following = db.session.scalars(u1.following.select()).all()
        followers = db.session.scalars(u2.followers.select()).all()
        self.assertEqual(following, [])
        self.assertEqual(followers, [])

        u1.follow(u2)
        db.session.commit()
        self.assertTrue(u1.is_following(u2))
        self.assertEqual(u1.following_count(), 1)
        self.assertEqual(u2.followers_count(), 1)
        u1_following = db.session.scalars(u1.following.select()).all()
        u2_followers = db.session.scalars(u2.followers.select()).all()
        self.assertEqual(u1_following[0].username, 'susan')
        self.assertEqual(u2_followers[0].username, 'john')

        u1.unfollow(u2)
        db.session.commit()
        self.assertFalse(u1.is_following(u2))
        self.assertEqual(u1.following_count(), 0)
        self.assertEqual(u2.followers_count(), 0)

    def test_follow_posts(self):
        u1, u2, u3, u4, p1, p2, p3, p4 = self.create_users_and_posts()

        # setup the followers
        u1.follow(u2)  # john follows susan
        u1.follow(u4)  # john follows david
        u2.follow(u3)  # susan follows mary
        u3.follow(u4)  # mary follows david
        db.session.commit()

        # check the following posts of each user
        f1 = db.session.scalars(u1.following_posts()).all()
        f2 = db.session.scalars(u2.following_posts()).all()
        f3 = db.session.scalars(u3.following_posts()).all()
        f4 = db.session.scalars(u4.following_posts()).all()
        self.assertEqual(f1, [p2, p4, p1])
        self.assertEqual(f2, [p2, p3])
        self.assertEqual(f3, [p3, p4])
        self.assertEqual(f4, [p4])

    def test_user_repr(self):
        u = User(username='testuser')
        self.assertEqual(repr(u), '<User testuser>')

    def test_last_seen_default(self):
        u = User(username='test', email='test@example.com')
        db.session.add(u)
        db.session.commit()
        self.assertIsNotNone(u.last_seen)
        self.assertIsInstance(u.last_seen, datetime)
        # Check if it's close to now (within a few seconds)
        self.assertLess((datetime.now(timezone.utc) - u.last_seen).total_seconds(), 5)

    def test_get_reset_password_token_and_verify(self):
        u = User(username='test', email='test@example.com')
        db.session.add(u)
        db.session.commit() # Need ID for JWT
        token = u.get_reset_password_token(expires_in=1) # Short expiry for testing
        self.assertIsNotNone(token)

        # Verify valid token
        user_from_token = User.verify_reset_password_token(token)
        self.assertEqual(user_from_token, u)

        # Verify expired token
        time.sleep(2) # Wait for token to expire
        user_from_expired_token = User.verify_reset_password_token(token)
        self.assertIsNone(user_from_expired_token)

        # Verify invalid token (wrong secret key)
        invalid_token = jwt.encode(
            {'reset_password': u.id, 'exp': time.time() + 600},
            'wrong-secret-key', algorithm='HS256')
        user_from_invalid_token = User.verify_reset_password_token(invalid_token)
        self.assertIsNone(user_from_invalid_token)

        # Verify malformed token
        malformed_token = 'not.a.real.token'
        user_from_malformed_token = User.verify_reset_password_token(malformed_token)
        self.assertIsNone(user_from_malformed_token)

        # Verify token with missing 'reset_password' claim
        token_missing_claim = jwt.encode(
            {'exp': time.time() + 600},
            self.app.config['SECRET_KEY'], algorithm='HS256')
        user_from_missing_claim = User.verify_reset_password_token(token_missing_claim)
        self.assertIsNone(user_from_missing_claim)

    def test_unread_message_count(self):
        u1 = User(username='john', email='john@example.com')
        u2 = User(username='susan', email='susan@example.com')
        db.session.add_all([u1, u2])
        db.session.commit()

        # No messages yet
        self.assertEqual(u1.unread_message_count(), 0)

        # Send a message to u1
        m1 = Message(author=u2, recipient=u1, body='hi john',
                     timestamp=datetime.now(timezone.utc) - timedelta(minutes=5))
        db.session.add(m1)
        db.session.commit()
        self.assertEqual(u1.unread_message_count(), 1)

        # u1 reads messages
        u1.last_message_read_time = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.session.commit()
        self.assertEqual(u1.unread_message_count(), 0)

        # Send another message to u1 (after last_message_read_time)
        m2 = Message(author=u2, recipient=u1, body='hi again john',
                     timestamp=datetime.now(timezone.utc))
        db.session.add(m2)
        db.session.commit()
        self.assertEqual(u1.unread_message_count(), 1)

        # Send another message to u1 (before last_message_read_time)
        m3 = Message(author=u2, recipient=u1, body='old message',
                     timestamp=datetime.now(timezone.utc) - timedelta(minutes=10))
        db.session.add(m3)
        db.session.commit()
        self.assertEqual(u1.unread_message_count(), 1) # Should still be 1, as m3 is old

    @patch('app.models.json.dumps')
    def test_add_notification(self, mock_json_dumps):
        mock_json_dumps.return_value = '{"message": "test"}'
        u = User(username='test', email='test@example.com')
        db.session.add(u)
        db.session.commit()

        # Add a notification
        n = u.add_notification('test_notification', {'message': 'test'})
        db.session.commit()

        self.assertIsNotNone(n)
        self.assertEqual(n.name, 'test_notification')
        self.assertEqual(n.user, u)
        self.assertEqual(n.payload_json, '{"message": "test"}')
        self.assertEqual(db.session.scalar(sa.select(Notification).where(Notification.user == u, Notification.name == 'test_notification')), n)

        # Add another notification with the same name, should replace the old one
        mock_json_dumps.return_value = '{"message": "updated"}'
        n2 = u.add_notification('test_notification', {'message': 'updated'})
        db.session.commit()
        self.assertEqual(db.session.scalar(sa.select(sa.func.count()).select_from(Notification)).all(), 1)
        self.assertEqual(n2.payload_json, '{"message": "updated"}')
        self.assertEqual(db.session.scalar(sa.select(Notification).where(Notification.user == u, Notification.name == 'test_notification')), n2)


    @patch('app.tasks.example_task') # Mock the actual task function if it exists, otherwise a dummy path
    @patch('rq.Queue.enqueue')
    def test_launch_task(self, mock_enqueue, mock_example_task):
        u = User(username='test', email='test@example.com')
        db.session.add(u)
        db.session.commit()

        mock_job = MagicMock()
        mock_job.get_id.return_value = 'test-job-id-123'
        mock_enqueue.return_value = mock_job

        # Mock current_app.task_queue
        with patch('flask.current_app') as mock_current_app:
            mock_current_app.task_queue = MagicMock()
            mock_current_app.task_queue.enqueue.return_value = mock_job
            mock_current_app.config = {'SECRET_KEY': 'test-secret-key'} # For JWT, not directly used here but good practice

            task = u.launch_task('example_task', 'Example task description', 1, 2, kwarg='value')
            db.session.commit()

            self.assertIsNotNone(task)
            self.assertEqual(task.id, 'test-job-id-123')
            self.assertEqual(task.name, 'example_task')
            self.assertEqual(task.description, 'Example task description')
            self.assertEqual(task.user, u)
            self.assertFalse(task.complete)

            mock_current_app.task_queue.enqueue.assert_called_once_with(
                'app.tasks.example_task', u.id, 1, 2, kwarg='value'
            )
            self.assertEqual(db.session.scalar(sa.select(Task).where(Task.id == 'test-job-id-123')), task)

    @patch('app.tasks.example_task')
    @patch('rq.Queue.enqueue')
    def test_get_tasks_in_progress(self, mock_enqueue, mock_example_task):
        u = User(username='test', email='test@example.com')
        db.session.add(u)
        db.session.commit()

        mock_job1 = MagicMock()
        mock_job1.get_id.return_value = 'task-id-1'
        mock_job2 = MagicMock()
        mock_job2.get_id.return_value = 'task-id-2'
        mock_job3 = MagicMock()
        mock_job3.get_id.return_value = 'task-id-3'

        with patch('flask.current_app') as mock_current_app:
            mock_current_app.task_queue = MagicMock()
            mock_current_app.task_queue.enqueue.side_effect = [mock_job1, mock_job2, mock_job3]
            mock_current_app.config = {'SECRET_KEY': 'test-secret-key'}

            task1 = u.launch_task('task_a', 'Description A')
            task2 = u.launch_task('task_b', 'Description B')
            task3 = u.launch_task('task_c', 'Description C')
            db.session.commit()

            task1.complete = True
            db.session.commit()

            in_progress_tasks = db.session.scalars(u.get_tasks_in_progress()).all()
            self.assertEqual(len(in_progress_tasks), 2)
            self.assertIn(task2, in_progress_tasks)
            self.assertIn(task3, in_progress_tasks)
            self.assertNotIn(task1, in_progress_tasks)

    @patch('app.tasks.example_task')
    @patch('rq.Queue.enqueue')
    def test_get_task_in_progress(self, mock_enqueue, mock_example_task):
        u = User(username='test', email='test@example.com')
        db.session.add(u)
        db.session.commit()

        mock_job1 = MagicMock()
        mock_job1.get_id.return_value = 'task-id-1'
        mock_job2 = MagicMock()
        mock_job2.get_id.return_value = 'task-id-2'

        with patch('flask.current_app') as mock_current_app:
            mock_current_app.task_queue = MagicMock()
            mock_current_app.task_queue.enqueue.side_effect = [mock_job1, mock_job2]
            mock_current_app.config = {'SECRET_KEY': 'test-secret-key'}

            task1 = u.launch_task('task_a', 'Description A')
            task2 = u.launch_task('task_b', 'Description B')
            db.session.commit()

            found_task_a = u.get_task_in_progress('task_a')
            self.assertEqual(found_task_a, task1)

            task1.complete = True
            db.session.commit()

            found_task_a_completed = u.get_task_in_progress('task_a')
            self.assertIsNone(found_task_a_completed)

            found_task_b = u.get_task_in_progress('task_b')
            self.assertEqual(found_task_b, task2)

            not_found_task = u.get_task_in_progress('non_existent_task')
            self.assertIsNone(not_found_task)

    def test_posts_count(self):
        u = User(username='test', email='test@example.com')
        db.session.add(u)
        db.session.commit()

        self.assertEqual(u.posts_count(), 0)

        p1 = Post(body="test post 1", author=u)
        p2 = Post(body="test post 2", author=u)
        db.session.add_all([p1, p2])
        db.session.commit()

        self.assertEqual(u.posts_count(), 2)

    @patch('app.models.url_for')
    def test_to_dict(self, mock_url_for):
        # Mock url_for to return predictable strings
        mock_url_for.side_effect = lambda endpoint, id=None, page=None, per_page=None: f'/{endpoint}/{id}' if id else f'/{endpoint}'

        u = User(id=1, username='testuser', email='test@example.com', about_me='Hello',
                 last_seen=datetime(2023, 1, 1, 10, 0, 0, tzinfo=timezone.utc))
        db.session.add(u)
        db.session.commit()

        # Add a post to test post_count
        p = Post(body="test post", author=u)
        db.session.add(p)
        db.session.commit()

        # Add a follower to test follower_count
        follower = User(username='follower', email='follower@example.com')
        db.session.add(follower)
        db.session.commit()
        follower.follow(u)
        db.session.commit()

        # Add a following to test following_count
        followed = User(username='followed', email='followed@example.com')
        db.session.add(followed)
        db.session.commit()
        u.follow(followed)
        db.session.commit()

        data = u.to_dict()
        self.assertEqual(data['id'], 1)
        self.assertEqual(data['username'], 'testuser')
        self.assertEqual(data['last_seen'], '2023-01-01T10:00:00+00:00')
        self.assertEqual(data['about_me'], 'Hello')
        self.assertEqual(data['post_count'], 1)
        self.assertEqual(data['follower_count'], 1)
        self.assertEqual(data['following_count'], 1)
        self.assertNotIn('email', data)
        self.assertIn('_links', data)
        self.assertEqual(data['_links']['self'], '/api.get_user/1')
        self.assertEqual(data['_links']['followers'], '/api.get_followers/1')
        self.assertEqual(data['_links']['following'], '/api.get_following/1')
        self.assertIn('gravatar.com', data['_links']['avatar'])

        data_with_email = u.to_dict(include_email=True)
        self.assertEqual(data_with_email['email'], 'test@example.com')

    def test_from_dict(self):
        u = User(username='oldname', email='old@example.com', about_me='Old about')
        db.session.add(u)
        db.session.commit()

        data = {'username': 'newname', 'email': 'new@example.com', 'about_me': 'New about'}
        u.from_dict(data)
        self.assertEqual(u.username, 'newname')
        self.assertEqual(u.email, 'new@example.com')
        self.assertEqual(u.about_me, 'New about')

        # Test new user with password
        new_u = User()
        new_user_data = {'username': 'brandnew', 'email': 'brandnew@example.com', 'password': 'testpassword'}
        new_u.from_dict(new_user_data, new_user=True)
        self.assertEqual(new_u.username, 'brandnew')
        self.assertEqual(new_u.email, 'brandnew@example.com')
        self.assertTrue(new_u.check_password('testpassword'))
        self.assertIsNotNone(new_u.password_hash)

        # Test existing user with password (should not set password if new_user=False)
        u.from_dict({'password': 'newpassword'})
        self.assertFalse(u.check_password('newpassword')) # Password should not change if not new_user

    @patch('app.models.secrets.token_hex')
    def test_get_token_and_check_token(self, mock_token_hex):
        mock_token_hex.return_value = 'testtoken123'
        u = User(username='test', email='test@example.com')
        db.session.add(u)
        db.session.commit()

        # Get token for the first time
        token = u.get_token(expires_in=1) # Short expiry
        self.assertEqual(token, 'testtoken123')
        self.assertEqual(u.token, 'testtoken123')
        self.assertIsNotNone(u.token_expiration)
        db.session.commit() # Persist token and expiration

        # Check valid token
        checked_user = User.check_token('testtoken123')
        self.assertEqual(checked_user, u)

        # Get token again before expiry, should return same token
        mock_token_hex.return_value = 'newtoken456' # Should not be called
        token2 = u.get_token(expires_in=1)
        self.assertEqual(token2, 'testtoken123')
        self.assertEqual(u.token, 'testtoken123') # Token should not have changed

        # Wait for token to expire
        time.sleep(2)
        db.session.refresh(u) # Refresh user object to get updated token_expiration

        # Check expired token
        checked_user_expired = User.check_token('testtoken123')
        self.assertIsNone(checked_user_expired)

        # Get token after expiry, should generate new one
        mock_token_hex.return_value = 'newtoken456'
        token3 = u.get_token(expires_in=1)
        self.assertEqual(token3, 'newtoken456')
        self.assertEqual(u.token, 'newtoken456')
        self.assertIsNotNone(u.token_expiration)
        db.session.commit()

        # Check invalid token
        checked_user_invalid = User.check_token('wrongtoken')
        self.assertIsNone(checked_user_invalid)

        # Check token for non-existent user
        self.assertIsNone(User.check_token('nonexistenttoken'))

    def test_revoke_token(self):
        u = User(username='test', email='test@example.com')
        db.session.add(u)
        db.session.commit()

        token = u.get_token(expires_in=3600)
        db.session.commit()
        self.assertIsNotNone(User.check_token(token))

        u.revoke_token()
        db.session.commit()
        self.assertIsNone(User.check_token(token))


class PostModelCase(ModelUnitTestCase):
    """Tests for the Post model."""

    def test_post_repr(self):
        u = User(username='testuser')
        db.session.add(u)
        db.session.commit()
        p = Post(body='My first post!', author=u)
        self.assertEqual(repr(p), '<Post My first post!>')

    def test_post_timestamp_default(self):
        u = User(username='testuser')
        db.session.add(u)
        db.session.commit()
        p = Post(body='test', author=u)
        db.session.add(p)
        db.session.commit()
        self.assertIsNotNone(p.timestamp)
        self.assertIsInstance(p.timestamp, datetime)
        self.assertLess((datetime.now(timezone.utc) - p.timestamp).total_seconds(), 5)


class MessageModelCase(ModelUnitTestCase):
    """Tests for the Message model."""

    def test_message_repr(self):
        u1 = User(username='sender')
        u2 = User(username='recipient')
        db.session.add_all([u1, u2])
        db.session.commit()
        m = Message(author=u1, recipient=u2, body='Hello!')
        self.assertEqual(repr(m), '<Message Hello!>')

    def test_message_timestamp_default(self):
        u1 = User(username='sender')
        u2 = User(username='recipient')
        db.session.add_all([u1, u2])
        db.session.commit()
        m = Message(author=u1, recipient=u2, body='Hello!')
        db.session.add(m)
        db.session.commit()
        self.assertIsNotNone(m.timestamp)
        self.assertIsInstance(m.timestamp, datetime)
        self.assertLess((datetime.now(timezone.utc) - m.timestamp).total_seconds(), 5)


class NotificationModelCase(ModelUnitTestCase):
    """Tests for the Notification model."""

    def test_get_data(self):
        u = User(username='testuser')
        db.session.add(u)
        db.session.commit()
        data_payload = {'key': 'value', 'number': 123}
        n = Notification(name='test_notif', user=u, payload_json=json.dumps(data_payload))
        db.session.add(n)
        db.session.commit()

        retrieved_data = n.get_data()
        self.assertEqual(retrieved_data, data_payload)
        self.assertIsInstance(retrieved_data, dict)

        # Test with empty JSON
        n_empty = Notification(name='empty_notif', user=u, payload_json='{}')
        db.session.add(n_empty)
        db.session.commit()
        self.assertEqual(n_empty.get_data(), {})

        # Test with invalid JSON (should raise an error, but model expects valid)
        n_invalid = Notification(name='invalid_notif', user=u, payload_json='not json')
        db.session.add(n_invalid)
        db.session.commit()
        with self.assertRaises(json.JSONDecodeError):
            n_invalid.get_data()


    def test_notification_timestamp_default(self):
        u = User(username='testuser')
        db.session.add(u)
        db.session.commit()
        n = Notification(name='test_notif', user=u, payload_json='{}')
        db.session.add(n)
        db.session.commit()
        self.assertIsNotNone(n.timestamp)
        self.assertIsInstance(n.timestamp, float)
        self.assertLess(time.time() - n.timestamp, 5)


class TaskModelCase(ModelUnitTestCase):
    """Tests for the Task model."""

    @patch('rq.job.Job.fetch')
    def test_get_rq_job(self, mock_job_fetch):
        u = User(username='testuser')
        db.session.add(u)
        db.session.commit()

        task_id = 'test-task-id-1'
        task = Task(id=task_id, name='test_task', user=u)
        db.session.add(task)
        db.session.commit()

        # Test successful fetch
        mock_rq_job = MagicMock()
        mock_job_fetch.return_value = mock_rq_job
        with patch('flask.current_app') as mock_current_app:
            mock_current_app.redis = MagicMock() # Mock redis connection
            retrieved_job = task.get_rq_job()
            self.assertEqual(retrieved_job, mock_rq_job)
            mock_job_fetch.assert_called_once_with(task_id, connection=mock_current_app.redis)

        # Test job not found
        mock_job_fetch.reset_mock()
        mock_job_fetch.side_effect = rq.exceptions.NoSuchJobError
        with patch('flask.current_app') as mock_current_app:
            mock_current_app.redis = MagicMock()
            retrieved_job_none = task.get_rq_job()
            self.assertIsNone(retrieved_job_none)

        # Test Redis error
        mock_job_fetch.reset_mock()
        mock_job_fetch.side_effect = redis.exceptions.RedisError
        with patch('flask.current_app') as mock_current_app:
            mock_current_app.redis = MagicMock()
            retrieved_job_error = task.get_rq_job()
            self.assertIsNone(retrieved_job_error)

    @patch('rq.job.Job.fetch')
    def test_get_progress(self, mock_job_fetch):
        u = User(username='testuser')
        db.session.add(u)
        db.session.commit()

        task_id = 'test-task-id-2'
        task = Task(id=task_id, name='test_task', user=u)
        db.session.add(task)
        db.session.commit()

        # Test job exists and has progress
        mock_rq_job = MagicMock()
        mock_rq_job.meta = {'progress': 50}
        mock_job_fetch.return_value = mock_rq_job
        with patch('flask.current_app') as mock_current_app:
            mock_current_app.redis = MagicMock()
            progress = task.get_progress()
            self.assertEqual(progress, 50)

        # Test job exists but no progress meta
        mock_rq_job.meta = {}
        mock_job_fetch.return_value = mock_rq_job
        with patch('flask.current_app') as mock_current_app:
            mock_current_app.redis = MagicMock()
            progress = task.get_progress()
            self.assertEqual(progress, 0) # Default to 0 if not found

        # Test job does not exist
        mock_job_fetch.side_effect = rq.exceptions.NoSuchJobError
        with patch('flask.current_app') as mock_current_app:
            mock_current_app.redis = MagicMock()
            progress = task.get_progress()
            self.assertEqual(progress, 100) # Returns 100 if job is not found (implies complete or failed)

    def test_task_repr(self):
        u = User(username='testuser')
        db.session.add(u)
        db.session.commit()
        task = Task(id='some-id', name='my_task', description='A task', user=u)
        # Task model doesn't have a __repr__ defined, so it will use the default object repr.
        # This test is more to ensure it doesn't crash and to document the default behavior.
        self.assertIn('Task object at', repr(task)) # Default repr includes object address
