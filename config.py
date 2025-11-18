import os

# Get the base directory of the application
basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    # --- Core Application Configuration ---

    # SECRET_KEY: Essential for security (e.g., session management, CSRF protection).
    # This MUST be set in the environment for production deployments.
    SECRET_KEY = os.getenv('SECRET_KEY')
    if not SECRET_KEY:
        raise EnvironmentError("SECRET_KEY environment variable is not set. This is critical for application security.")

    # SERVER_NAME: Used for URL generation. Can be None for development.
    SERVER_NAME = os.getenv('SERVER_NAME')

    # LOG_TO_STDOUT: Controls logging behavior.
    LOG_TO_STDOUT = os.getenv('LOG_TO_STDOUT')

    # POSTS_PER_PAGE: Pagination setting.
    POSTS_PER_PAGE = 25

    # LANGUAGES: Supported languages for the application.
    LANGUAGES = ['en', 'es']

    # ADMINS: List of email addresses for application administrators.
    ADMINS = ['your-email@example.com']

    # --- Database Configuration ---

    # SQLALCHEMY_DATABASE_URI: Database connection string.
    # Provides a SQLite default for development. For production, DATABASE_URL should be set.
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', '').replace(
        'postgres://', 'postgresql://') or \
        'sqlite:///' + os.path.join(basedir, 'app.db')

    # --- Email Configuration ---

    MAIL_SERVER = os.getenv('MAIL_SERVER')
    MAIL_PORT = int(os.getenv('MAIL_PORT') or 25)
    MAIL_USE_TLS = os.getenv('MAIL_USE_TLS') is not None  # Checks if MAIL_USE_TLS is set to any value (e.g., '1', 'True')
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')

    # If a mail server is configured, then credentials should also be provided.
    if MAIL_SERVER:
        if not MAIL_USERNAME:
            raise EnvironmentError("MAIL_USERNAME environment variable is not set, but MAIL_SERVER is configured. Email sending will fail.")
        if not MAIL_PASSWORD:
            raise EnvironmentError("MAIL_PASSWORD environment variable is not set, but MAIL_SERVER is configured. Email sending will fail.")

    # --- Third-Party Service Integrations ---

    # MS_TRANSLATOR_KEY: Microsoft Translator API key.
    # If not set, translation features will be disabled or non-functional.
    MS_TRANSLATOR_KEY = os.getenv('MS_TRANSLATOR_KEY')

    # ELASTICSEARCH_URL: Elasticsearch connection string.
    # If not set, search features will be disabled or non-functional.
    ELASTICSEARCH_URL = os.getenv('ELASTICSEARCH_URL')

    # REDIS_URL: Redis connection string.
    # Used for background tasks, caching, etc. Provides a local default for development.
    REDIS_URL = os.getenv('REDIS_URL') or 'redis://localhost:6379/0'
