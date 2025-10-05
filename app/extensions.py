from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_mail import Mail
from flask_bootstrap import Bootstrap
from flask_moment import Moment
from flask_babel import Babel
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


db = SQLAlchemy()
migrate = Migrate()
login = LoginManager()
mail = Mail()
bootstrap = Bootstrap()
moment = Moment()
babel = Babel()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])


login.login_view = 'auth.login'
login.login_message = 'Please log in to access this page.'


@babel.localeselector
def get_locale():
    # You can add logic here to determine the user's preferred locale
    # For example, from request.accept_languages or user settings
    # For now, we'll return a default or a hardcoded value
    # from flask import request
    # return request.accept_languages.best_match(['en', 'es', 'fr'])
    return 'en'
