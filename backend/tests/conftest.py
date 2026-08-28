import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

from app import create_app, db as _db
from config import Config


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    AUTO_CREATE_DB = True
    ENABLE_SCHEDULER = False
    REQUIRE_AUTH = True
    JWT_SECRET_KEY = "test-jwt-secret"
    SECRET_KEY = "test-secret"


@pytest.fixture
def app():
    application = create_app(TestConfig)
    yield application


@pytest.fixture
def db(app):
    with app.app_context():
        yield _db
        _db.session.remove()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def user(app, db):
    from app.models import User
    with app.app_context():
        u = User(email="analyst@example.com", role="analyst")
        u.set_password("password123")
        db.session.add(u)
        db.session.commit()
        return u.id


@pytest.fixture
def auth_headers(app, user):
    from app.models import User
    from app.utils.auth import encode_token
    with app.app_context():
        u = User.query.get(user)
        token = encode_token(u)
    return {"Authorization": f"Bearer {token}"}
