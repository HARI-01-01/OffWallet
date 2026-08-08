from src.main import app


def test_app_imports_successfully():
    assert app is not None
