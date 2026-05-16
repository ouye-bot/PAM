import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ['FLASK_ENV'] = 'development'

# Import app module
import importlib.util
spec = importlib.util.spec_from_file_location('pam_app', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'app.py'))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
flask_app = mod.app

from app import db
from app.models.user import User

with flask_app.app_context():
    user = User.query.filter_by(username='admin').first()
    if user:
        user.totp_enabled = False
        db.session.commit()
        print('TOTP已临时关闭')
    else:
        print('admin user not found')