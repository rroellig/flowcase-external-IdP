import os
from flask import Flask, request, g
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt

__version__ = "develop"

db = SQLAlchemy()
migrate = Migrate()
bcrypt = Bcrypt()

# Custom user class for auto-login
class AutoLoginUser:
    def __init__(self, user):
        self.user = user
        
    def __getattr__(self, name):
        return getattr(self.user, name)
    
    @property
    def is_authenticated(self):
        return True
        
    @property
    def is_active(self):
        return True
        
    def get_groups(self):
        return self.user.get_groups()

def create_app(config=None):
    app = Flask(__name__)
    
    from config.config import configure_app
    configure_app(app, config)
    
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
    db.init_app(app)
    migrate.init_app(app, db)
    bcrypt.init_app(app)
    
    # Auto-login middleware
    @app.before_request
    def auto_login():
        from models.user import User
        
        # Get user from HTTP headers
        user = User.get_current_user()
                
        # Set current user
        g.user = AutoLoginUser(user)
    
    # Register blueprints
    from routes.auth import auth_bp
    from routes.admin import admin_bp
    from routes.droplet import droplet_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp, url_prefix='/api/admin')
    app.register_blueprint(droplet_bp)
    
    @app.errorhandler(404)
    def page_not_found(e):
        from flask import render_template
        return render_template('404.html'), 404
    
    @app.context_processor
    def inject_user():
        if hasattr(g, 'user'):
            return {'current_user': g.user}
        return {}
    
    return app