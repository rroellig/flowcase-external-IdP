import os
import argparse
import random
import string
from sqlalchemy.dialects import registry

# Register our custom SQLite dialect with WAL mode
registry.register("sqlite.pysqlite_wal", "utils.sqlite_wal", "SQLiteDialect_pysqlite_wal")

def parse_args():
	parser = argparse.ArgumentParser()
	parser.add_argument('--port', type=int, default=5000)
	parser.add_argument('--debug', action='store_true')
	parser.add_argument('--debug-user', type=str, help='Username to use when running locally without Authentik')
	parser.add_argument('--debug-groups', type=str, help='Comma-separated list of groups to use when running locally without Authentik (e.g. "admin,users")')
	
	return parser.parse_known_args()[0]

def configure_app(app, config=None):
	# Configure SQLite with WAL journal mode and connection pooling to avoid locking issues with Gunicorn
	sqlite_path = os.path.join(os.getcwd(), 'data', 'flowcase.db')
	app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite+pysqlite_wal:///{sqlite_path}'
	
	# Configure SQLAlchemy engine options for better concurrency with SQLite
	app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
		'connect_args': {
			'timeout': 60,  # 60 second timeout
			'check_same_thread': False,  # Allow threads to share the connection
		},
		'pool_size': 10,  # Maximum number of connections to keep
		'max_overflow': 20,  # Maximum number of connections that can be created beyond pool_size
		'pool_timeout': 30,  # Seconds to wait before giving up on getting a connection from the pool
		'pool_recycle': 1800,  # Recycle connections after 30 minutes
	}
	app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
	
	os.makedirs("data", exist_ok=True)
	
	# Load secret key
	if not os.path.exists("data/secret_key"):
		with open("data/secret_key", "w") as f:
			f.write(''.join(random.choice(string.ascii_letters + string.digits) for i in range(64)))
	
	with open("data/secret_key", "r") as f:
		app.secret_key = f.read()
	
	if config:
		app.config.update(config)
		
	return app 