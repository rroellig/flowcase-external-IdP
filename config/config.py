import os
import argparse
import random
import string

def parse_args():
	parser = argparse.ArgumentParser()
	parser.add_argument('--port', type=int, default=5000)
	parser.add_argument('--debug', action='store_true')
	parser.add_argument('--debug-user', type=str, help='Username to use when running locally without Authentik')
	parser.add_argument('--debug-groups', type=str, help='Comma-separated list of groups to use when running locally without Authentik (e.g. "admin,users")')
	
	return parser.parse_known_args()[0]

def configure_app(app, config=None):
	app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.getcwd(), 'data', 'flowcase.db')
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