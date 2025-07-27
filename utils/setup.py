import os
from __init__ import db
from models.registry import Registry
from utils.logger import log

def create_default_registry():
	"""Create default registry if none exists"""
	if Registry.query.count() == 0:
		flowcase_registry = Registry(url="https://registry.flowcase.org")
		db.session.add(flowcase_registry)
		db.session.commit()

def initialize_app(app):
	"""Initialize the application for first run"""
	with app.app_context():
		log("INFO", "Initializing Flowcase...")
		
		os.makedirs("data", exist_ok=True)
		
		# Create the firstrun file if it doesn't exist
		if not os.path.exists("data/.firstrun"):
			with open("data/.firstrun", "w") as f:
				f.write("")
			
			# Create default registry
			create_default_registry()
		
		log("INFO", "Flowcase initialized.")