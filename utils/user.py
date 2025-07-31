import os
from flask import request, abort

class User():
	"""
	User class that gets all information from HTTP headers
	No database storage is used for users
	"""
	def __init__(self, username, groups):
		self.id = username  # Use username as ID
		self.username = username
		self.groups = groups if groups else []
	
	def has_permission(self, permission):
		# Admin can do everything
		if 'admin' in self.groups:
			return True
		
		# Non-admins can only view droplets and instances
		if permission in ["perm_view_droplets", "perm_view_instances"]:
			return True
			
		return False
	
	def get_groups(self):
		"""
		Return a list of groups for compatibility with templates
		"""
		return self.groups
	
	def is_admin(self):
		"""
		Check if user is in group admin
		"""
		if 'admin' in self.groups:
			return True
	
	@staticmethod
	def get_current_user():
		"""
		Get user and groups from HTTP headers or environment variables
		"""
		
		# Check for headers first
		username = request.headers.get("X-Authentik-Username")
		groups_header = request.headers.get("X-Authentik-Groups")
		
		# Debug output
		# print("X-Authentik-Username: ", username)
		# print("X-Authentik-Groups: ", groups_header)
		
		# If no username in headers, check for debug arguments from command line or environment variables
		if not username:
			os.environ.get('FLOWCASE_DEBUG_USER')
			print(f"Using debug username from environment: {os.environ.get('FLOWCASE_DEBUG_USER')}")
			username = os.environ.get('FLOWCASE_DEBUG_USER')
			
			# Use debug groups if provided
			if os.environ.get('FLOWCASE_DEBUG_GROUPS'):
				groups_header = os.environ.get('FLOWCASE_DEBUG_GROUPS')
				print(f"Using debug groups from environment: {groups_header}")
		
		# If still no username, abort with 401
		if not username:
			abort(401)

		# Parse groups from header or debug argument
		groups = []
		if groups_header:
			# Split by comma and strip whitespace
			groups = [group.strip() for group in groups_header.split('|')]
			
		return User(username=username, groups=groups)