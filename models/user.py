from flask_login import UserMixin
from flask import request, g

class User(UserMixin):
	"""
	User class that gets all information from HTTP headers
	No database storage is used for users
	"""
	def __init__(self, username, is_admin=False):
		self.id = username  # Use username as ID
		self.username = username
		self.is_admin = is_admin
	
	def has_permission(self, permission):
		# Admin can do everything
		if self.is_admin:
			return True
		
		# Non-admins can only view droplets and instances
		if permission in ["perm_view_droplets", "perm_view_instances"]:
			return True
			
		return False
	
	def get_groups(self):
		"""
		Return a list of groups for compatibility with templates
		In the simplified model, we just return 'admin' or 'user' based on is_admin
		"""
		if self.is_admin:
			return ['admin']
		else:
			return ['user']
	
	@staticmethod
	def get_current_user():
		"""Get user from HTTP headers"""
		username = request.headers.get("X-authentik-username")
		
		# Default to admin if no header is present
		if not username:
			username = "admin"
		
		# Check if user is admin from header
		is_admin = request.headers.get("X-authentik-is-admin", "false").lower() == "true"
		# Default admin user is always admin
		if username == "admin":
			is_admin = True
			
		return User(username=username, is_admin=is_admin)