from flask import request, abort
from config.config import parse_args

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
	
	@staticmethod
	def get_current_user():
		"""
		Get user and groups from HTTP headers or debug arguments
		"""
		# Get command line arguments
		args = parse_args()
		
		# Check for headers first
		username = request.headers.get("X-Authentik-Username")
		groups_header = request.headers.get("X-Authentik-Groups")
		
		# Debug output
		print("X-Authentik-Username: ", username)
		print("X-Authentik-Groups: ", groups_header)
		
		# If no username in headers, check for debug arguments
		if not username and args.debug_user:
			print(f"Using debug username: {args.debug_user}")
			username = args.debug_user
			
			# Use debug groups if provided
			if args.debug_groups:
				groups_header = args.debug_groups
				print(f"Using debug groups: {groups_header}")
		
		# If still no username, abort with 401
		if not username:
			abort(401)

		# Parse groups from header or debug argument
		groups = []
		if groups_header:
			# Split by comma and strip whitespace
			groups = [group.strip() for group in groups_header.split('|')]
			
		return User(username=username, groups=groups)