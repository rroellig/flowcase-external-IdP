class Permissions:
	# Permission constants
	ADMIN_PANEL = "perm_admin_panel"
	VIEW_INSTANCES = "perm_view_instances"
	EDIT_INSTANCES = "perm_edit_instances"
	VIEW_USERS = "perm_view_users"
	EDIT_USERS = "perm_edit_users"
	VIEW_DROPLETS = "perm_view_droplets"
	EDIT_DROPLETS = "perm_edit_droplets"
	VIEW_REGISTRY = "perm_view_registry"
	EDIT_REGISTRY = "perm_edit_registry"
	VIEW_GROUPS = "perm_view_groups"
	EDIT_GROUPS = "perm_edit_groups"

	@staticmethod
	def check_permission(userid, permission):
		from flask import g
		
		# Get the user from the current request context
		user = g.user
		if not user:
			return False
			
		# Use the has_permission method from the User model
		return user.has_permission(permission)