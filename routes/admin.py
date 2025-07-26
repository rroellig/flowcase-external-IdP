import platform
import sys
import os
import subprocess
from flask import Blueprint, jsonify, request, g
from __init__ import db, __version__, __commit__
from models.user import User
from models.droplet import Droplet, DropletInstance
from models.registry import Registry
from models.log import Log
import utils.docker

admin_bp = Blueprint('admin', __name__)

def get_git_commit():
	"""Get the current git commit hash"""
	# First try to use the commit hash from __init__.py which is set during Docker build
	if __commit__ != "Unknown":
		return __commit__[:7] if len(__commit__) >= 7 else __commit__
	
	# If that fails, try to get it directly using Git commands
	try:
		commit_hash = subprocess.check_output(['git', 'rev-parse', 'HEAD'], stderr=subprocess.STDOUT).decode('utf-8').strip()
		return commit_hash[:7]  # Return short hash (first 7 characters)
	except (subprocess.CalledProcessError, FileNotFoundError):
		return "Unknown"

@admin_bp.route('/system_info', methods=['GET'])
def api_admin_system():

	#Get Nginx version
	nginx_version = None
	try:
		#get docker container
		nginx_container = utils.docker.docker_client.containers.get("flowcase-nginx")
		result = nginx_container.exec_run("nginx -v")
		nginx_version = result.output.decode('utf-8').split("\n")[0].replace("nginx version: nginx/", "")
	except:
		nginx_version = "Unable to get version"

	response = {
		"success": True,
		"system": {
			"hostname": os.popen("hostname").read().strip(),
			"os": f"{platform.system()} {platform.release()}"
		},
		"version": {
			"flowcase": __version__,
			"python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
			"docker": utils.docker.get_docker_version(),
			"nginx": nginx_version,
			"commit": get_git_commit(),
		},
	}
 
	return jsonify(response)

@admin_bp.route('/users', methods=['GET'])
def api_admin_users():
	
	# Only return the current user since users are not stored in the database
	response = {
		"success": True,
		"users": [{
			"id": g.user.id,
			"username": g.user.username,
			"is_admin": g.user.is_admin
		}],
		"note": "Users are managed via IdP and retrieved from HTTP headers"
	}
 
	return jsonify(response)

@admin_bp.route('/instances', methods=['GET'])
def api_admin_instances():

	if not utils.docker.is_docker_available():
		return jsonify({
			"success": False, 
			"error": "Docker service is not available, can't retrieve instances"
		}), 503

	instances = DropletInstance.query.all()
 
	response = {
		"success": True,
		"instances": []
	}
 
	for instance in instances:
		try:
			droplet = Droplet.query.filter_by(id=instance.droplet_id).first()
			user = User(username=instance.username)  # Create User object from username
			container = utils.docker.docker_client.containers.get(f"flowcase_generated_{instance.id}")
			response["instances"].append({
				"id": instance.id,
				"created_at": instance.created_at,
				"updated_at": instance.updated_at,
				"ip": container.attrs['NetworkSettings']['Networks']['flowcase_default_network']['IPAddress'],
				"droplet": {
					"id": droplet.id,
					"display_name": droplet.display_name,
					"description": droplet.description,
					"container_docker_image": droplet.container_docker_image,
					"container_docker_registry": droplet.container_docker_registry,
					"container_cores": droplet.container_cores,
					"container_memory": droplet.container_memory,
					"image_path": droplet.image_path
				},
				"user": {
					"id": user.id,
					"username": user.username
				}
			})
		except Exception as e:
			# Skip this instance if we can't get container info
			continue
 
	return jsonify(response)

@admin_bp.route('/droplets', methods=['GET'])
def api_admin_droplets():

	droplets = Droplet.query.all()
	droplets = sorted(droplets, key=lambda x: x.display_name)
 
	response = {
		"success": True,
		"droplets": []
	}
 
	for droplet in droplets:
		response["droplets"].append({
			"id": droplet.id,
			"display_name": droplet.display_name,
			"description": droplet.description,
			"image_path": droplet.image_path,
			"droplet_type": droplet.droplet_type,
			"container_docker_image": droplet.container_docker_image,
			"container_docker_registry": droplet.container_docker_registry,
			"container_cores": droplet.container_cores,
			"container_memory": droplet.container_memory,
			"container_persistent_profile_path": droplet.container_persistent_profile_path,
			"server_ip": droplet.server_ip,
			"server_port": droplet.server_port,
			"server_username": droplet.server_username,
			"server_password": "********************************" if droplet.server_password else None
		})
 
	return jsonify(response)

@admin_bp.route('/droplet', methods=['POST'])
def api_admin_edit_droplet():

	droplet_id = request.json.get('id')
	droplet = Droplet.query.filter_by(id=droplet_id).first()
 
	create_new = False
	if not droplet or droplet_id == "null":
		create_new = True
		droplet = Droplet()
  
	# Validate input
	droplet.description = request.json.get('description', None)
	if droplet.description == "":
		droplet.description = None
	droplet.image_path = request.json.get('image_path', None)
	if droplet.image_path == "":
		droplet.image_path = None

	droplet.display_name = request.json.get('display_name')
	if not droplet.display_name:
		return jsonify({"success": False, "error": "Display Name is required"}), 400

	droplet.droplet_type = request.json.get('droplet_type')
	if not droplet.droplet_type:
		return jsonify({"success": False, "error": "Droplet Type is required"}), 400
 
	if droplet.droplet_type == "container":
		droplet.container_docker_registry = request.json.get('container_docker_registry')
		if not droplet.container_docker_registry:
			return jsonify({"success": False, "error": "Docker Registry is required"}), 400

		droplet.container_docker_image = request.json.get('container_docker_image')
		if not droplet.container_docker_image:
			return jsonify({"success": False, "error": "Docker Image is required"}), 400
	
		# Ensure cores and memory are integers
		if not request.json.get('container_cores'):
			return jsonify({"success": False, "error": "Cores is required"}), 400
		if not request.json.get('container_memory'):
			return jsonify({"success": False, "error": "Memory is required"}), 400

		try:
			droplet.container_cores = float(request.json.get('container_cores'))
		except:
			return jsonify({"success": False, "error": "Cores must be a number"}), 400
		try:
			droplet.container_memory = float(request.json.get('container_memory'))
		except:
			return jsonify({"success": False, "error": "Memory must be a number"}), 400

		# Check if cores or memory are negative
		if droplet.container_cores < 0:
			return jsonify({"success": False, "error": "Cores cannot be negative"}), 400
		if droplet.container_memory < 0:
			return jsonify({"success": False, "error": "Memory cannot be negative"}), 400

		droplet.container_persistent_profile_path = request.json.get('container_persistent_profile_path')
		if not droplet.container_persistent_profile_path:
			droplet.container_persistent_profile_path = None
  
	elif droplet.droplet_type == "vnc" or droplet.droplet_type == "rdp" or droplet.droplet_type == "ssh":
		droplet.server_ip = request.json.get('server_ip')
		if not droplet.server_ip:
			return jsonify({"success": False, "error": "Server IP is required"}), 400

		droplet.server_port = request.json.get('server_port')
		if not droplet.server_port:
			return jsonify({"success": False, "error": "Server Port is required"}), 400
  
		droplet.server_username = request.json.get('server_username', None)
		if droplet.server_username == "":
			droplet.server_username = None
   
		new_server_password = request.json.get('server_password', None)
		if new_server_password != "********************************":
			droplet.server_password = new_server_password
  
		droplet.container_cores = 1
		droplet.container_memory = 1024
  
	if create_new:
		db.session.add(droplet)
 
	db.session.commit()
 
	return jsonify({"success": True})

@admin_bp.route('/droplet', methods=['DELETE'])
def api_admin_delete_droplet():
	
	droplet_id = request.json.get('id')
	droplet = Droplet.query.filter_by(id=droplet_id).first()
	if not droplet:
		return jsonify({"success": False, "error": "Droplet not found"}), 404
 
	db.session.delete(droplet)
	db.session.commit()
 
	# Delete any instances of this droplet
	instances = DropletInstance.query.filter_by(droplet_id=droplet_id).all()
	
	if utils.docker.is_docker_available():
		for instance in instances:
			try:
				container = utils.docker.docker_client.containers.get(f"flowcase_generated_{instance.id}")
				container.remove(force=True)
			except Exception as e:
				pass  # Container might not exist
			db.session.delete(instance)
			db.session.commit()
	else:
		# Even if Docker is not available, we should still delete the DB records
		for instance in instances:
			db.session.delete(instance)
		db.session.commit()
 
	return jsonify({"success": True})

@admin_bp.route('/instance', methods=['DELETE'])
def api_admin_delete_instance():

	instance_id = request.json.get('id')
	instance = DropletInstance.query.filter_by(id=instance_id).first()
	if not instance:
		return jsonify({"success": False, "error": "Instance not found"}), 404
 
	if utils.docker.is_docker_available():
		try:
			container = utils.docker.docker_client.containers.get(f"flowcase_generated_{instance.id}")
			container.remove(force=True)
		except Exception as e:
			pass  # Container might not exist
	
	db.session.delete(instance)
	db.session.commit()
 
	return jsonify({"success": True})

# User management routes removed - users are now managed via IdP

# Group management endpoints removed - simplified permission scheme

@admin_bp.route('/registry')
def api_admin_registry():

	registry = Registry.query.all()

	response = {
		"success": True,
		"flowcase_version": __version__,
		"registry": []
	}

	for r in registry:
		# Get info
		try:
			import requests
			info = requests.get(f"{r.url}/info.json").json()
			droplets = requests.get(f"{r.url}/droplets.json").json()
		except:
			info = {
				"name": "Failed to get info",
			}
			droplets = []
			from utils.logger import log
			log("ERROR", f"Failed to get registry info from {r.url}")

		response["registry"].append({
			"id": r.id,
			"url": r.url,
			"info": info,
			"droplets": droplets
		})

	return jsonify(response)

@admin_bp.route('/registry', methods=['POST', 'DELETE'])
def api_admin_edit_registry():
	if request.method == 'POST':

		url = request.json.get('url')
		if not url:
			return jsonify({"success": False, "error": "URL is required"}), 400

		# Check if registry already exists
		registry = Registry.query.filter_by(url=url).first()
		if registry:
			return jsonify({"success": False, "error": "Registry with this URL already exists"}), 400
	
		registry = Registry(url=url)
		db.session.add(registry)
		db.session.commit()
	
		return jsonify({"success": True})

	elif request.method == 'DELETE':

		registry_id = request.json.get('id')
		registry = Registry.query.filter_by(id=registry_id).first()
		if not registry:
			return jsonify({"success": False, "error": "Registry not found"}), 404
	
		db.session.delete(registry)
		db.session.commit()
 
		return jsonify({"success": True})

@admin_bp.route('/logs', methods=['GET'])
def api_admin_logs():
	
	page = request.args.get('page', 1, type=int)
	per_page = request.args.get('per_page', 50, type=int)
	log_type = request.args.get('type', None)
	
	query = Log.query
	
	if log_type and log_type.upper() in ['DEBUG', 'INFO', 'WARNING', 'ERROR']:
		query = query.filter(Log.level == log_type.upper())
	
	logs_pagination = query.order_by(Log.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
	logs = logs_pagination.items
	
	return jsonify({
		"success": True,
		"logs": [
			{
				"id": log.id,
				"created_at": log.created_at.strftime('%Y-%m-%d %H:%M:%S'),
				"level": log.level,
				"message": log.message
			} for log in logs
		],
		"pagination": {
			"page": page,
			"per_page": per_page,
			"total": logs_pagination.total,
			"pages": logs_pagination.pages
		}
	}) 