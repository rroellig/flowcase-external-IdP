from __init__ import create_app, db
from config.config import parse_args
from utils.docker import init_docker, cleanup_containers, start_image_pull_thread
from utils.setup import initialize_app

if __name__ == '__main__':
	args = parse_args()
	
	app = create_app()
	
	with app.app_context():
		db.create_all()
		initialize_app(app)
	
	docker_client = init_docker()
	if not docker_client:
		print("Warning: Failed to initialize Docker client. Running droplets will be unavailable.")
	else:
		cleanup_containers()
		start_image_pull_thread(app)
	
	print(f"Starting server on port {args.port}")
	app.run(host="0.0.0.0", debug=args.debug, port=args.port)