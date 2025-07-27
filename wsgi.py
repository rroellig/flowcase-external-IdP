from __init__ import create_app
from utils.docker import init_docker, cleanup_containers, start_image_pull_thread
from utils.setup import initialize_app

# Create the Flask application
app = create_app()

# Initialize the application
with app.app_context():
    from __init__ import db
    db.create_all()
    initialize_app(app)

# Initialize Docker client
docker_client = init_docker()
if not docker_client:
    print("Warning: Failed to initialize Docker client. Running droplets will be unavailable.")
else:
    cleanup_containers()
    start_image_pull_thread(app)

if __name__ == '__main__':
    from config.config import parse_args
    args = parse_args()
    print(f"Starting server on port {args.port}")
    app.run(host="0.0.0.0", debug=args.debug, port=args.port)
