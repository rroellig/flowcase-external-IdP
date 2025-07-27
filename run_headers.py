from flask import Flask, request
from config.config import parse_args

import json

app = Flask(__name__)

@app.route("/")
def show_headers():
    headers = request.headers
    headers_html = "<h1>Request Headers</h1><ul>"
    for header, value in headers.items():
        headers_html += f"<li><strong>{header}:</strong> {value}</li>"
    headers_html += "</ul>"
    return headers_html

if __name__ == '__main__':
    args = parse_args()

    print("Starting HTTP Headers Debug Server...")
    print("Access http://127.0.0.1:{args.port}/ to see your request headers")
    app.run(host="0.0.0.0", debug=args.debug, port=args.port)
