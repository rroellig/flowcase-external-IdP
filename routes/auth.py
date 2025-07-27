from flask import Blueprint, request, redirect, url_for, render_template, make_response, g
from __init__ import db
from models.user import User
from utils.logger import log

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/')
def index():
    # Always redirect to dashboard
    return redirect(url_for('auth.dashboard'))

@auth_bp.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@auth_bp.route('/droplet_connect', methods=['GET'])
def droplet_connect():
    # Always allow connection
    return make_response("", 200)