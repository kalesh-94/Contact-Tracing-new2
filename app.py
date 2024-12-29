from flask import Flask, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///newdatabase.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = "sqlite:///newdatabase.db"

# Initialize database and migration
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='user')  # 'user' or 'admin'
    is_infected = db.Column(db.Boolean, default=False)  # True for infected, False for uninfected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship to LoginActivity
    login_activities = db.relationship('LoginActivity', back_populates='user')

class LoginActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship to User
    user = db.relationship('User', back_populates='login_activities')

# Routes
@app.route('/')
def home():
    return render_template('home.html')


@app.route('/user/signup', methods=['GET', 'POST'])
def user_signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            return "Username already exists!", 400

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, role='user')

        db.session.add(new_user)
        try:
            db.session.commit()  # Commit to the database
            print("User successfully added")  # Debug statement
        except Exception as e:
            db.session.rollback()  # In case of error, rollback the session
            print(f"Error occurred: {e}")  # Print the error for debugging
            return "An error occurred. Please try again.", 500

        return redirect('/user/login')

    return render_template('signup.html')


# User routes
@app.route('/user/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, role='user').first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = 'user'

            # Capture the location on login (latitude and longitude)
            latitude = request.form['latitude']
            longitude = request.form['longitude']

            # Store the login activity with location
            login_activity = LoginActivity(user_id=user.id, latitude=latitude, longitude=longitude)
            db.session.add(login_activity)
            db.session.commit()

            return redirect('/user/dashboard')
        else:
            return "Invalid username or password", 401

    return render_template('login.html')

@app.route('/user/dashboard')
def user_dashboard():
    if 'user_id' in session and session.get('role') == 'user':
        user = User.query.get(session['user_id'])
        if not user:
            return redirect('/user/login')

        user_activities = LoginActivity.query.filter_by(user_id=user.id).all()
        return render_template('user_dashboard.html', user=user, user_activities=user_activities)
    
    return redirect('/user/login')

# Admin routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        admin = User.query.filter_by(username=username, role='admin').first()

        if admin and check_password_hash(admin.password, password):
            session['admin_id'] = admin.id
            session['role'] = 'admin'
            return redirect('/admin/dashboard')
        else:
            return "Invalid admin username or password", 401

    return render_template('admin_login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_id' in session and session.get('role') == 'admin':
        users = User.query.filter_by(role='user').all()
        activities = LoginActivity.query.order_by(LoginActivity.timestamp.desc()).all()

        user_locations = [
            {
                'username': activity.user.username,
                'latitude': activity.latitude,
                'longitude': activity.longitude,
                'is_infected': activity.user.is_infected
            }
            for activity in activities
        ]

        return render_template('admin.html', users=users, user_locations=user_locations)

    return redirect('/admin/login')

# Predefine admin in the database
def create_admin():
    admin_username = "Admin1"
    admin_password = "12345"
    admin = User.query.filter_by(username=admin_username, role='admin').first()
    if not admin:
        # Use 'pbkdf2:sha256' instead of 'sha256'
        hashed_password = generate_password_hash(admin_password, method='pbkdf2:sha256')
        new_admin = User(username=admin_username, password=hashed_password, role='admin')
        db.session.add(new_admin)
        db.session.commit()

@app.route('/update_status', methods=['POST'])
def update_status():
    if 'admin_id' not in session or session.get('role') != 'admin':
        return "Unauthorized", 403

    data = request.json
    user_id = data.get('user_id')
    is_infected = data.get('is_infected')
    status = data.get('status')

    user = User.query.get(user_id)
    if user:
        user.is_infected = is_infected
        user.status = status
        db.session.commit()
        return "Status updated", 200



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin()

    debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)


