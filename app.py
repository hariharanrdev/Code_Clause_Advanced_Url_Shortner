from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
import os
import string
import random
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    urls = db.relationship('URL', backref='owner', lazy=True)

class URL(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_url = db.Column(db.String(500), nullable=False)
    short_url = db.Column(db.String(10), unique=True, nullable=False)
    visits = db.Column(db.Integer, default=0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    visit_details = db.relationship('Visit', backref='url', cascade='all, delete-orphan', lazy=True)

class Visit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url_id = db.Column(db.Integer, db.ForeignKey('url.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_agent = db.Column(db.String(200))
    ip_address = db.Column(db.String(50))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    if current_user.is_authenticated:
        urls = URL.query.filter_by(owner=current_user)
        return render_template('dashboard.html', urls=urls)
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('home'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

def generate_short_url():
    characters = string.ascii_letters + string.digits
    short_url = ''.join(random.choice(characters) for _ in range(6))
    link = URL.query.filter_by(short_url=short_url).first()
    if link:
        return generate_short_url()
    return short_url

@app.route('/shorten', methods=['POST'])
@login_required
def shorten():
    original_url = request.form.get('url')
    short_url = generate_short_url()
    new_url = URL(original_url=original_url, short_url=short_url, owner=current_user)
    db.session.add(new_url)
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/<short_url>')
def redirect_to_url(short_url):
    url = URL.query.filter_by(short_url=short_url).first_or_404()
    url.visits += 1

    visit = Visit(url_id=url.id, user_agent=request.headers.get('User-Agent'), ip_address=request.remote_addr)
    db.session.add(visit)
    db.session.commit()

    return redirect(url.original_url)

@app.route('/analytics/<int:url_id>')
@login_required
def analytics(url_id):
    url = URL.query.get_or_404(url_id)
    if url.owner != current_user:
        return redirect(url_for('home'))
    visits = Visit.query.filter_by(url_id=url.id).all()
    return render_template('analytics.html', url=url, visits=visits)

@app.route('/delete/<int:url_id>', methods=['POST'])
@login_required
def delete_url(url_id):
    url = URL.query.get_or_404(url_id)
    if url.owner != current_user:
        flash('You do not have permission to delete this URL')
        return redirect(url_for('home'))
    db.session.delete(url)
    db.session.commit()
    flash('URL has been deleted')
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
