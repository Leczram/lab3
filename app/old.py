from flask import Flask, render_template, redirect, request, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import InputRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Zmienić na bezpieczną, stałą wartość w produkcji
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    thread_id = db.Column(db.Integer, db.ForeignKey('thread.id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('posts', lazy=True))



class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(20), default='user')


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    submit = SubmitField('Login')

class Thread(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    posts = db.relationship('Post', backref='thread', lazy='dynamic')



class ThreadForm(FlaskForm):
    title = StringField('Title', validators=[InputRequired(), Length(min=5, max=100)])
    submit = SubmitField('Create Thread')

class PostForm(FlaskForm):
    content = TextAreaField('Content', validators=[InputRequired()])
    submit = SubmitField('Post Reply')

@app.route('/admin/users')
def admin_users():
    if 'user_id' not in session or User.query.get(session['user_id']).role != 'admin':
        flash('Access denied.')
        return redirect(url_for('home'))
    users = User.query.all()
    return render_template('admin_users.html', users=users)


@app.route('/thread/<int:thread_id>', methods=['GET', 'POST'])
def thread(thread_id):
    thread = Thread.query.get_or_404(thread_id)
    form = PostForm()
    if form.validate_on_submit():
        if 'user_id' not in session:
            flash('You need to be logged in to post replies.')
            return redirect(url_for('login'))
        post = Post(content=form.content.data, user_id=session['user_id'], thread_id=thread.id)
        db.session.add(post)
        db.session.commit()
        return redirect(url_for('thread', thread_id=thread.id))
    posts = thread.posts.all()
    return render_template('thread.html', thread=thread, form=form, posts=posts)

@app.route('/forum')
def forum():
    threads = Thread.query.all()
    return render_template('forum.html', threads=threads)

@app.route('/new_thread', methods=['GET', 'POST'])
def new_thread():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    form = ThreadForm()
    if form.validate_on_submit():
        thread = Thread(title=form.title.data)
        db.session.add(thread)
        db.session.commit()
        return redirect(url_for('forum'))
    return render_template('new_thread.html', form=form)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user is None:
            hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
            new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
            db.session.add(new_user)
            try:
                db.session.commit()
                flash('New user has been created!')
                return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback()
                flash(f'Error registering user: {str(e)}')
        else:
            flash('Username or email already exists.')
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            session['user_id'] = user.id
            flash('You have been successfully logged in.')
            return redirect(url_for('forum'))  # Przekieruj na forum zamiast profilu
        else:
            flash('Invalid username or password.')
    return render_template('login.html', form=form)

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('You are not logged in!')
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if user:
        return render_template('profile.html', user=user)
    else:
        flash('User not found!')
        return redirect(url_for('home'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.')
    return redirect(url_for('home'))

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

if __name__ == '__main__':
    app.run(debug=True)
