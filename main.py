# Written by Arpan Neupane on September 3, 2020
# Copyright ©️ Arpan Neupane 2020.
# Refer to the README.md for more information.

from flask import Flask, url_for, render_template, flash, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_bootstrap import Bootstrap
from wtforms import SubmitField, TextAreaField, StringField, PasswordField
from wtforms.validators import InputRequired, Length, ValidationError, Email
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
import os
from datetime import datetime
from flask_bcrypt import Bcrypt
app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

app.config['SECRET_KEY'] = 'jfale!@#gys^&*(@jafd00193n'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
bootstrap = Bootstrap(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    todo = db.Column(db.String(130), nullable=False)
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    todo = db.relationship('Todo', backref='writer', lazy=True)


class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Email(message="Invalid Email"), Length(max=50)])
    username = StringField("Username", validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=4, max=15)])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("That username already exists. Please choose a different one.")
    
    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()
        if existing_user_email:
            raise ValidationError("That email address belongs to different user. Please choose a different one.")

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=4, max=50)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=4, max=15)])
    submit = SubmitField('Login')


class NewTodoForm(FlaskForm):
    todo = TextAreaField("Enter Todo", validators=[InputRequired(), Length(min=4, max=130)])
    submit = SubmitField("Create Todo")


@app.route('/home')
@app.route('/')
def home():
    return render_template('index.html', title="Home")


# Registration
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(email=form.email.data, username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

    return render_template('signup.html', form=form, title='Sign Up')


# Login
@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for("home"))
        flash("User does not exist, or invalid username or password.", 'warning')
    return render_template("login.html", form=form, title="Login")


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('login'))


# Show the todos made by the user.
@login_required
@app.route('/mytodos')
def show_todos():
    incomplete = Todo.query.filter_by(writer=current_user, complete=False).all()
    complete = Todo.query.filter_by(writer=current_user, complete=True).all()
    return render_template('mytodos.html', incomplete=incomplete, complete=complete)


@login_required
@app.route("/newtodo", methods=['GET','POST'])
def create_todo():
    form = NewTodoForm()
    if form.validate_on_submit():
        todo = Todo(todo=form.todo.data, complete=False, writer=current_user)
        db.session.add(todo)
        db.session.commit()
        flash("Your todo has been created!", 'success')
        return redirect(url_for('show_todos'))
    return render_template('newtodo.html', title='New Todo', form=form)


@login_required
@app.route('/complete/<todo_id>', methods=['GET', 'POST'])
def complete_todo(todo_id):
    todo = Todo.query.get_or_404(todo_id)
    todo.complete = True
    db.session.commit()
    flash('Todo Completed 🙌🏽!', 'success')
    return redirect(url_for('show_todos'))


@login_required
@app.route('/delete/<todo_id>', methods=['GET', 'POST'])
def delete_todo(todo_id):
    todo = Todo.query.get_or_404(todo_id)
    db.session.delete(todo)
    db.session.commit()
    flash('Todo Deleted', 'success')
    return redirect(url_for('show_todos'))



if __name__ == "__main__":
    app.run(debug=True) 