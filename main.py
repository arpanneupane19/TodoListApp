# Written by Arpan Neupane on September 1, 2020
# Copyright ©️ Arpan Neupane 2020.
# Refer to the README.md for more information.

from flask import Flask, url_for, render_template, flash, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_bootstrap import Bootstrap
from wtforms import SubmitField, TextAreaField
from wtforms.validators import InputRequired, Length, ValidationError
app = Flask(__name__)
db = SQLAlchemy(app)


app.config['SECRET_KEY'] = 'jfale!@#gys^&*(@jafd00193n'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
bootstrap = Bootstrap(app)


class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    todo = db.Column(db.String(130), nullable=False)
    complete = db.Column(db.Boolean)


class NewTodoForm(FlaskForm):
    todo = TextAreaField("Enter Todo", validators=[InputRequired(), Length(min=4, max=130)])
    submit = SubmitField("Create Todo")


@app.route('/home')
@app.route('/')
def home():
    return render_template('index.html', title="Home")


@app.route('/mytodos')
def show_todos():
    incomplete = Todo.query.filter_by(complete=False)
    complete = Todo.query.filter_by(complete=True)
    return render_template('mytodos.html', complete=complete, incomplete=incomplete)


@app.route("/newtodo", methods=['GET','POST'])
def create_todo():
    form = NewTodoForm()
    if form.validate_on_submit():
        todo = Todo(todo=form.todo.data, complete=False)
        db.session.add(todo)
        db.session.commit()
        flash("Your todo has been created!", 'success')
        return redirect(url_for('show_todos'))
    return render_template('newtodo.html', title='New Todo', form=form)


@app.route('/complete/<todo_id>', methods=['GET', 'POST'])
def complete_todo(todo_id):
    todo = Todo.query.get_or_404(todo_id)
    todo.complete = True
    db.session.commit()
    flash('Todo Completed 🙌🏽!', 'success')
    return redirect(url_for('show_todos'))


@app.route('/delete/<todo_id>', methods=['GET', 'POST'])
def delete_todo(todo_id):
    todo = Todo.query.get_or_404(todo_id)
    db.session.delete(todo)
    db.session.commit()
    flash('Todo Deleted', 'success')
    return redirect(url_for('show_todos'))


if __name__ == "__main__":
    app.run() 