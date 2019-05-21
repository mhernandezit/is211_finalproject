#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Flask application using sqlite3 database"""

import sqlite3 as lite
import re
import os
import json
import pandas as pd
from flask import (Flask, render_template, request, redirect,
                   g, flash, session)
from werkzeug.security import check_password_hash, generate_password_hash
from flask_bootstrap import Bootstrap
from flask_moment import Moment

app = Flask(__name__)
bootstrap = Bootstrap(app)
app.secret_key = os.urandom(24).encode('hex')
moment = Moment(app)
vendor_list = []
user_inventory = []
import sqlite3



# Parsing data from json to get the fields I need for the database
# for item in responsedata:
#     item_id = item.get('id')
#     references[item_id] = {}
#     references[item_id]['cvss'] = item.get('cvss')
#     references[item_id]['summary'] = item.get('summary')
#     references[item_id]['references'] = item.get('references')
# print references

columns = ['id', 'cvss', 'summary','references','vulnerable_configuration']
df = pd.read_json(open('ciscoresponse.json'))
df2 = df.loc[:, columns]
print df2

# vendordata = json.load(open('vendors.json'))
vendor_df = pd.read_json(open('vendors.json'))
vdf = vendor_df.drop(columns='product')
print vdf

cisco_df = pd.read_json(open('ciscodevices.json'))
print cisco_df

def add_inventory(userid, devices):
    for device in devices:



def get_db():
    """ Database initialization, getter """
    if 'db' not in g:
        g.db = lite.connect('hw13.db')
        g.db.row_factory = lite.Row

    return g.db


@app.route('/', methods=['GET'])
def index():
    """ Default route - returns the dashboard if a user is logged in
        Otherwise, returns a login page """
    if 'logged_in' in session:
        return redirect('/dashboard')
    else:
        return render_template('auth/login.html')


@app.route('/dashboard', methods=['GET'])
def dashboard():
    """ Dashboard - normal page returns the school homepage
        If a user has a shortcut to this page, but is not logged in
        this page will redirect to the login """
    if 'logged_in' in session:
        return render_template('school/dashboard.html',
                               student_roster=student_roster,
                               quiz_roster=quiz_roster)
    else:
        return redirect('/')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """ Login page, pulls username, password from a form
        checks if the username is in the DB, and if the
        password hash matches the password in the DB """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        error = None
        database = get_db()
        user = database.execute(
            """SELECT * FROM teachers WHERE username = ?""",
            (username,)).fetchone()

        if user is None:
            error = 'Incorrect username.'
            flash("Testing flash")
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'
            flash("Incorrect password")

        if error is None:
            session.clear()
            session['logged_in'] = True
            session['user_id'] = user['teacherid']

            for row in database.execute('SELECT * FROM students'):
                if row not in student_roster:
                    student_roster.append((row))

            for row in database.execute('SELECT * FROM quizzes'):
                if row not in quiz_roster:
                    quiz_roster.append((row))

            return redirect('/dashboard')

        flash("flash")
        return render_template('auth/login.html')

    if request.method == 'GET':
        return redirect('/dashboard')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """ Page to register a new admin user """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        error = None
        database = get_db()

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        elif database.execute(
                """SELECT teacherid FROM teachers WHERE username = ?""",
                (username,)).fetchone() is not None:
            error = 'User {} is already registered.'.format(username)

        if error is None:
            database.execute(
                """INSERT INTO teachers (username, password) VALUES (?, ?)""",
                (username, generate_password_hash(password)))
            database.commit()

        return redirect('/dashboard')

    elif request.method == 'GET':
        return render_template('auth/register.html')


@app.route('/student/add', methods=['GET', 'POST'])
def add_student():
    """ Function to add a student to the database """
    if 'logged_in' in session:
        if request.method == 'GET':
            return render_template('school/add_student.html')
        elif request.method == 'POST':
            firstname = request.form['firstname']
            lastname = request.form['lastname']
            database = get_db()
            error = None

            if not firstname:
                error = 'First name is required.'
            elif not lastname:
                error = 'Last name is required.'

            if re.search(r'[!@#$%^&*(),.?":{}|<>]', firstname):
                error = "Invalid characters used. " \
                        "Please do not include special characters."
            elif re.search(r'[!@#$%^&*(),.?":{}|<>]', lastname):
                error = "Invalid characters used. " \
                        "Please do not include special characters."

            if error is None:
                database.execute(
                    """INSERT INTO students (firstname, lastname)
                    VALUES (?, ?)""", (firstname, lastname))
                database.commit()

                for row in database.execute("""SELECT * FROM students
                                            WHERE firstname=? AND
                                            lastname=?;""",
                                            (firstname, lastname)):
                    student_roster.append((row))
                return redirect('/dashboard')

        flash(error)
        return render_template('school/add_student.html')
    else:
        return redirect('/')


@app.route('/quiz/add', methods=['GET', 'POST'])
def add_quiz():
    """ Function to add a quiz to the database """
    error = None
    if 'logged_in' in session:
        if request.method == 'GET':
            return render_template('school/add_quiz.html')
        elif request.method == 'POST':
            subject = request.form['subject']
            questions = request.form['questions']
            date = request.form['date']
            database = get_db()

            if not subject:
                error = 'Subject is required.'
            elif not questions:
                error = 'Number of questions is required.'
            elif not date:
                error = 'Quiz date is required.'

            if re.search(r'[!@#$%^&*(),.?":{}|<>]', subject):
                error = "Invalid characters used in Subject. "

            if error is None:
                database.execute(
                    """ INSERT INTO
                        quizzes (subject, questions, date)
                        VALUES
                       ( ? , ? , ? )""", (subject, questions, date))
                database.commit()

                for row in database.execute(
                    """SELECT * FROM quizzes
                        WHERE subject =? AND questions =? AND date =? ;""",
                        (subject, questions, date)):
                    quiz_roster.append((row))
                return redirect('/dashboard')

        flash(error)
        return render_template('school/add_quiz.html')
    else:
        return redirect('/')


@app.route('/student/<path:studentid>', methods=['GET'])
def view_student(studentid):
    """ Function to add a student to the database """
    if 'logged_in' in session:
        student_data = []
        student_name = []
        sid = studentid
        database = get_db()

        for row in database.execute('SELECT firstname, lastname '
                                    'FROM students '
                                    'WHERE studentid=?;', sid):
            if row not in student_name:
                student_name.append((row))

        for row in database.execute(
            """SELECT quizzes.quizid,
                quizzes.subject,
                quizzes.questions,
                quizzes.date,
                grades.score
                FROM   quizzes
                JOIN   grades
                ON     grades.quizid == quizzes.quizid
                WHERE   studentid=?;""", sid):
            if row not in student_data:
                student_data.append((row))

        return render_template('school/student.html',
                               studentid=studentid,
                               student_data=student_data,
                               student_name=student_name)


@app.route('/inventory/add', methods=['GET', 'POST'])
def add_score():
    """ Function to add a device to the user inventory """
    if 'logged_in' in session and request.method == 'GET':
        vendor_list = []
        quiz_list = []
        database = get_db()

        for row in database.execute('SELECT * FROM vendors;'):
            if row not in vendor_list:
                vendor_list.append((row))

        for row in database.execute('SELECT quizid, subject FROM quizzes;'):
            if row not in quiz_list:
                quiz_list.append((row))

        return render_template('school/results.html',
                               student_list=student_list,
                               quiz_list=quiz_list)

    elif 'logged_in' in session and request.method == 'POST':
        student = request.form['student_list']
        quiz = request.form['quiz_list']
        score = request.form['score']
        database = get_db()
        message = None

        if score > 0 and score < 100:
            duplicates = database.execute("""
            SELECT * FROM grades WHERE studentid=? AND quizid=?;""",
                                          (student, quiz))

            if duplicates.fetchone() is None:
                database.execute(
                    """INSERT INTO grades(studentid, quizid, score)
                     VALUES (?, ?, ?);""",
                                (student, quiz, score))
                database.commit()
                message = "Quiz added successfully!"
            else:
                message = "Duplicate quiz for this student found."
        else:
            message = "Score must be between 0 and 100"

        flash(message)

        return redirect('/results/add')

    else:
        return redirect('/')


@app.errorhandler(404)
def page_not_found(error):
    """ Renders a custom 404 error page """
    print error
    return render_template('404.html'), 404


@app.errorhandler(500)
def server_error(error):
    """ Renders a custom 500 error page """
    print error
    return render_template('500.html'), 500


@app.errorhandler(405)
def unauthorized_error(error):
    """ Renders a custom 405 error page """
    print error
    return render_template('405.html'), 405


if __name__ == '__main__':
    app.run(debug=1)


