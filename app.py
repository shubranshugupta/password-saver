# import boto3
from flask import (
    Flask, 
    jsonify, 
    make_response, 
    redirect, 
    request, 
    render_template, 
    flash, 
    session
)
from flask_restful import abort
from werkzeug.security import generate_password_hash, check_password_hash
import pynamodb

from src.utils import password_check, create_id, encrypt, decrypt
from src.model import User, PasswordSaver, Pagination

app = Flask(__name__, template_folder='templates')

app.config["SECRET_KEY"] = "rzaNklYJO4iQ_ahQXCDLIp_AFEh2UOZYalKFDT3hhg4"

if not User.exists():
    User.create_table(read_capacity_units=1, write_capacity_units=1, wait=True)

if not PasswordSaver.exists():
    PasswordSaver.create_table(read_capacity_units=1, write_capacity_units=1, wait=True)


@app.route('/', methods=['GET'])
def index():
    return render_template('header.html')


@app.route('/signup', methods=['POST'])
def signup():
    username = request.form['name']
    email = request.form['email']
    password = request.form['password']
    password_confirm = request.form['password_confirm']
    
    if password != password_confirm:
        flash('Passwords do not match', 'danger')
        return render_template('header.html')

    msg, valid = password_check(password)
    if not valid:
        flash(msg, 'warning')
        return render_template('header.html')
    
    try:
        user = User.get(hash_key=email)

        flash('Email already exists', 'warning')
        return redirect('/')
    except User.DoesNotExist:
        password = generate_password_hash(password, salt_length=32)
        user = User(email=email, username=username, password=password)
        user.save()

        session['email'] = user.email
        session['user'] = user.username

        flash('Account created successfully', 'success')
        return redirect('/user')


@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']

    try:
        user = User.get(hash_key=email)
        if check_password_hash(user.password, password):
            session['email'] = user.email
            session['user'] = user.username
            flash('Login successful', 'success')
            return redirect('/user')
        else:
            flash('Incorrect password', 'warning')
            return redirect('/')

    except User.DoesNotExist:
        flash('Email does not exist', 'warning')
        return redirect('/')


@app.route('/logout', methods=['GET'])
def logout():
    session.clear()
    flash('Logout successful', 'success')
    return redirect('/')


@app.route('/user', methods=['GET'])
def user():
    if 'email' in session:
        page = request.args.get('page', 1, type=int)
        email = session['email']
        try:
            pagination = Pagination("password_saver", "userID", email, ["account", "username", "password"])
            items, key = pagination.paginate(limit=1)
            print(items)
            items, key = pagination.paginate(last_key=key, limit=1)
            print(items)

        except pynamodb.exceptions.GetError:
            return abort(503)

        return render_template('header.html', accounts=items, length=len(items), decrypt=decrypt)
    else:
        flash("Please Login", "danger")
        return redirect('/')


@app.route('/addAccount', methods=['POST'])
def add_account():
    if 'email' in session:
        main_email = session['email']

        account = request.form['account']
        email = request.form['email']
        password = request.form['password']
        password = encrypt(password)

        password_saver = PasswordSaver(accountId=create_id(), userID=main_email, account=account, username=email, password=password)
        password_saver.save()

        flash('Account added successfully', 'success')
        return redirect('/user')
    else:
        flash("Please Login", "danger")
        return redirect('/')


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")