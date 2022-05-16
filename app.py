from flask import (
    Flask, 
    jsonify,  
    redirect, 
    request, 
    render_template, 
    flash, 
    url_for,
)
from flask_login import login_user, logout_user, login_required
from flask_login import current_user
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from sqlalchemy_utils import database_exists, create_database
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import os

from src.utils import (
    decrypt, 
    get_value, 
    password_check, 
    create_id, 
    encrypt,
    get_mysql_url,
    get_mail,
    get_admin,
)
from src import db, login_manager, mail
from src.model import User, Accounts, Admin
from src.errors.handlers import errors
from src.mail import send_confirm_mail, send_reset_mail

# Create Important Folder
os.makedirs("data", exist_ok=True)

# Create a Flask application
app = Flask(__name__, template_folder='templates')
app.register_blueprint(errors)
app.config["SECRET_KEY"] = get_value('config.yaml', 'SECRET_KEY')
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = get_value('config.yaml', 'SQLALCHEMY_TRACK_MODIFICATIONS')

# for reading database
mysql_url = get_mysql_url()
if mysql_url:
    if not database_exists(mysql_url):
        create_database(mysql_url)
    app.config["SQLALCHEMY_DATABASE_URI"] = mysql_url
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = get_value('config.yaml', 'DATABASE_URL')


#database
db.init_app(app)
db.create_all(app=app)


# confirm email
server, username, password, port, use_tls, use_ssl = get_mail()
app.config['MAIL_SERVER'] = server
app.config['MAIL_PORT'] = port
app.config['MAIL_USERNAME'] = username
app.config['MAIL_PASSWORD'] = password
app.config['MAIL_USE_TLS'] = use_tls
app.config['MAIL_USE_SSL'] = use_ssl
mail.init_app(app)


# token serializer
ts = URLSafeTimedSerializer(app.config['SECRET_KEY'])


# Admin details
admin_email, admin_password = get_admin()
admin = Admin(admin_email, admin_password)


#login manager
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    if user_id is None:
        return None
    if user_id == admin_email or user_id == "admin":
        return admin
    return User.query.get(user_id)


@app.route('/')
@app.route('/login', methods=['POST', 'GET'])
def login():
    '''
    Login page and home page
    '''
    if request.method == 'GET':
        if current_user.is_authenticated:
            return redirect(url_for('user_dashboard'))

        return render_template('login.html', user=current_user)
    else:
        email = request.form.get('email')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False

        user = User.query.filter_by(email=email).first()

        if not user:
            flash('No Account Found', 'danger')
            return redirect(url_for('login'))
        
        if not check_password_hash(user.password, password):
            flash('Please check your login details and try again.', 'danger')
            return redirect(url_for('login'))

        login_user(user, remember=remember)

        flash('Login Successful', 'success')
        return redirect(url_for('user_dashboard'))


@app.route('/admin_login', methods=['POST'])
def admin_login():
    '''
    Admin login page
    '''
    email = request.form.get('username')
    password = request.form.get('password')
    
    if (email == admin_email) and (password == admin_password):
        login_user(admin, remember=True)
        print(current_user, current_user.is_authenticated)

        flash('Login Successful', 'success')
        return redirect(url_for('admin_dashboard'))
    
    flash('Please check your login details and try again.', 'danger')
    return redirect(url_for('login'))


@app.route('/signup', methods=['POST'])
def signup():
    '''
    Signup page
    '''
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')
    cnf_password = request.form.get('password_confirm')

    if password != cnf_password:
        flash('Password does not match', 'danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()

    if user:
        flash('Email address already exists.', 'danger')
        return redirect(url_for('login'))
    
    msg, status = password_check(password)
    if not status:
        flash(msg, 'warning')
        return redirect(url_for('login'))

    new_user = User(
        id=create_id(),
        email=email, 
        username=name, 
        password=generate_password_hash(password, method='sha256'),
        createdAt=datetime.now()
    )

    login_user(new_user)

    db.session.add(new_user)
    db.session.commit()

    try:
        send_confirm_mail(app, ts, email, current_user.username)
        flash('Please check your email to confirm your Email', 'info')
    except Exception as e:
        flash('Error sending email', 'danger')

    flash('Account created successfully', 'success')
    return redirect(url_for('user_dashboard'))


@app.route('/send_verification', methods=['GET'])
@login_required
def send_verification():
    '''
    Send verification email
    '''
    try:
        send_confirm_mail(app, ts, current_user.email, current_user.username)
        flash('Verification email sent. Refresh Page already Verify.', 'success')
        return jsonify({'status': 'success'})
    except Exception as e:
        flash('Error sending email', 'danger')
        return jsonify({'status': 'error'})


@app.route('/confirm/<token>', methods=['GET'])
def confirm_email(token):
    '''
    Confirm email
    '''
    try:
        email = ts.loads(token, salt='email-confirm', max_age=86400)
        user = User.query.filter_by(email=email).first()
        if user:
            user.verified = True
            db.session.commit()
            flash('Your email has been confirmed', 'success')
            return redirect(url_for('login'))
        else:
            flash('User not exist', 'danger')
            return redirect(url_for('login'))
    except SignatureExpired:
        flash('The token has expired', 'danger')
        return redirect(url_for('login'))
    except BadSignature:
        flash('The token is invalid', 'danger')
        return redirect(url_for('login'))


@app.route('/send_reset_password', methods=['GET', 'POST'])
def send_reset_password():
    '''
    Send reset password email
    '''
    if current_user.is_authenticated:
        return redirect(url_for('user_dashboard'))

    email = request.form.get('email')
    user = User.query.filter_by(email=email).first()

    if not user:
        flash('No Account Found', 'danger')
        return redirect(url_for('login'))

    if user.verified:
        try:
            send_reset_mail(app, ts, email)
            flash('Password Reset mail send.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash('Error sending email', 'danger')
            return redirect(url_for('login'))
    else:
        flash('Please verify your email first', 'danger')
        return redirect(url_for('login'))


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    '''
    Reset password
    '''
    if current_user.is_authenticated:
        return redirect(url_for('user_dashboard'))

    try:
        email = ts.loads(token, salt='reset-password', max_age=1800)
        user = User.query.filter_by(email=email).first()
        if user is None:
            flash('User Not present', 'danger')
            return redirect(url_for('login'))
    except SignatureExpired:
        flash('The token has expired', 'danger')
        return redirect(url_for('login'))
    except BadSignature:
        flash('The token is invalid', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'GET':
        return render_template('reset_password.html', user=current_user, token=token)
    else:
        password = request.form.get('password')
        cnf_password = request.form.get('cnf_password')

        if password != cnf_password:
            flash('Password does not match', 'danger')
            return redirect(url_for('reset_password', token=token))
        
        msg, status = password_check(password)
        if not status:
            flash(msg, 'warning')
            return redirect(url_for('reset_password', token=token))
        
        user.password = generate_password_hash(password, method='sha256')
        db.session.commit()

        flash('Password changed successfully', 'success')
        return redirect(url_for('login'))


@app.route('/user', methods=['GET'])
@login_required
def user_dashboard():
    '''
    User dashboard
    '''
    page = request.args.get('page', 1, type=int)

    accounts = Accounts.query.filter(Accounts.user_id==current_user.id).order_by(Accounts.createdAt.desc()).paginate(page=page, per_page=10)
    return render_template(
        'user.html', 
        user=current_user, 
        accounts=accounts, 
        decrypt=decrypt, 
        enumerate=enumerate,
        verified = current_user.verified
    )


@app.route('/account_detail', methods=['GET'])
@login_required
def account_detail():
    '''
    User account detail
    '''
    return render_template(
        'user_account.html', 
        user=current_user,
    )


@app.route('/admin', methods=['GET'])
@login_required
def admin_dashboard():
    '''
    Admin dashboard
    '''
    page = request.args.get('page', 1, type=int)

    users = User.query.order_by(User.createdAt.desc()).paginate(page=page, per_page=10)
    return render_template(
        'admin.html',
        user=current_user,
        users_detail=users,
        enumerate=enumerate,
    )


@app.route('/update_username', methods=['POST'])
@login_required
def update_username():
    '''
    Update users username
    '''
    data = request.get_json()
    username = data.get("username")
    email = current_user.email

    user = User.query.filter_by(email=email).first()
    user.username = username
    db.session.commit()

    flash('Username updated successfully', 'success')
    return jsonify({'status': 'success'})


@app.route('/add_account', methods=['POST'])
@login_required
def add_account():
    '''
    Add different account to user
    '''
    account_name = request.form.get('account')
    username = request.form.get('email')
    password = encrypt(request.form.get('password'))

    new_account = Accounts(
        id=create_id(),
        user_id=current_user.id,
        account_name=account_name,
        username=username,
        password=password,
        createdAt=datetime.now()
    )

    user = User.query.filter_by(id=current_user.id).first()
    user.total_accounts += 1

    db.session.add(new_account)
    db.session.add(user)
    db.session.commit()

    return redirect(url_for('user_dashboard'))


@app.route('/update', methods=['POST'])
@login_required
def update():
    '''
    Update users different accounts that saved.
    '''
    data = request.get_json()
    account_id = data['accountid']
    account_name = data['account']
    username = data['email']
    password = encrypt(data['password'])

    account = Accounts.query.filter_by(id=account_id).first()
    account.account_name = account_name
    account.username = username
    account.password = password

    db.session.add(account)
    db.session.commit()

    return jsonify({'status': 'success'})


@app.route('/delete', methods=['POST'])
@login_required
def delete():
    '''
    Delete users different accounts that saved.
    '''
    data = request.get_json()
    account_id = data['accountid']

    user = User.query.filter_by(id=current_user.id).first()
    user.total_accounts -= 1

    account = Accounts.query.filter_by(id=account_id).first()

    db.session.add(user)
    db.session.delete(account)
    db.session.commit()

    return jsonify({'status': 'success'})


@app.route('/deleteUser', methods=['POST'])
@login_required
def delete_user():
    '''
    Delete users.
    '''
    password = request.form.get('password')
    if not check_password_hash(current_user.password, password):
        flash('Password does not match', 'danger')
        return redirect(url_for('account_detail'))

    user = User.query.filter_by(id=current_user.id).first()
    db.session.delete(user)
    db.session.commit()

    flash('Account deleted successfully', 'success')
    logout_user()
    return redirect(url_for('login'))


@app.route('/logout')
@login_required
def logout():
    '''
    Logout user
    '''
    logout_user()
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True, port=80, host="0.0.0.0")