from flask import (
    Flask, 
    jsonify,  
    redirect, 
    request, 
    render_template, 
    flash, 
    url_for
)
from flask_login import login_user, logout_user, login_required
from flask_login import current_user
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from src.utils import decrypt, get_value, password_check, create_id, encrypt
from src import db, login_manager
from src.model import User, Accounts
from src.errors.handlers import errors

app = Flask(__name__, template_folder='templates')
app.register_blueprint(errors)
app.config["SECRET_KEY"] = get_value('config.yaml', 'SECRET_KEY')
app.config["SQLALCHEMY_DATABASE_URI"] = get_value('config.yaml', 'DATABASE_URL')
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = get_value('config.yaml', 'SQLALCHEMY_TRACK_MODIFICATIONS')


#database
db.init_app(app)
db.create_all(app=app)


#login manager
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)



@app.route('/')
@app.route('/login', methods=['POST', 'GET'])
def login():
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

@app.route('/signup', methods=['POST'])
def signup():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')

    user = User.query.filter_by(email=email).first()

    if user:
        flash('Email address already exists.', 'danger')
        return redirect(url_for('login'))
    
    msg, status = password_check(password)
    if status == False:
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
    flash('Account created successfully', 'success')
    return redirect(url_for('user_dashboard'))

@app.route('/user', methods=['GET'])
@login_required
def user_dashboard():
    page = request.args.get('page', 1, type=int)

    accounts = Accounts.query.filter(Accounts.user_id==current_user.id).order_by(Accounts.createdAt.desc()).paginate(page=page, per_page=10)
    return render_template('user.html', user=current_user, accounts=accounts, decrypt=decrypt, enumerate=enumerate)

@app.route('/add_account', methods=['POST'])
@login_required
def add_account():
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
    user = User.query.filter_by(id=current_user.id).first()
    db.session.delete(user)
    db.session.commit()

    logout_user()
    return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True, port=80)