# Password saver

Most of the time, you don't want to store your passwords in plain text and it is more difficult to remember the password of lots of accounts. This is why we have a **password saver**. It's a simple password saver website where you can save, and edit any account username and password. It also has a login system to log in and see your protected accounts.

## Features

1. User login details are stored in a database. Where password stored in hashed form. For hashing, it uses [SHA256](https://en.wikipedia.org/wiki/SHA-2).

2. Users can save their account details in a database. The user's account password is saved in encrypted form. For encryption it use [Fernet Encryption](https://cryptography.io/en/latest/fernet/).
  
3. It also has email verification and forget password features. You can verify your email address and reset your password by clicking on the link sent to the user in the email.

4. For database we can use [SQLite](https://www.sqlite.org/) or [MySQL](https://www.mysql.com/). By default, it uses SQLite as a database.

5. It uses the [threading](https://en.wikipedia.org/wiki/Thread_(computing)) concept to send an email.

## Sample Image

![Img1](https://github.com/shubranshugupta/password-saver/blob/main/static/Img1.png)

![Img2](https://github.com/shubranshugupta/password-saver/blob/main/static/Img2.png)

![Img3](https://github.com/shubranshugupta/password-saver/blob/main/static/Img3.jpg)

## How to Install and run?

1. From Source File.

    ```bash
    git clone https://github.com/shubranshugupta/password-saver.git

    pip install -r requirements.txt
    ```

    Edit the `config.yaml` file and set the following keys:

    ```yaml
    # Database Configuration
    # If you want to use MySQL database then set the following keys. By default it uses SQLite.
    MYSQL_HOST: "hostname"
    MYSQL_USER: "username"
    MYSQL_PASSWORD: "password"
    MYSQL_PORT: 3306

    # Email Configuration
    # If you want to use Gmail then set the following keys. By default it uses Gmail smtp server.
    # Note MAIL_USERNAME & MAIL_PASSWORD should not be blank.
    MAIL_SERVER: 'server'
    MAIL_USERNAME: 'username'
    MAIL_PASSWORD: 'password'
    MAIL_PORT: 465
    MAIL_USE_SSL: True
    MAIL_USE_TLS: False

    # Admin Details
    # By default email and password is admin.
    ADMIN_EMAIL: 'admin'
    ADMIN_PASSWORD: 'admin'
    ```

    Run the application:

    ```bash
    cd password-saver
    # for windows
    python app.py
    # for linux
    python3 app.py
    ```

2. From Docker Image.

   For Docker image, you can use the following the [link](https://hub.docker.com/repository/docker/shubhgupta24/passwordsaver)

## 🔧 Tools and Technology used

1. OS:

    ![Linux](https://img.shields.io/badge/OS-Linux-informational?style=flat&logo=linux&logoColor=white&color=2bbc8a)
    ![Windows](https://img.shields.io/badge/OS-Windows-informational?style=flat&logo=windows&logoColor=white&color=2bbc8a)

2. Programing Language:

    ![Python](https://img.shields.io/badge/Code-Python-informational?style=flat&logo=python&logoColor=white&color=2bbc8a)
    ![JS](https://img.shields.io/badge/Code-JavaScript-informational?style=flat&logo=javascript&logoColor=white&color=2bbc8a)
    ![HTML](https://img.shields.io/badge/Code-HTML-informational?style=flat&logo=html5&logoColor=white&color=2bbc8a)

3. Database:

    ![SQLite](https://img.shields.io/badge/DB-SQLite-informational?style=flat&logo=sqlite&logoColor=white&color=2bbc8a)
    ![MySQL](https://img.shields.io/badge/DB-MySQL-informational?style=flat&logo=mysql&logoColor=white&color=2bbc8a)

4. Tools:

    ![Git](https://img.shields.io/badge/Tools-GitHub-informational?style=flat&logo=github&logoColor=white&color=2bbc8a)
    ![Docker](https://img.shields.io/badge/Tools-Docker-informational?style=flat&logo=docker&logoColor=white&color=2bbc8a)
    ![Flask](https://img.shields.io/badge/Tools-Flask-informational?style=flat&logo=flask&logoColor=white&color=2bbc8a)
    ![SQLAlchemy](https://img.shields.io/badge/Tools-SQLAlchemy-informational?style=flat&logo=sqlalchemy&logoColor=white&color=2bbc8a)
    ![Bootstrap](https://img.shields.io/badge/Tools-Bootstrap-informational?style=flat&logo=bootstrap&logoColor=white&color=2bbc8a)
    ![Gmail](https://img.shields.io/badge/Tools-Gmail-informational?style=flat&logo=gmail&logoColor=white&color=2bbc8a)
    ![Cryptography](https://img.shields.io/badge/Tools-Cryptography-informational?style=flat&logo=cryptography&logoColor=white&color=2bbc8a)
