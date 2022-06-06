FROM python:3.9

# Defining working dir and paste all file in it
WORKDIR /passwdSaver
ADD . /passwdSaver

# Install dependencies
RUN pip3 install -r requirements.txt

# Database Environmental variables
ENV MYSQL_HOST=""
ENV MYSQL_USER=""
ENV MYSQL_PASSWORD=""
ENV MYSQL_PORT=3306

# Mail Environment variables
ENV MAIL_SERVER="smtp.gmail.com"
ENV MAIL_USERNAME=""
ENV MAIL_PASSWORD=""
ENV MAIL_PORT=465
ENV MAIL_USE_TLS=False
ENV MAIL_USE_SSL=True

# Admin details
ENV ADMIN_EMAIL="admin"
ENV ADMIN_PASSWORD="admin"

# Exposing port
EXPOSE 80

# Run the application:
CMD [ "python3.9", "app.py" ]