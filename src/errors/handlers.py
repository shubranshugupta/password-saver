from flask import Blueprint, render_template

errors = Blueprint('error', __name__, template_folder='templates', static_folder='static')

@errors.app_errorhandler(404)
def error_404(error):
    return render_template('error.html', error=404), 404

@errors.app_errorhandler(500)
def error_500(error):
    return render_template('error.html', error=500), 500

@errors.app_errorhandler(403)
def error_403(error):
    return render_template('error.html', error=403), 403

@errors.app_errorhandler(405)
def error_403(error):
    return render_template('error.html', error=405), 405

@errors.app_errorhandler(400)
def error_400(error):
    return render_template('error.html', error=400), 400