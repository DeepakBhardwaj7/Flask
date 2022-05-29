from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
import jwt
from functools import wraps
from werkzeug.utils import secure_filename
from flask import Flask, request, jsonify, make_response, render_template, session, redirect, url_for,flash
from datetime import datetime, timedelta

app = Flask(__name__)

UPLOAD_FOLDER = 'static/uploads/'

app.config['SECRET_KEY'] = "some-secret key"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  #size till 10 mb

expected_extenstion = ['jpg','jpeg']

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
)

# database name
# decorator for verifying the JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            return jsonify({"Alert!": 'Token is missing'})
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify({'Alert!': 'Invalid Token'})
        return f(*args, **kwargs)
    return decorated


@app.route('/')
def home():
    return render_template('login.html')

# else:
# 	return redirect(url_for('login'))
# return 'logged in currently!'
# User Database Route
# this route sends back list of use


# route for logging user in
@app.route('/login', methods=['POST'])
def login():
    if request.form['name'] and request.form['password'] == '12345':
        token = jwt.encode({
            'user': request.form['name'],
            'expiration': str(datetime.utcnow() + timedelta(seconds=120))},
            app.config['SECRET_KEY'])
        return redirect("http://127.0.0.1:5000/dashboard?token={}".format(str(token.decode('utf-8'))), 302)
    else:
        return make_response(
            'unable to verify', 403, {'auth': 'failed'}
        )

@token_required
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in expected_extenstion


@app.route('/dashboard')
@token_required
def dashboard():
    return render_template('task.html',title='Python Flask Upload and display image')


@app.route('/upload', methods=['POST'])
@limiter.limit("5 per minute")
def upload_image():
    file = request.files['file']
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename) # Flask method, used when we want to store filename.
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        flash('Image successfully uploaded')
        return render_template('task_uploaded_image.html', filename=filename,title = filename)
    else:
        flash('Please upload the file have these extension- jpg, jpeg')
        return redirect(request.url)


@app.route('/display/<filename>')
def display_image(filename):
    return redirect(url_for('static', filename='uploads/'+filename))


if __name__ == "__main__":
    app.run(debug=True)
