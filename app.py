from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import jwt
from functools import wraps
from werkzeug.utils import secure_filename
from flask import Flask, request, jsonify, make_response, render_template,redirect, url_for,flash
from datetime import datetime, timedelta
import boto3

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads/'
app.config['SECRET_KEY'] = "some-secret key"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  #size till 10 mb
app.config['S3_BUCKET'] = "flask-task"
app.config['S3_KEY'] = "AKIA6JRRQREYDQUSHEOF"
app.config['S3_SECRET'] = "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"
app.config['S3_LOCATION'] = 'http://{}.s3.amazonaws.com/'.format(app.config['S3_BUCKET'])


expected_extenstion = ['jpg','jpeg','png']

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
)
s3 = boto3.client(
        "s3",
        aws_access_key_id=app.config['S3_KEY'],
        aws_secret_access_key=app.config['S3_SECRET']
    )

def send_to_s3(file, bucket_name):
    """
    Docs: http://boto3.readthedocs.io/en/latest/guide/s3.html
    """
    try:
        s3.upload_fileobj(
            file,
            bucket_name,
            file.filename,
        )
    except Exception as e:
        print("Something Happened: ", e)
        return e
    return "{}{}".format(app.config["S3_LOCATION"], file.filename)

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
        return redirect("https://flask-task-2.herokuapp.com/dashboard?token={}".format(str(token.decode('utf-8'))), 302)
    else:
        flash('Invalid User Password, please try again.')
        return render_template('login.html')

@token_required
def allowed_file(filename):
    print('Filename: ',filename)
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
        output = send_to_s3(file, app.config["S3_BUCKET"])
        print('output:{}'.format(output))
        flash('Image successfully uploaded')
        return redirect(url_for('display_image',filename=filename))
        # return render_template('task_uploaded_image.html', filename=filename,title = filename)
    else:
        flash('Please upload the file have these extension- jpg, jpeg')
        return redirect(request.url)


def show_image(filename,bucket):
    print("In show-function")
    try:
        for item in s3.list_objects(Bucket=bucket)['Contents']:
            if str(item['Key']) == filename:
                print('item:{}'.format(item['Key']))
                print('filename:{}'.format(filename))
                presigned_url = s3.generate_presigned_url('get_object', Params = {'Bucket': bucket, 'Key': item['Key']}, ExpiresIn = 100)
                return presigned_url
    except Exception as e:
        pass

@app.route('/display/<filename>')
def display_image(filename):
    print('in display: ',filename)
    contents = show_image(filename,"flask-task")
    print('Contents: ',contents)
    return render_template('task_uploaded_image.html', contents=contents,title=filename)
    # return redirect(url_for('static', filename='uploads/'+filename))

if __name__ == "__main__":
    app.run(debug=True)
