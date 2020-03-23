from jinja2 import StrictUndefined
import os
from datetime import datetime
from flask import Flask, render_template, redirect, request, flash, session

#from flask_debugtoolbar import DebugToolbarExtension
from werkzeug.utils import secure_filename
from modelPJ import User, Scan, Best_Practices, connect_to_db, db
import yara 


app = Flask(__name__)

# Required to use Flask sessions and the debug toolbar
app.secret_key = "NASC"

# Normally, if you use an undefined variable in Jinja2, it fails
# silently. This is horrible. Fix this so that, instead, it raises an
# error.
app.jinja_env.undefined = StrictUndefined
UPLOAD_FOLDER = 'fileexamples'
rules = yara.compile("mainrule.yara")
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


@app.route('/', methods=['GET'])
def index():
    """Homepage. That shows login form"""
    return render_template('homepage.html')

@app.route('/', methods=["POST"])
def process_login():

    username = request.form["username"]
    password = request.form["password"]

    user = User.query.filter_by(username=username).first()

    if not user:
        flash("Invaild user, Please Register an account")
        return redirect("/sign_up")

    if user.password != password:
        flash("Invaild password")
        return redirect("/")

    session["username"] = user.username

    flash("Successfully logged in")
    return redirect(f'/homepage')

@app.route("/sign_up", methods=['GET'])
def signup_form():
    """Show form to Register an Account"""

    return render_template('sign_upform.html')

@app.route("/sign_up", methods=['POST'])
def process_signup():
    """processes register"""
    fname= request.form["fname"]
    lname= request.form["lname"]
    email = request.form["email"]
    username = request.form["username"]
    password = request.form["password"]
    

    new_user = User(fname=fname, lname=lname, email=email, username=username, password=password)

    db.session.add(new_user)
    db.session.commit()

    flash(f"User {username} added.")

    session["username"] = new_user.username

    return redirect(f'/homepage')

@app.route("/homepage")
def home_NACS():
    """Offical homepage of the user"""
    #user= User.query

    scan_info = User.query(User.user_id, Scan.scan_type, Scan.scan_date, Scan.scan_findings).join(Scan).all()

    return render_template("user_home.html", scan_info= scan_info)

@app.route("/scan_files", methods =["GET"])
def scan_files():
    """User uploads files, scan them, get results"""

    return render_template("scan_files.html")

@app.route("/upload", methods=['POST'])
def upload_file():
    """Allows user to upload files"""

    file = request.files['file']
    filename = secure_filename(file.filename)
    #file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    filepath = (os.path.join(app.config['UPLOAD_FOLDER'], filename))

    scan_type= "File Scan"
    user_id = user.user_id
    scan_date = datetime.now

    match = rules.match(filepath)
 

    if match:
        findings = (f"[!] Malicious Code found, Delete {filename} asap to protect machine!")
        scan = Scan(findings=findings, scan_type=scan_type, scan_date=scan_date,
        user_id=user_id)
    
        db.session.add(scan)
        db.session.commit()
        return render_template("malfile.html")

    else:
        findings = (f"[!] No Malicious Code found in {filename}, Your Safe!")
        scan = Scan(findings=findings, scan_type=scan_type, scan_date=scan_date,
        user_id=user_id)
    
        db.session.add(scan)
        db.session.commit()
        return render_template("nonmalfile.html")




@app.route("/scan_url")
def scan_url():
    #username = request.get.arg("username")

    return render_template("scan_url.html")


@app.route("/best_practices")
def best_practices():
    #username = request.get.arg("username")
    """list the best practices for cyber security at home"""

    tips = Best_Practices.query.all()

    return render_template("best_practices.html", tips=tips)

@app.route("/logout")
def logout():
    """user logs out"""

    del session["username"]
    flash("Successful Log Out.")
    
    return redirect("/")


if __name__ == "__main__":
    # We have to set debug=True here, since it has to be True at the
    # point that we invoke the DebugToolbarExtension
    app.debug = True
    # make sure templates, etc. are not cached in debug mode
    app.jinja_env.auto_reload = app.debug

    connect_to_db(app)
   


    # Use the DebugToolbar
    #DebugToolbarExtension(app)

    app.run(port=5000, host='0.0.0.0')