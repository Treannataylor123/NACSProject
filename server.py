from jinja2 import StrictUndefined
import os
import json
from flask_sqlalchemy import SQLAlchemy
from pprint import pformat
from datetime import datetime
from flask import Flask, render_template, redirect, request, flash, session
import requests
import urllib
import urllib3
import re
import httplib2
from pysafebrowsing import SafeBrowsing
#from flask_debugtoolbar import DebugToolbarExtension
from werkzeug.utils import secure_filename
from modelPJ import User, Scan, Best_Practices, Top_Threats, connect_to_db, db
import yara 


app = Flask(__name__)

# Required to use Flask sessions and the debug toolbar
app.secret_key = "NACS"

# Normally, if you use an undefined variable in Jinja2, it fails
# silently. This is horrible. Fix this so that, instead, it raises an
# error.

app.jinja_env.undefined = StrictUndefined
UPLOAD_FOLDER = 'fileexamples'
rules = yara.compile("mainrule.yara")
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
API_KEY = os.environ["SAFEBROWSE_KEY"]


@app.route('/', methods=['GET'])
def index():
    """Offical Homepage. That shows login form and registeration link"""
    return render_template('homepage.html')

@app.route('/', methods=["POST"])
def process_login():
    """processes login"""

    username = request.form["username"]
    password = request.form["password"]

    user = User.query.filter_by(username=username).first()

    if not user:
        flash("Invaild user, Please Register an account")
        return redirect("/sign_up")

    if user.password != password:
        flash("Invaild password")
        return redirect("/")

    else:
        session["username"] = user.username
        session["user_id"] = user.user_id
        flash("Successfully logged in")
        #return redirect(f'/homepage')
        return redirect(f'/homepage/{user.user_id}')

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
    session["user_id"] = new_user.user_id

    #return redirect(f"/homepage")
    return redirect(f"/homepage/{new_user.user_id}")


#@app.route("/homepage/")
@app.route("/homepage/<int:user_id>")
def user_home(user_id):
    """displays Offical homepage of the user including previous scans"""
    username = session["username"]
    #user = User.query.all()
    #scans = Scan.query.all()
    #user_id = session["user_id"]

    #uid = Scan.query.filter_by(user_id=user_id).first()
    uid = user_id

    #if user_id == scan_user: 
    scan_info = Scan.query.filter_by(user_id=user_id).all()
    return render_template("user_home.html", username=username, scan_info=scan_info, user_id=user_id, uid=uid)
    #else:
        #return render_template("user_home.html", username = username )


@app.route("/scan_files", methods =["GET"])
def scan_files():
    """display file upload form"""
    user_id = session["user_id"]

    return render_template("scan_files.html", user_id=user_id)

@app.route("/upload", methods=['POST'])
def upload_file():
    """preforms file scan"""

    file = request.files['file']
    filename = secure_filename(file.filename)
    #file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    filepath = (os.path.join(app.config['UPLOAD_FOLDER'], filename))

    scan_type= "File Scan"
    user_id = session['user_id']
    scan_date = datetime.now()

    match = rules.match(filepath)

    

    if match :
        findings = (f"[!] Malicious Code found, Delete {filename} asap to protect machine!")

        scan = Scan(findings=findings, scan_type=scan_type, scan_date=scan_date, user_id=user_id)
    
        db.session.add(scan)
        db.session.commit()

        return render_template("malfile.html", filename=filename, scan_type=scan_type, user_id=user_id)

    else:

        findings = (f"[!] No Malicious Code found in {filename}, Your Safe!")
        scan = Scan(findings=findings, scan_type=scan_type, scan_date=scan_date,
        user_id=user_id)

        db.session.add(scan)
        db.session.commit()

     
        return render_template("nonmalfile.html", filename=filename, scan_type=scan_type, user_id=user_id)

@app.route("/scan_url")
def scan_url():
    """display url form"""
    user_id = session["user_id"]
    
    return render_template("scan_url.html", user_id=user_id)

@app.route("/url_scan", methods=['POST'])
def url_scan():
    """"preforms scan for url"""
    web_url = request.form['url']
    search = SafeBrowsing(API_KEY)
    #web_url = urllib.request.urlopen(web_url)
    #web_url = requests.get(web_url).json
    res = search.lookup_urls([web_url])
    scan_type= "Url Scan"
    user_id = session['user_id']
    scan_date = datetime.now()
    is_mal = []


    for key, val in res.items():
        urls = key
        results = val
    for t, threat in results.items():
        if t == 'threats':
            threat_type = threat
        if t == 'malicious':
            is_mal = threat
        if t == 'platforms':
            platforms = threat

    #is_mal = "".join(is_mal)


    if is_mal == False:
        finding = (f'[!] The following {urls} is {is_mal} of Malicious code.')
        
        new_scan = Scan(findings=findings, scan_type=scan_type, scan_date=scan_date, user_id=user_id)
        
        db.session.add(new_scan)
        db.session.commit()

    
        return render_template("nonmalfile.html", web_url= web_url, scan_type=scan_type, user_id=user_id, is_mal=is_mal)

    if is_mal == True:

        findings= (f'[!] The following {urls} is {is_mal} of Malicious code. Threat Type: {threat_type}!')
        
        new_scan = Scan(findings=findings, scan_type=scan_type, scan_date=scan_date, user_id=user_id)
        
        db.session.add(new_scan)
        db.session.commit()
  
        return render_template("malfile.html", web_url=web_url, scan_type=scan_type, user_id=user_id)

        #return redirect("/")


@app.route("/best_practices")
def best_practices():
    """displau list ofbest practices for cyber security at home"""

    tips = Best_Practices.query.all()
    user_id = session["user_id"]
    

    return render_template("best_practices.html", tips=tips, user_id=user_id)

@app.route("/top_threats")
def top_threats():
    """display the top threats for Mac and Windows OS"""
    threats = Top_Threats.query.all()
    user_id = session["user_id"]

    

    return render_template("topthreats.html", threats=threats, user_id= user_id)

@app.route("/logout")
def logout():
    """user logs out"""

    del session["username"]
    del session["user_id"]
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