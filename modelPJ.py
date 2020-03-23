from flask_sqlalchemy import SQLAlchemy




db = SQLAlchemy()

class User(db.Model):

    __tablename__ = "users"

    user_id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    fname = db.Column(db.String(64), nullable=False)
    lname = db.Column(db.String(64), nullable=False)
    email = db.Column(db.String(64), nullable=False)
    username = db.Column(db.String(64), unique= True, nullable=False)
    password = db.Column(db.String(64), nullable=False)

class Scan(db.Model):
    
    __tablename__ = "scans"


    scan_id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    scan_type = db.Column(db.String(100), nullable=True)
    findings = db.Column(db.String(225), nullable=True)
    scan_date = db.Column(db.DateTime, nullable=False)

class Best_Practices(db.Model):

    __tablename__ = "best_practices"


    tip_id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    tip_title = db.Column(db.String(225), nullable=False)
    tip_paragraph = db.Column(db.String(1000), nullable=False)


def connect_to_db(app):
    """Connect the database to our Flask app."""

    # Configure to use our PstgreSQL database
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql:///NACSdb'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.app = app
    db.init_app(app)


if __name__ == "__main__":
    # As a convenience, if we run this module interactively, it will leave
    # you in a state of being able to work with the database directly.

    from server import app
    connect_to_db(app)
    print("Connected to NACS DB.")




  