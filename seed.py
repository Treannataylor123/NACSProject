from jinja2 import StrictUndefined
import os
from flask import Flask, render_template, redirect, request, flash, session
from datetime import datetime
#from flask_debugtoolbar import DebugToolbarExtension
from werkzeug.utils import secure_filename
from modelPJ import User, Scan, Top_tools, Top_Threats, Best_Practices,connect_to_db, db
import yara 


app = Flask(__name__)

# Required to use Flask sessions and the debug toolbar
app.secret_key = "NASC"

# Normally, if you use an undefined variable in Jinja2, it fails
# silently. This is horrible. Fix this so that, instead, it raises an
# error.
app.jinja_env.undefined = StrictUndefined


def load_BP():
    """Load titles and paragraphs from practices into database."""

   
    file = open("bestpractices.txt")
    counter = 0
    title = []
    paragraph = []
    tips = {}

    for row in file:
        
        
        #row = row.strip("{][':")
        row = row.split('paragraphs')
        titles = row[counter]
        titles = titles.strip("], '\n")
        titles = titles.strip("{titles': [")
        
        title.append(titles)
       


        
        paragraphs = row[1:]
        paragraphs = ' '.join(paragraphs)
    
        paragraphs = paragraphs.strip("': ['")
        paragraphs = paragraphs.strip("']}")
        paragraphs = paragraphs.strip("]}")
        paragraphs = paragraphs.strip()
       

        paragraph.append(paragraphs)

 
    tips = {title[i]: paragraph[i] for i in range(len(title))}

    for key, val in tips.items():
        if key != None or val != None:
             tip_title = key
             tip_paragraph = val
             new_tip = Best_Practices(tip_title=tip_title, tip_paragraph=tip_paragraph)
             db.session.add(new_tip)
             db.session.commit()

def load_threats():
    """loadind the top malware threats into Top_Threats DB"""
    file = open("blacklist.txt")
    i = 0

    for row in file: 
        row = row.strip("  '  '  ' '")
        row = row.split("': '")
        threat_title = row[0]
        threat_paragraph = row[1: ]
        threat_paragraph = "".join(threat_paragraph).rstrip()
        print(threat_paragraph)

        if i < 10:
            threat_os = "Windows"
           
        else:
            threat_os = "Mac iOS"
            

        new_threat = Top_Threats(threat_title=threat_title, threat_paragraph=threat_paragraph, threat_os=threat_os)
        db.session.add(new_threat)
        db.session.commit()
        i += 1
def load_tools():
    file = open("recommend.txt")

    for row in file:

        row = row.rstrip()

        # parse the line futher by spliting the line by fields/catagory
        tool_type, tool_title, tool_url, tool_features, tool_price = row.split("|")

        new_tool = Top_tools(tool_type=tool_type, tool_title=tool_title, tool_url=tool_url, tool_features=tool_features, 
                tool_price=tool_price)

        db.session.add(new_tool)
        db.session.commit()


if __name__ == "__main__":
    connect_to_db(app)

    # # # In case tables haven't been created, create them
    db.drop_all()
    db.create_all()

    # Import different types of data
    load_BP()
    load_threats()
    load_tools()
   
  