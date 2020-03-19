from jinja2 import StrictUndefined
import os
from flask import Flask, render_template, redirect, request, flash, session

#from flask_debugtoolbar import DebugToolbarExtension
from werkzeug.utils import secure_filename
from modelPJ import User, Scan, Best_Practices,connect_to_db, db
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
       
        #title.remove(1)


        
        paragraphs = row[1:]
        paragraphs = ' '.join(paragraphs)
        #print(paragraphs)
        paragraphs = paragraphs.strip("': ['")
        paragraphs = paragraphs.strip("']}")
        paragraphs = paragraphs.strip("]}")
        paragraphs = paragraphs.strip()
        #paragraphs = paragraphs.strip("]")

        paragraph.append(paragraphs)

        #print(f"this is a new {row}")
        #if counter > (row):
            #counter += 1
    #print(f'titles are {title} ') 

    #print(f'---->>>>> paragraph is {paragraph}')
    tips = {title[i]: paragraph[i] for i in range(len(title))}

    for key, val in tips.items():
        if key != None and val != None:
             tip_title = key
             tip_paragraph = val
             new_tip = Best_Practices(tip_title=tip_title, tip_paragraph=tip_paragraph)
             db.session.add(new_tip)
             db.session.commit()
        


        

            

        #title = Best_Practices(tip_tilte=title,
                    #tip_paragraph=paragraph)

        # We need to add to the session or it won't ever be stored
        #db.session.add(title)

    # Once we're done, we should commit our work
    #db.session.commit()



if __name__ == "__main__":
    connect_to_db(app)

    # # # In case tables haven't been created, create them
    db.drop_all()
    db.create_all()

    # Import different types of data
    load_BP()
   
  