# app.py
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from db import engine
from sqlalchemy import create_engine, text,URL
import os
from dotenv import load_dotenv
from llm_chain import get_sql_for_question, llm
load_dotenv()
#from llm_chain import get_sql_for_question, llm  # functions for LLM processing
# If using a user database model:
# from models import init_db, User


app = Flask(__name__)
#app.secret_key = "sree@1234567890"  # set a secure secret key for session signing
os.environ["APP_SECRET_KEY"]=os.getenv("APP_SECRET_KEY")
app.config['SECRET_KEY'] = os.environ['APP_SECRET_KEY']

# If using SQLAlchemy ORM for user auth (optional):
# init_db()  # create tables if not exists


# Simple in-memory user store for demonstration (username -> password_hash)
users = {"salesuser"}

@app.route('/')
def welcome():
    return "welcome to nlp-sql app"

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Basic checks
        if not username or not password:
            flash("Username and password are required", "warning")
            return render_template('register.html')
        if username in users:
            flash("Username already exists", "danger")
            return render_template('register.html')
        # Save the new user with hashed password
        users[username] = generate_password_hash(password)
        flash("Registration successful! Please log in.", "success")
        #return redirect(url_for('login'))
    return render_template('register.html')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Verify credentials
        if username in users:# and check_password_hash(users[username], password):
            session.clear()  # clear any previous session data
            session['username'] = username
            session['history'] = []  # initialize an empty chat history for the user
            flash(f"Welcome, {username}!", "info")
            return redirect(url_for('chat'))
        flash("Invalid username or password", "danger")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for('login'))

# app.py (continued)

# app.py (continued)

import re

def validate_sql(query):
    """Basic validation to allow only read-only SELECT queries."""
    # Disallow dangerous keywords or multiple statements
    forbidden = [";", "DROP", "ALTER", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "CREATE"]
    for word in forbidden:
        if re.search(rf"\b{word}\b", query, flags=re.IGNORECASE):
            return False
    # Only allow queries that start with SELECT or WITH (for CTEs) 
    stripped = query.strip().lower()
    if not (stripped.startswith("select") or stripped.startswith("with")):
        return False
    return True

def format_result(results_list):
    """Format query results as a string (markdown table or text)."""
    if not results_list:
        return "_(No results)_"
    # If it's a single value result, just return it
    if len(results_list) == 1 and len(results_list[0]) == 1:
        # return the single value
        return str(list(results_list[0].values())[0])
    # Otherwise, format as a table (markdown)
    headers = results_list[0].keys()
    # header row
    table = " | ".join(headers) + "\n"
    table += " | ".join("---" for _ in headers) + "\n"
    for row in results_list:
        row_vals = [str(v) for v in row.values()]
        table += " | ".join(row_vals) + "\n"
    return table


from datetime import datetime

@app.route('/chat', methods=['GET', 'POST'])
def chat():
    # Require login
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']

    if request.method == 'POST':
        user_query = request.form.get('query', '').strip()
        if user_query:
            # Append the user's query to history
            session['history'].append({"role": "user", "content": user_query, "time": datetime.now()})
            try:
                # Use LangChain/GPT-4 to get an SQL query for the user's question
                sql_query = get_sql_for_question(user_query, session['history'])
            except Exception as e:
                # Handle errors from the LLM (e.g., API errors)
                error_msg = f"LLM Error: {str(e)}"
                session['history'].append({"role": "assistant", "content": error_msg, "error": True})
                return render_template('chat.html', history=session['history'])
            # Validate the generated SQL for safety
            safe = validate_sql(sql_query)
            if not safe:
                # If validation fails (e.g., a disallowed operation), do not execute
                session['history'].append({
                    "role": "assistant",
                    "content": "⚠️ The generated SQL query was deemed unsafe and was not executed.",
                    "error": True
                })
            else:
                # Attempt to execute the SQL query against the database
                try:
                    with engine.connect() as conn:
                        result = conn.execute(text(sql_query))
                        print('coming n ')
                        rows = result.fetchall()
                        # Convert result rows to list of dicts for display (or any suitable format)
                        columns = result.keys()
                        results_list = [dict(zip(columns, row)) for row in rows]
                        output = format_result(results_list)
                        print(output)
                except Exception as e:
                    output = f"⚠️ SQL Execution Error: {str(e)}"
                # Append assistant response with the SQL and the output
            session['history'].append({
                    "role": "assistant",
                    "sql": sql_query,
                    "content": output,
                    "error": False
                })
        # After processing POST, redirect to GET (Post/Redirect/Get pattern) to avoid form re-submission
        #return redirect(url_for('chat'))

    # GET request – just render the chat interface with current history
    return render_template('chat.html', history=session.get('history', []), username=username)

if __name__=="__main__":
    app.run(debug=True)
