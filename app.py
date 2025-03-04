from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
import bcrypt
from TechBot.config import get_db_connection  # Import your existing database connection function
from psycopg2.extras import RealDictCursor
from datetime import datetime
import smtplib
import random
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SMTP_USERNAME = 'your-emailID'  # Replace with your email
SMTP_PASSWORD = 'your-app-password'  # Use an app-specific password if using Gmail

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with your generated secure key
load_dotenv()


# Utility function to send email
def send_email(to_email, otp):
    try:
        flash('Attempting Sending email','error')
        msg = MIMEMultipart()
        msg['From'] = SMTP_USERNAME
        msg['To'] = to_email
        msg['Subject'] = 'Verification of TechBot'

        body = f'Your OTP code is {otp}'
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        text = msg.as_string()
        server.sendmail(SMTP_USERNAME, to_email, text)
        server.quit()
        flash('Successfully sent','success')
    except Exception as e:
        print(f'Error sending email: {str(e)}')

# Route for signup page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        connection = get_db_connection()
        cursor = connection.cursor()
        
        try:
            cursor.execute(
                "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                (username, email, hashed_password)
            )
            connection.commit()
            flash('Signup successful!', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            connection.rollback()
            flash(f'Signup failed: {str(e)}', 'error')
        finally:
            cursor.close()
            connection.close()

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Please provide both username and password.', 'error')
            return redirect(url_for('login'))

        connection = get_db_connection()
        cursor = connection.cursor()

        # Fetch user details including id, email, and hashed password
        cursor.execute("SELECT user_id, email, password FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        # Check if user exists and password matches
        if user and bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
            session['logged_in'] = True
            session['user_id'] = user[0]  # Store user_id in the session
            session['email'] = user[1]
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Login failed: Incorrect username or password.', 'error')

        cursor.close()
        connection.close()

    return render_template('login.html')

# Route to display the profile page
@app.route('/profile')
def profile():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    email = session.get('email')
    username = session.get('username')
    return render_template('profile.html', email=email, username=username)

# Route to handle logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# Main route to display the index page
@app.route('/')
def index():
    return render_template('index.html')  # Renders the index file provided by you

@app.route('/review_code', methods=['POST'])
def review_code():
    # Check if the user is authenticated
    if not session.get('logged_in'):
        return jsonify({'error': 'User not authenticated'}), 401

    # Get the code name or user query from the request
    code_name = request.json.get('code_name')

    if not code_name:
        return jsonify({'error': 'No code name provided'}), 400

    connection = get_db_connection()
    cursor = connection.cursor(cursor_factory=RealDictCursor)

    try:
        # Check if code exists in the database
        cursor.execute("SELECT correct_code FROM codes WHERE code_name = %s", (code_name,))
        result = cursor.fetchone()

        if result:
            # If code exists, use it as the bot response
            bot_message = result['correct_code']
        else:
            # Call the Gemini API to generate a response
            chat_session = model.start_chat(history=[])
            response = chat_session.send_message(code_name)

            # Use the API response as the bot message
            bot_message = response.text

            # Add the code name to the requested codes table if it doesn't exist
            cursor.execute("INSERT INTO requested_codes (code_name) VALUES (%s)", (code_name,))
            connection.commit()

        # Save the interaction to the chat_history table
        insert_query = """
        INSERT INTO chat_history (code_name, user_message, bot_message, timestamp, user_id)
        VALUES (%s, %s, %s, %s, %s)
        RETURNING id;
        """
        cursor.execute(insert_query, (code_name, code_name, bot_message, datetime.now(), session['user_id']))
        chat_id = cursor.fetchone()['id']
        connection.commit()

        # Return the bot response
        return jsonify({'correct_code': bot_message, 'chat_id': chat_id})

    except Exception as e:
        print(f"Error occurred during query execution: {str(e)}")
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500
    finally:
        cursor.close()
        connection.close()

@app.route('/get_user_info', methods=['GET'])
def get_user_info():
    # Get user_id from the session
    user_id = session.get('user_id')

    if not user_id:
        return jsonify({"error": "User not logged in"}), 401

    try:
        # Connect to the database
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        # Fetch chat history for the user
        query = """
        SELECT id, code_name, user_message, bot_message, timestamp
        FROM chat_history
        WHERE user_id = %s
        ORDER BY timestamp DESC
        """
        cursor.execute(query, (user_id,))
        chat_history = cursor.fetchall()

        # Close the database connection
        cursor.close()
        conn.close()

        # Construct the response data
        response_data = {
            "user_name": session.get('username'),  # Fetch username from session
            "chat_history": chat_history
        }

        return jsonify(response_data)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    
@app.route('/get_chat/<int:chat_id>', methods=['GET'])
def get_chat(chat_id):
    # Get user_id from the session to ensure the user is authenticated
    user_id = session.get('user_id')

    if not user_id:
        return jsonify({"error": "User not logged in"}), 401

    try:
        # Connect to the database
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        # Fetch messages for the given chat_id
        query = """
        SELECT user_message, bot_message, timestamp
        FROM chat_history
        WHERE id = %s AND user_id = %s
        ORDER BY timestamp ASC
        """
        cursor.execute(query, (chat_id, user_id))
        messages = cursor.fetchall()

        # Close the database connection
        cursor.close()
        conn.close()

        # Construct response format
        response_data = {
            "messages": []
        }

        # Add each message to the response
        for msg in messages:
            response_data["messages"].append({
                "sender": "user",
                "content": msg['user_message']
            })
            response_data["messages"].append({
                "sender": "bot",
                "content": msg['bot_message'],
                "is_code": '```' in msg['bot_message']  # Simple check for code blocks
            })

        return jsonify(response_data)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Route to capture user messages
@app.route('/get_code', methods=['POST'])
def get_code():
    user_input = request.form.get('message')
    if not user_input:
        flash('No message provided!', 'error')
        return redirect(url_for('index'))

    connection = get_db_connection()
    cursor = connection.cursor(cursor_factory=RealDictCursor)

    try:
        cursor.execute("SELECT correct_code FROM codes WHERE code_name = %s", (user_input,))
        result = cursor.fetchone()

        if result:
            correct_code = result['correct_code']
            print(f"Fetched Code: {correct_code}")
            flash(f'Correct Code: {correct_code}', 'success')
        else:
            flash('No matching code found for the provided name. It has been added to the requests list.', 'error')
            cursor.execute("INSERT INTO requested_codes (code_name) VALUES (%s)", (user_input,))
            connection.commit()

    except Exception as e:
        connection.rollback()
        error_message = str(e)
        print(f"Error retrieving code: {error_message}")
        flash(f'An unexpected error occurred: {error_message}', 'error')
    finally:
        cursor.close()
        connection.close()

    return redirect(url_for('index'))

# Route for the Forgot Password page
@app.route('/forgotpassword', methods=['GET', 'POST'])
def forgotpassword():
    return render_template('forgotpassword.html')

# Route to send OTP to the user's email
@app.route('/send_otp', methods=['POST'])
def send_otp():
    email = request.form['email']
    
    if not email:
        flash('Please provide an email.', 'error')
        return redirect(url_for('forgotpassword'))

    otp = ''.join(random.choices('0123456789', k=4))  # Generate a 4-digit OTP
    
    connection = get_db_connection()
    cursor = connection.cursor()
    
    try:
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        
        if not user:
            flash('No account found with this email.', 'error')
            return redirect(url_for('forgotpassword'))

        cursor.execute("UPDATE users SET otp = %s WHERE email = %s", (otp, email))
        connection.commit()

        send_email(email, otp)
        flash('OTP sent to your email. Please check your inbox.', 'success')
    except Exception as e:
        connection.rollback()
        flash(f'Error: {str(e)}', 'error')
    finally:
        cursor.close()
        connection.close()

    return redirect(url_for('forgotpassword'))

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    email = request.form['email']
    otp_input = request.form['otp']

    if not email or not otp_input:
        flash('Please provide email and OTP.', 'error')
        return redirect(url_for('forgotpassword'))

    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute("SELECT otp FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user and user[0] == otp_input:
            flash('OTP verified successfully. You can reset your password now.', 'success')
            return redirect(url_for('reset_password', email=email))
        else:
            flash('Invalid OTP. Please try again.', 'error')
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
    finally:
        cursor.close()
        connection.close()

    return redirect(url_for('forgotpassword'))

# Route to render the reset password page
@app.route('/resetpassword', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('reset_password', email=email))

        encrypted_password = bcrypt.hashpw(confirm_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        connection = get_db_connection()
        cursor = connection.cursor()

        try:
            cursor.execute("UPDATE users SET password = %s WHERE email = %s", (encrypted_password, email))
            connection.commit()
            flash('Password updated successfully.', 'success')
        except Exception as e:
            connection.rollback()
            flash(f'Error: {str(e)}', 'error')
        finally:
            cursor.close()
            connection.close()

        return redirect(url_for('login'))

    email = request.args.get('email')
    return render_template('resetpassword.html', email=email) 

# Main entry point
if __name__ == '__main__':
    app.run(debug=True)