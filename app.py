from flask import Flask, render_template, request, redirect, flash, session, url_for, jsonify, make_response, abort
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import secrets
import mysql.connector
import plotly.colors as pc
import pandas as pd
import plotly.express as px
import plotly.io as pio
import datetime
import io
import re
import random
import hashlib
import time
from dotenv import dotenv_values

app = Flask(__name__)

app.secret_key = secrets.token_hex(16)

config = dotenv_values("key.env")

# Load credentials from .env file
EMAIL_CONFIG = {
    "email": config["EMAIL_USER"],
    "password": config["EMAIL_PASS"]
}

DB_CONFIG = {
    "host": config["DB_HOST"],
    "user": config["DB_USER"],
    "password": config["DB_PASS"],
    "database": config["DB_NAME"],
    "port": int(config["DB_PORT"])
}

# Database Connection Function
def connect_db():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except mysql.connector.Error as err:
        print(f"Database connection error: {err}")
        return None



def send_otp_email(user_email, otp):
    sender_email = EMAIL_CONFIG["email"]
    sender_password = EMAIL_CONFIG["password"]

    subject = "Your One-Time Password (OTP)"
    body = f"Your OTP for login is: {otp}\n\nDo not share this OTP with anyone."

    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = user_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, user_email, msg.as_string())
        return True
    except Exception as e:
        print(f"Error sending OTP: {e}")
        return False


@app.route('/send_otp', methods=['POST'])
def send_otp():
    data = request.get_json()
    email = data.get("email")

    if not email:
        return jsonify({"success": False, "message": "Email is required!"}), 400
    email = email.lower()

    # Check if user is already registered
    with connect_db() as db:
        cursor = db.cursor()
        cursor.execute("SELECT mail_id FROM user_pass WHERE mail_id = %s", (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            return jsonify({"success": False, "message": "You are already registered! Please log in."})

    # Generate and store OTP
    otp = str(random.randint(100000, 999999))
    session['otp'] = hashlib.sha256(otp.encode()).hexdigest()  # Hash the OTP for security
    session['email'] = email
    session['otp_time'] = time.time()

    # Send OTP email
    if send_otp_email(email, otp):  # Replace with your email function
        return jsonify({"success": True, "message": "OTP sent successfully!"})

    return jsonify({"success": False, "message": "Failed to send OTP!"}), 500



@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()

        with connect_db() as db:
            cursor = db.cursor()
            cursor.execute("SELECT mail_id FROM user_pass WHERE mail_id = %s", (email,))
            if not cursor.fetchone():
                flash("Email not found!", "error")
                return redirect(url_for('forgot_password'))

        otp = str(random.randint(100000, 999999))
        session['otp'] = hashlib.sha256(otp.encode()).hexdigest()
        session['reset_email'] = email
        session['otp_time'] = time.time()

        if send_otp_email(email, otp):
            flash("OTP sent successfully!", "success")
            return redirect(url_for('verify_otp'))
        flash("Failed to send OTP. Please try again.", "error")

    return render_template('forgot_password.html')


@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'reset_email' not in session or 'otp' not in session:
        return redirect(url_for('forgot_password'))

    if time.time() - session.get('otp_time', 0) > 300:
        session.clear()
        flash("OTP expired! Please request a new one.", "error")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        entered_otp = hashlib.sha256(request.form['otp'].encode()).hexdigest()

        if session['otp'] == entered_otp:
            session['verified_email'] = session.pop('reset_email')
            return redirect(url_for('reset_password'))
        flash("Invalid OTP. Please try again.", "error")

    return render_template('verify_otp.html')


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if 'verified_email' not in session:
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if len(new_password) < 8 or not re.search(r'[A-Z]', new_password) or not re.search(r'\d', new_password):
            flash("Password must be at least 8 characters long, contain one uppercase letter and one number.", "error")
            return render_template('reset_password.html')

        if new_password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template('reset_password.html')

        email = session.pop('verified_email')
        password = new_password

        with connect_db() as db:
            cursor = db.cursor()
            cursor.execute("UPDATE user_pass SET password = %s WHERE mail_id = %s", (password, email))
            db.commit()

        flash("Password reset successfully!", "success")
        return redirect(url_for('home'))

    return render_template('reset_password.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user_name = request.form['user_name'].strip().capitalize()
        password = request.form['password']
        mail_id = request.form['mail_id'].lower()

        with connect_db() as db:
            cursor = db.cursor()

            # Check if email is already registered
            cursor.execute("SELECT mail_id FROM user_pass WHERE mail_id = %s", (mail_id,))
            existing_user = cursor.fetchone()
            if existing_user:
                flash("You are already registered! Please log in.", 'error')
                return redirect(url_for('register'))

            # Insert new user
            cursor.execute("INSERT INTO user_pass (user_name, password, mail_id) VALUES (%s, %s, %s)",
                           (user_name, password, mail_id))
            db.commit()

        flash("Registration successful! Please login.", 'success')
        return redirect(url_for('home'))

    return render_template('register.html')


@app.route('/check_email', methods=['POST'])
def check_email():
    data = request.get_json()
    mail_id = data.get('email').lower()

    with connect_db() as db:
        cursor = db.cursor()
        cursor.execute("SELECT mail_id FROM user_pass WHERE mail_id = %s", (mail_id,))
        exists = cursor.fetchone() is not None

    return jsonify({"exists": exists})

# Routes
@app.route('/', methods=['POST', "GET"])
def home():
    if request.method == 'POST':
        mail_id = request.form.get('mail_id', '').strip().lower()
        password = request.form.get('password', '').strip()

        conn = connect_db()
        if conn:
            with conn.cursor(dictionary=True) as cursor:
                cursor.execute("SELECT mail_id, password, user_name, user_type FROM user_pass WHERE mail_id = %s;", (mail_id,))
                user = cursor.fetchone()
            conn.close()

            if user and user['password'] == password:
                session['mail_id'] = mail_id
                session['user_name'] = user['user_name']
                session["user_type"] = user["user_type"]
                session["user_name"] = session["user_name"]

                flash("Login Successful!", 'success')
                return redirect(url_for('home_route'))  # Corrected redirect
            else:
                flash("Invalid credentials, try again.", 'error')
                return redirect(url_for('wrong_page'))
    return render_template('login.html')

@app.route('/wrong')
def wrong_page():
    return render_template('wrong_id_pass.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    return render_template('login.html')


menu_items_1 = [  # Admin menu
    {"link": "agent_dashboard", "icon": "bx-home-circle", "name": "Dashboard"},  # Home-style dashboard
    {"link": "show_data", "icon": "bx-show", "name": "Show Data"},  # Eye icon for visibility
    {"link": "owner_insert", "icon": "bx-user-plus", "name": "Owner Insert"},  # User add icon
    {"link": "invoice_download", "icon": "bx-download", "name": "Invoice Download"},  # Download icon
    {"link": "bill", "icon": "bx-receipt", "name": "Bill"},  # Receipt icon
    {"link": "due_service", "icon": "bx-time", "name": "Due Service Report"},  # Clock for due service
    {"link": "logout", "icon": "bx-power-off", "name": "Logout"},  # Power-off icon for logout
]

menu_items_2 = [  # Regular user menu
    {"link": "agent_dashboard", "icon": "bx-home-circle", "name": "Dashboard"},
    {"link": "show_data", "icon": "bx-show", "name": "Show Data"},
    {"link": "invoice_download", "icon": "bx-download", "name": "Invoice Download"},
    {"link": "due_service", "icon": "bx-time", "name": "Due Service Report"},
    {"link": "logout", "icon": "bx-power-off", "name": "Logout"},
]

@app.route("/home")
def home_route():
    if 'mail_id' not in session:
        return redirect(url_for('login'))

    user_name = session.get('user_name')
    user_type = session.get('user_type')
    menu_items = menu_items_1 if user_type == 'admin' else menu_items_2

    return render_template("home.html", menu_items=menu_items, active_page="home", user_name=user_name)


@app.route("/<page>")
def page(page):
    if 'mail_id' not in session:
        return redirect(url_for('login'))

    user_type = session.get('user_type')
    menu_items = menu_items_1 if user_type == 'admin' else menu_items_2

    if page in [item['link'] for item in menu_items]:
        return render_template(f"{page}.html", menu_items=menu_items, active_page=page)
    return abort(404)

@app.route('/welcome')
def welcome():
    if 'mail_id' not in session:
        return redirect(url_for('home'))
    return render_template("welcome.html")

# Owner Insert Routes
@app.route('/owner_insert', methods=['GET', 'POST'])
def owner_insert():
    cars = get_cars()
    if request.method == 'POST':
        car_no = request.form.get('car_no')
        mobile_no = request.form.get('mobile_no')
        car_status = request.form.get('car_status')
        driver_name = request.form.get('driver_name')

        if car_no and mobile_no and car_status:
            try:
                conn = connect_db()
                if conn:
                    with conn.cursor() as cursor:
                        cursor.execute("INSERT INTO owner_insert (car_no, mobile_no, car_status, driver_name) VALUES (%s, %s, %s, %s)", (car_no, mobile_no, car_status, driver_name))
                        conn.commit()
                    conn.close()
                    flash("Car added successfully!", 'success')
            except mysql.connector.IntegrityError:
                flash("Car number already exists!", 'error')
            except Exception as e:
                e_owner = e
                flash(f"An error occurred: {e_owner}", 'error')
        else:
            flash("All fields are required!", 'warning')

        return redirect(url_for('owner_insert'))

    return render_template('owner_insert.html', cars=cars)


@app.route('/cars', methods=['GET'])
def get_cars():
    car_no = request.args.get('car_no')  # Get car_no from request parameters
    if not car_no:
        return []  # Return an empty list instead of jsonify([])

    conn = connect_db()
    if conn:
        with conn.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT * FROM owner_insert WHERE car_no = %s", (car_no,))
            cars = cursor.fetchall()
        conn.close()
        return cars  # Return the list directly (not jsonify)

    return []


@app.route('/show_data', methods=['GET', 'POST'])
def show_data():
    try:
        # Fetch data from the database
        with connect_db() as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT COALESCE(oi.car_status, 'Unknown') AS car_status, 
                           d.car_no, d.customer_name, d.order_id, d.car_name, 
                           d.city, d.phone_number, d.delivered_date, 
                           d.final_service, d.service_category 
                    FROM detail AS d 
                    LEFT JOIN owner_insert AS oi ON d.car_no = oi.car_no;
                """)
                data = cursor.fetchall()
                columns = [desc[0] for desc in cursor.description]

        # Handle case where no data is returned
        if not data:
            return render_template("show_data.html", data=[], cities=[], city_selected="",
                                   start_date_selected="", end_date_selected="", car_no_selected="",
                                   no_data=True, columns=columns)

        # Create DataFrame
        df = pd.DataFrame(data, columns=columns)
        df["delivered_date"] = pd.to_datetime(df["delivered_date"]).dt.date  # Convert to date only

        # Get filters from request
        city = request.args.get("city", "")
        start_date = request.args.get("start_date", "")
        end_date = request.args.get("end_date", "")
        car_no = request.args.get("car_no", "")

        # Apply filters
        if city and city.lower() != "all":
            df = df[df["city"] == city]

        if start_date and end_date:
            try:
                start_date_obj = datetime.datetime.strptime(start_date, "%Y-%m-%d").date()
                end_date_obj = datetime.datetime.strptime(end_date, "%Y-%m-%d").date()

                if start_date_obj > end_date_obj:
                    return render_template("show_data.html", error_message="Start date must be earlier than or equal to end date.",
                                           cities=df["city"].unique().tolist(), city_selected=city,
                                           start_date_selected=start_date, end_date_selected=end_date,
                                           car_no_selected=car_no, columns=columns, data=[])

                df = df[(df["delivered_date"] >= start_date_obj) & (df["delivered_date"] <= end_date_obj)]
            except ValueError:
                return render_template("show_data.html", error_message="Invalid date format. Use YYYY-MM-DD.",
                                       cities=df["city"].unique().tolist(), city_selected=city,
                                       start_date_selected=start_date, end_date_selected=end_date,
                                       car_no_selected=car_no, columns=columns, data=[])

        if car_no and car_no.lower() != "all":
            df = df[df["car_no"] == car_no]

        if df.empty:
            if start_date and end_date:
                error_message = f"No data found between {start_date} and {end_date}."
            else:
                error_message = "No data found for selected filters."
            return render_template("show_data.html", error_message=error_message, cities=[], city_selected=city,
                                   start_date_selected=start_date, end_date_selected=end_date,
                                   car_no_selected=car_no, columns=columns, data=[])

        cities = df["city"].unique().tolist()

        if request.method == 'POST':
            output = io.BytesIO()
            with pd.ExcelWriter(output, engine='openpyxl') as writer:
                df.to_excel(writer, index=False, sheet_name="Filtered Data")
            output.seek(0)

            response = make_response(output.getvalue())
            response.headers['Content-Disposition'] = f'attachment; filename=filtered_data_{datetime.datetime.now().strftime("%d%m%y")}.xlsx'
            response.headers['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            return response

        # Render the filtered data
        return render_template("show_data.html", data=df.to_dict(orient='records'), cities=cities, city_selected=city,
                               start_date_selected=start_date, end_date_selected=end_date,
                               car_no_selected=car_no, columns=columns)

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return render_template("show_data.html", error_message="An error occurred while fetching data.",
                               cities=[], city_selected="", start_date_selected="", end_date_selected="",
                               car_no_selected="", columns=[], data=[])


@app.route('/bill', methods=['GET', 'POST'])
def bill_data():
    try:
        # Fetch data from the database
        with connect_db() as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT COALESCE(oi.car_status, 'Unknown') AS car_status, 
                           d.car_no, d.customer_name, d.order_id, d.car_name, 
                           d.city, d.phone_number, d.delivered_date, 
                           d.final_service, d.service_category, d.discounted_charge, 
                           d.Revenue, d.gmv, d.additional_charge, d.discount
                    FROM detail AS d 
                    LEFT JOIN owner_insert AS oi ON d.car_no = oi.car_no;
                """)
                data = cursor.fetchall()
                columns = [desc[0] for desc in cursor.description]

        # Handle case where no data is returned
        if not data:
            return render_template("bill_data.html", data=[], cities=[], city_selected="",
                                   start_date_selected="", end_date_selected="", car_no_selected="",
                                   no_data=True, columns=columns)

        # Create DataFrame
        df = pd.DataFrame(data, columns=columns)
        df["delivered_date"] = pd.to_datetime(df["delivered_date"]).dt.date  # Convert to date only

        # Get filters from request
        city = request.args.get("city", "")
        start_date = request.args.get("start_date", "")
        end_date = request.args.get("end_date", "")
        car_no = request.args.get("car_no", "")

        # Apply filters
        if city and city.lower() != "all":
            df = df[df["city"] == city]

        if start_date and end_date:
            try:
                start_date_obj = datetime.datetime.strptime(start_date, "%Y-%m-%d").date()
                end_date_obj = datetime.datetime.strptime(end_date, "%Y-%m-%d").date()

                if start_date_obj > end_date_obj:
                    return render_template("bill_data.html", error_message="Start date must be earlier than or equal to end date.",
                                           cities=df["city"].unique().tolist(), city_selected=city,
                                           start_date_selected=start_date, end_date_selected=end_date,
                                           car_no_selected=car_no, columns=columns, data=[])

                df = df[(df["delivered_date"] >= start_date_obj) & (df["delivered_date"] <= end_date_obj)]
            except ValueError:
                return render_template("bill_data.html", error_message="Invalid date format. Use YYYY-MM-DD.",
                                       cities=df["city"].unique().tolist(), city_selected=city,
                                       start_date_selected=start_date, end_date_selected=end_date,
                                       car_no_selected=car_no, columns=columns, data=[])

        if car_no and car_no.lower() != "all":
            df = df[df["car_no"] == car_no]

        if df.empty:
            if start_date and end_date:
                error_message = f"No data found between {start_date} and {end_date}."
            else:
                error_message = "No data found for selected filters."
            return render_template("bill_data.html", error_message=error_message, cities=[], city_selected=city,
                                   start_date_selected=start_date, end_date_selected=end_date,
                                   car_no_selected=car_no, columns=columns, data=[])

        cities = df["city"].unique().tolist()

        if request.method == 'POST':
            output = io.BytesIO()
            with pd.ExcelWriter(output, engine='openpyxl') as writer:
                df.to_excel(writer, index=False, sheet_name="Filtered Data")
            output.seek(0)

            response = make_response(output.getvalue())
            response.headers['Content-Disposition'] = f'attachment; filename=filtered_data_{datetime.datetime.now().strftime("%d%m%y")}.xlsx'
            response.headers['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            return response

        # Render the filtered data
        return render_template("bill_data.html", data=df.to_dict(orient='records'), cities=cities, city_selected=city,
                               start_date_selected=start_date, end_date_selected=end_date,
                               car_no_selected=car_no, columns=columns)

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return render_template("bill_data.html", error_message="An error occurred while fetching data.",
                               cities=[], city_selected="", start_date_selected="", end_date_selected="",
                               car_no_selected="", columns=[], data=[])


@app.route("/invoice_download", methods=["GET", "POST"])
def download_invoice():
    search_query = request.form.get("search", "").strip()
    data_bill = []

    try:
        with connect_db() as conn:
            with conn.cursor() as cursor:
                query = """
                    SELECT COALESCE(oi.car_status, 'Unknown') AS car_status, 
                           d.car_no, d.customer_name, d.order_id, d.car_name, 
                           d.phone_number, d.delivered_date, d.final_service, d.invoice_link 
                    FROM detail AS d 
                    LEFT JOIN owner_insert AS oi ON d.car_no = oi.car_no
                """
                params = ()

                if search_query:
                    query += """
                        WHERE d.customer_name LIKE %s 
                           OR d.car_no LIKE %s 
                           OR d.order_id LIKE %s
                           OR d.phone_number LIKE %s
                    """
                    params = (f"%{search_query}%", f"%{search_query}%", f"%{search_query}%", f"%{search_query}%")

                query += " ORDER BY d.delivered_date DESC;"
                cursor.execute(query, params)
                rows = cursor.fetchall()

                # Convert to DataFrame with column names
                column_names = [
                    "car_status", "car_no", "customer_name", "order_id", "car_name",
                    "phone_number", "delivered_date", "final_service", "invoice_link"
                ]

                data_bill = pd.DataFrame(rows, columns=column_names) if rows else pd.DataFrame(columns=column_names)
    except Exception as e:
        print(f"Database query error: {e}")
        return f"Database error: {e}", 500

    return render_template('download_invoice.html', data=data_bill.to_dict('records'), search_query=search_query)


# for agent dashboard
@app.route('/agent_dashboard')
def agent_dashboard():
    try:
        # Fetch data from MySQL
        with connect_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT COALESCE(oi.car_status, 'Unknown') AS car_status, d.car_no, d.order_id, d.city, 
                       d.delivered_date, d.final_service , d.service_category
                FROM detail AS d  
                LEFT JOIN owner_insert AS oi ON d.car_no = oi.car_no;
            """)
            data = cursor.fetchall()
            columns = [desc[0] for desc in cursor.description]
            df = pd.DataFrame(data, columns=columns)

            # Data Processing
            active_cars = df['car_status'].value_counts().get('Active', 0)
            inactive_cars = df['car_status'].value_counts().get('Inactive', 0)
            unknown_cars = df['car_status'].value_counts().get('Unknown', 0)

            orders_by_city = df['city'].value_counts()
            orders_by_service = df['service_category'].value_counts()

            repeat_customers = df['car_no'].value_counts()[df['car_no'].value_counts() > 1].count()
            unique_cars = df['car_no'].nunique()

            current_month = pd.Timestamp.now().month
            cars_delivered_current_month = df[pd.to_datetime(df['delivered_date']).dt.month == current_month].shape[0] \
                if not df['delivered_date'].isnull().all() else 0

            final_service_counts = df['final_service'].value_counts()

            total_orders = df["order_id"].count()


            # Plotly Charts
            def create_plotly_chart(chart_type, data, labels, title, size=0.6):
                colors = pc.qualitative.Plotly

                if chart_type == 'pie':
                    fig = px.pie(values=data, names=labels, title=title,
                                 color_discrete_sequence=colors,
                                 hole=0.5)

                    fig.update_traces(
                        textinfo='percent+label', pull=[0.05] * len(labels),
                        textposition='outside',
                        marker=dict(line=dict(color='black', width=1.2))
                    )

                    # Reduce Pie Chart Size
                    fig.update_layout(
                        template="plotly_white",
                        title=dict(text=title, font=dict(size=14, family="Arial", color="black"), x=0.5),

                        margin=dict(l=40, r=100, t=50, b=50),
                        showlegend=True,
                        width=380,
                        height=250
                    )


                elif chart_type == 'bar':
                    fig = px.bar(x=labels, y=data, title=title,
                                 labels={'x': 'Category', 'y': 'Count'},
                                 color=labels,
                                 color_discrete_sequence=colors,
                                 text=data)
                    fig.update_traces(marker=dict(line=dict(width=1, color='black')), textposition='outside')
                    fig.update_layout(
                        template="plotly_white",
                        title=dict(text=title, font=dict(size=16, family="Arial", color="black"), x=0.5),
                        # Centered title
                        legend=dict(
                            orientation="v",
                            yanchor="middle",
                            xanchor="right",
                            x=1.15,
                            y=0.5,
                            title_text=''
                        ),
                        margin=dict(l=40, r=140, t=50, b=80),
                        bargap=0.2,
                        bargroupgap=0.1,
                        showlegend=True,
                        width=1200,
                        height=350
                    )

                return pio.to_html(fig, full_html=False)

            # Create Pie Charts with Reduced Size
            car_status_chart = create_plotly_chart('pie', [active_cars, inactive_cars],
                                                   ['Active', 'Inactive'], 'Car Status Distribution')
            repeat_customer_chart = create_plotly_chart('pie', [repeat_customers, unique_cars - repeat_customers],
                                                        ['Repeat Customers', 'New Customers'], 'Repeat Customer Ratio')
            final_service_chart = create_plotly_chart('pie', final_service_counts.values, final_service_counts.index,
                                                      'Final Service Distribution')

            # Bar charts remain unchanged
            city_orders_chart = create_plotly_chart('bar', orders_by_city.values, orders_by_city.index,
                                                    'Orders by City')
            service_orders_chart = create_plotly_chart('bar', orders_by_service.values, orders_by_service.index,
                                                       'Orders by Service')

            # Render HTML template
            return render_template('agent_dashboard.html',
                                   car_status_chart=car_status_chart,
                                   city_orders_chart=city_orders_chart,
                                   service_orders_chart=service_orders_chart,
                                   repeat_customer_chart=repeat_customer_chart,
                                   final_service_chart=final_service_chart,
                                   active_cars=active_cars,
                                   inactive_cars=inactive_cars,
                                   orders_by_city=orders_by_city,
                                   orders_by_service=orders_by_service,
                                   repeat_customers=repeat_customers,
                                   cars_delivered_current_month=cars_delivered_current_month,
                                   total_orders = total_orders)

    except Exception as e:
        return f"Error: {e}"


@app.route('/add_car', methods=['POST'])
def add_car():
    car_no = request.form.get('car_no')
    mobile_no = request.form.get('mobile_no')
    car_status = request.form.get('car_status')

    if not car_no or not mobile_no or not car_status:
        flash("All fields are required!", 'danger')
        return redirect(url_for('owner_insert'))

    try:
        with connect_db() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO owner_insert (car_no, mobile_no, car_status) VALUES (%s, %s, %s)",
                           (car_no, mobile_no, car_status))
            conn.commit()
            flash("Car added successfully!", 'success')
    except mysql.connector.Error as e:
        flash(f"Database error: {e}", 'danger')

    return redirect(url_for('owner_insert'))


@app.route('/update_status/<car_no>', methods=['POST'])
def update_status(car_no):
    print(f"Received Car No: {car_no}")
    print(f"Form Data: {request.form}")  # Debugging: Check form data received

    new_status = request.form.get('car_status')

    if new_status:
        with connect_db() as conn:
            cursor = conn.cursor()

            # Debugging: Check if the car exists
            cursor.execute("SELECT car_status FROM owner_insert WHERE car_no = %s;", (car_no,))
            existing_record = cursor.fetchall()
            print(f"Existing Record: {existing_record}")  # Debugging

            if existing_record:
                cursor.execute("UPDATE owner_insert SET car_status = %s WHERE car_no = %s;", (new_status, car_no))
                conn.commit()
                flash("Car status updated successfully!", 'success')
            else:
                flash("Car not found!", 'danger')

    return redirect(url_for('owner_insert'))


@app.route('/due_service')
def due_service():
    current_datetime = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Current date and time

    try:
        with connect_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT COALESCE(oi.car_status, 'Unknown') AS car_status, 
                       d.car_no, d.city, d.car_name, 
                       d.delivered_date, d.final_service
                FROM detail AS d  
                LEFT JOIN owner_insert AS oi ON d.car_no = oi.car_no
                WHERE DATE_ADD(d.delivered_date, INTERVAL 150 DAY) 
                      BETWEEN DATE_SUB(CURDATE(), INTERVAL 1 DAY)  
                          AND DATE_ADD(CURDATE(), INTERVAL 1 DAY)
                ORDER BY DATE_ADD(d.delivered_date, INTERVAL 150 DAY), d.delivered_date;
            """)

            data = cursor.fetchall()
            columns = [desc[0] for desc in cursor.description]

            # Convert result to DataFrame
            df_due_service = pd.DataFrame(data, columns=columns)

            # Convert datetime to string format for JSON rendering
            df_due_service['delivered_date'] = df_due_service['delivered_date'].astype(str)

            # Convert DataFrame to a list of dictionaries for rendering in HTML
            data_list = df_due_service.to_dict(orient='records')

            return render_template('due_service.html', data=data_list, current_datetime=current_datetime)

    except Exception as e:
        print(f"Database Query Error: {e}")
        return "An error occurred while fetching due service data."


@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully!", 'success')
    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(debug=True)
