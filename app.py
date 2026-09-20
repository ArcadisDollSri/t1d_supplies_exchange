import math
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "change_this_to_a_secure_random_value"
DB_NAME = "t1d_exchange.db"


def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    # Users table
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            password_hash TEXT NOT NULL
        );
    """)

    # Donors table
    c.execute("""
        CREATE TABLE IF NOT EXISTS donors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            city TEXT,
            zip_code TEXT,
            latitude REAL,
            longitude REAL,
            supply_type TEXT NOT NULL,
            brand TEXT,
            quantity INTEGER,
            condition TEXT,
            expiry_date TEXT,
            offer_type TEXT NOT NULL,  -- sell / exchange / free
            notes TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    """)

    # Recipients table
    c.execute("""
        CREATE TABLE IF NOT EXISTS recipients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            city TEXT,
            zip_code TEXT,
            latitude REAL,
            longitude REAL,
            supply_type TEXT NOT NULL,
            urgency TEXT,
            notes TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    """)

    conn.commit()
    conn.close()


def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


# ---------- Auth helpers ----------

def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    conn.close()
    return user


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")

        if not name or not email or not password:
            flash("All fields are required.", "error")
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)

        conn = get_db()
        c = conn.cursor()
        try:
            c.execute("""
                INSERT INTO users (email, name, password_hash)
                VALUES (?, ?, ?)
            """, (email, name, password_hash))
            conn.commit()
        except sqlite3.IntegrityError:
            flash("Email already registered. Please log in.", "error")
            conn.close()
            return redirect(url_for("login"))
        conn.close()

        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", user=current_user())


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            flash("Logged in successfully.", "success")
            return redirect(url_for("index"))
        else:
            flash("Invalid email or password.", "error")
            return redirect(url_for("login"))

    return render_template("login.html", user=current_user())


@app.route("/logout")
def logout():
    session.pop("user_id", None)
    flash("Logged out.", "success")
    return redirect(url_for("index"))


# ---------- Core pages ----------

@app.route("/")
def index():
    return render_template("index.html", user=current_user())


@app.route("/donor", methods=["GET", "POST"])
def donor():
    user = current_user()
    if not user:
        flash("Please log in to offer supplies.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        city = request.form.get("city")
        zip_code = request.form.get("zip_code")
        latitude = request.form.get("latitude")
        longitude = request.form.get("longitude")
        supply_type = request.form.get("supply_type")
        brand = request.form.get("brand")
        quantity = request.form.get("quantity") or 0
        condition = request.form.get("condition")
        expiry_date = request.form.get("expiry_date")
        offer_type = request.form.get("offer_type")
        notes = request.form.get("notes")

        latitude = float(latitude) if latitude else None
        longitude = float(longitude) if longitude else None

        conn = get_db()
        c = conn.cursor()
        c.execute("""
            INSERT INTO donors
            (user_id, name, email, city, zip_code, latitude, longitude,
             supply_type, brand, quantity, condition, expiry_date, offer_type, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (user["id"], name, email, city, zip_code, latitude, longitude,
              supply_type, brand, quantity, condition, expiry_date, offer_type, notes))
        conn.commit()
        conn.close()

        flash("Offer submitted.", "success")
        return redirect(url_for("index"))

    return render_template("donor_form.html", user=user)


@app.route("/recipient", methods=["GET", "POST"])
def recipient():
    user = current_user()
    if not user:
        flash("Please log in to register a need.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        city = request.form.get("city")
        zip_code = request.form.get("zip_code")
        latitude = request.form.get("latitude")
        longitude = request.form.get("longitude")
        supply_type = request.form.get("supply_type")
        urgency = request.form.get("urgency")
        notes = request.form.get("notes")

        latitude = float(latitude) if latitude else None
        longitude = float(longitude) if longitude else None

        conn = get_db()
        c = conn.cursor()
        c.execute("""
            INSERT INTO recipients
            (user_id, name, email, city, zip_code, latitude, longitude,
             supply_type, urgency, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (user["id"], name, email, city, zip_code, latitude, longitude,
              supply_type, urgency, notes))
        conn.commit()
        conn.close()

        return redirect(url_for("matches",
                                supply_type=supply_type,
                                city=city,
                                zip_code=zip_code,
                                latitude=latitude,
                                longitude=longitude))

    return render_template("recipient_form.html", user=user)


# ---------- Matching logic ----------

def haversine(lat1, lon1, lat2, lon2):
    # Returns distance in kilometers
    R = 6371.0
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)

    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c


def find_matches(supply_type, city, zip_code, latitude, longitude):
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT *
        FROM donors
        WHERE supply_type = ?
    """, (supply_type,))
    donors = c.fetchall()
    conn.close()

    def score(d):
        s = 0
        # Text-based proximity
        if zip_code and d["zip_code"] and zip_code.strip() == d["zip_code"].strip():
            s += 2
        if city and d["city"] and city.strip().lower() == d["city"].strip().lower():
            s += 1
        # Geo distance (if both sides have lat/long)
        if latitude is not None and longitude is not None and d["latitude"] is not None and d["longitude"] is not None:
            dist_km = haversine(latitude, longitude, d["latitude"], d["longitude"])
            # Invert distance into score (closer = higher)
            s += max(0, 10 - dist_km)  # simple heuristic: within ~10km gets positive boost
        return s

    donors_sorted = sorted(donors, key=score, reverse=True)
    return donors_sorted


@app.route("/matches")
def matches():
    supply_type = request.args.get("supply_type")
    city = request.args.get("city")
    zip_code = request.args.get("zip_code")
    latitude = request.args.get("latitude")
    longitude = request.args.get("longitude")

    latitude = float(latitude) if latitude not in (None, "", "None") else None
    longitude = float(longitude) if longitude not in (None, "", "None") else None

    donors = find_matches(supply_type, city, zip_code, latitude, longitude)
    return render_template(
        "matches.html",
        user=current_user(),
        donors=donors,
        supply_type=supply_type,
        city=city,
        zip_code=zip_code,
        latitude=latitude,
        longitude=longitude
    )


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
