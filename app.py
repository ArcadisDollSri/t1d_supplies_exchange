import math
import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import (
    Column,
    Float,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    create_engine,
    insert,
    select,
)
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
secret_key = os.environ.get("SECRET_KEY")
if not secret_key:
    raise RuntimeError("Set SECRET_KEY to a cryptographically random value.")
secure_cookie_setting = os.environ.get("SESSION_COOKIE_SECURE", "true").lower()
if secure_cookie_setting not in {"true", "false", "1", "0", "yes", "no"}:
    raise RuntimeError("SESSION_COOKIE_SECURE must be true or false.")
app.config.update(
    SECRET_KEY=secret_key,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=secure_cookie_setting in {"true", "1", "yes"},
    SESSION_COOKIE_SAMESITE="Lax",
)
CSRFProtect(app)

database_url = os.environ.get("DATABASE_URL", "sqlite:///t1d_exchange.db")
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql+psycopg://", 1)
elif database_url.startswith("postgresql://"):
    database_url = database_url.replace("postgresql://", "postgresql+psycopg://", 1)

engine_options = {"pool_pre_ping": True}
if database_url.startswith("sqlite:"):
    engine_options["connect_args"] = {"check_same_thread": False}
engine = create_engine(database_url, hide_parameters=True, **engine_options)
metadata = MetaData()


users = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("email", String, unique=True, nullable=False),
    Column("name", String, nullable=False),
    Column("password_hash", String, nullable=False),
)

donors = Table(
    "donors",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("user_id", Integer, ForeignKey("users.id")),
    Column("name", String, nullable=False),
    Column("email", String, nullable=False),
    Column("city", String),
    Column("zip_code", String),
    Column("latitude", Float),
    Column("longitude", Float),
    Column("supply_type", String, nullable=False, index=True),
    Column("brand", String),
    Column("quantity", Integer),
    Column("condition", String),
    Column("expiry_date", String),
    Column("offer_type", String, nullable=False),
    Column("notes", String),
)

recipients = Table(
    "recipients",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("user_id", Integer, ForeignKey("users.id")),
    Column("name", String, nullable=False),
    Column("email", String, nullable=False),
    Column("city", String),
    Column("zip_code", String),
    Column("latitude", Float),
    Column("longitude", Float),
    Column("supply_type", String, nullable=False),
    Column("urgency", String),
    Column("notes", String),
)


def init_db():
    metadata.create_all(engine)


init_db()


# ---------- Auth helpers ----------

def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    with engine.connect() as conn:
        return conn.execute(
            select(users).where(users.c.id == user_id)
        ).mappings().first()


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

        try:
            with engine.begin() as conn:
                conn.execute(
                    insert(users).values(
                        email=email, name=name, password_hash=password_hash
                    )
                )
        except IntegrityError:
            flash("Email already registered. Please log in.", "error")
            return redirect(url_for("login"))

        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", user=current_user())


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        with engine.connect() as conn:
            user = conn.execute(
                select(users).where(users.c.email == email)
            ).mappings().first()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            flash("Logged in successfully.", "success")
            return redirect(url_for("index"))
        else:
            flash("Invalid email or password.", "error")
            return redirect(url_for("login"))

    return render_template("login.html", user=current_user())


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
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
        quantity = int(request.form.get("quantity") or 0)
        condition = request.form.get("condition")
        expiry_date = request.form.get("expiry_date")
        offer_type = request.form.get("offer_type")
        notes = request.form.get("notes")

        latitude = float(latitude) if latitude else None
        longitude = float(longitude) if longitude else None

        with engine.begin() as conn:
            conn.execute(
                insert(donors).values(
                    user_id=user["id"],
                    name=name,
                    email=email,
                    city=city,
                    zip_code=zip_code,
                    latitude=latitude,
                    longitude=longitude,
                    supply_type=supply_type,
                    brand=brand,
                    quantity=quantity,
                    condition=condition,
                    expiry_date=expiry_date,
                    offer_type=offer_type,
                    notes=notes,
                )
            )

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

        with engine.begin() as conn:
            conn.execute(
                insert(recipients).values(
                    user_id=user["id"],
                    name=name,
                    email=email,
                    city=city,
                    zip_code=zip_code,
                    latitude=latitude,
                    longitude=longitude,
                    supply_type=supply_type,
                    urgency=urgency,
                    notes=notes,
                )
            )

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
    with engine.connect() as conn:
        matching_donors = conn.execute(
            select(donors).where(donors.c.supply_type == supply_type)
        ).mappings().all()

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

    donors_sorted = sorted(matching_donors, key=score, reverse=True)
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
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
