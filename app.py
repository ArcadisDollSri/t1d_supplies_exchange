import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import (
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    UniqueConstraint,
    case,
    create_engine,
    func,
    insert,
    select,
    update,
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
    Column("supply_type", String, nullable=False),
    Column("urgency", String),
    Column("notes", String),
)

connection_requests = Table(
    "connection_requests",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("donor_id", Integer, ForeignKey("donors.id"), nullable=False),
    Column("recipient_id", Integer, ForeignKey("recipients.id"), nullable=False),
    Column("status", String, nullable=False),
    Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
    CheckConstraint(
        "status IN ('pending', 'approved', 'declined')",
        name="connection_requests_status_check",
    ),
    UniqueConstraint("donor_id", "recipient_id", name="connection_requests_pair_unique"),
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
        city = request.form.get("city", "").strip() or None
        zip_code = request.form.get("zip_code")
        zip_code = zip_code.strip() if zip_code else None
        supply_type = request.form.get("supply_type")
        brand = request.form.get("brand")
        quantity = int(request.form.get("quantity") or 0)
        condition = request.form.get("condition")
        expiry_date = request.form.get("expiry_date")
        offer_type = request.form.get("offer_type")
        notes = request.form.get("notes")

        if not city and not zip_code:
            flash("Enter a city or area, or a ZIP/postal code.", "error")
            return redirect(url_for("donor"))

        with engine.begin() as conn:
            conn.execute(
                insert(donors).values(
                    user_id=user["id"],
                    name=name,
                    email=email,
                    city=city,
                    zip_code=zip_code,
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
        city = request.form.get("city", "").strip() or None
        zip_code = request.form.get("zip_code")
        zip_code = zip_code.strip() if zip_code else None
        supply_type = request.form.get("supply_type")
        urgency = request.form.get("urgency")
        notes = request.form.get("notes")

        if not city and not zip_code:
            flash("Enter a city or area, or a ZIP/postal code.", "error")
            return redirect(url_for("recipient"))

        with engine.begin() as conn:
            result = conn.execute(
                insert(recipients).values(
                    user_id=user["id"],
                    name=name,
                    email=email,
                    city=city,
                    zip_code=zip_code,
                    supply_type=supply_type,
                    urgency=urgency,
                    notes=notes,
                )
            )
            recipient_id = result.inserted_primary_key[0]

        return redirect(url_for("matches", recipient_id=recipient_id))

    return render_template("recipient_form.html", user=user)


# ---------- Matching logic ----------

def find_matches(supply_type, city, zip_code, user_id):
    with engine.connect() as conn:
        matching_donors = conn.execute(
            select(
                donors.c.id,
                donors.c.city,
                donors.c.zip_code,
                donors.c.supply_type,
                donors.c.brand,
                donors.c.quantity,
                donors.c.condition,
                donors.c.expiry_date,
                donors.c.offer_type,
            ).where(
                donors.c.supply_type == supply_type,
                donors.c.user_id != user_id,
            )
        ).mappings().all()

    def location_rank(donor):
        same_city = bool(city and donor["city"]) and (
            city.strip().casefold() == donor["city"].strip().casefold()
        )
        same_zip = bool(zip_code and donor["zip_code"]) and (
            "".join(ch for ch in zip_code.upper() if ch.isalnum())
            == "".join(ch for ch in donor["zip_code"].upper() if ch.isalnum())
        ) and (not city or not donor["city"] or same_city)
        return (same_zip, same_city)

    sorted_donors = sorted(matching_donors, key=location_rank, reverse=True)
    return [
        {
            "id": donor["id"],
            "city": donor["city"],
            "supply_type": donor["supply_type"],
            "brand": donor["brand"],
            "quantity": donor["quantity"],
            "condition": donor["condition"],
            "expiry_date": donor["expiry_date"],
            "offer_type": donor["offer_type"],
            "same_zip": location_rank(donor)[0],
            "same_city": location_rank(donor)[1],
        }
        for donor in sorted_donors
    ]


@app.route("/matches")
def matches():
    user = current_user()
    if not user:
        flash("Please log in to view matches.", "error")
        return redirect(url_for("login"))

    recipient_id = request.args.get("recipient_id", type=int)
    with engine.connect() as conn:
        need = conn.execute(
            select(recipients).where(
                recipients.c.id == recipient_id,
                recipients.c.user_id == user["id"],
            )
        ).mappings().first()

    if not need:
        flash("Register a need before viewing matches.", "error")
        return redirect(url_for("recipient"))

    matching_donors = find_matches(
        need["supply_type"], need["city"], need["zip_code"], user["id"]
    )
    with engine.connect() as conn:
        request_rows = conn.execute(
            select(connection_requests.c.donor_id, connection_requests.c.status).where(
                connection_requests.c.recipient_id == need["id"]
            )
        ).all()
        approved_contacts = conn.execute(
            select(
                connection_requests.c.donor_id,
                donors.c.name,
                donors.c.email,
                donors.c.city,
                donors.c.zip_code,
            )
            .join(donors, donors.c.id == connection_requests.c.donor_id)
            .where(
                connection_requests.c.recipient_id == need["id"],
                connection_requests.c.status == "approved",
            )
        ).mappings().all()

    request_statuses = {row.donor_id: row.status for row in request_rows}
    donor_contacts = {row["donor_id"]: row for row in approved_contacts}
    return render_template(
        "matches.html",
        user=user,
        donors=matching_donors,
        need=need,
        request_statuses=request_statuses,
        donor_contacts=donor_contacts,
    )


@app.route("/connections", methods=["GET"])
def connections():
    user = current_user()
    if not user:
        flash("Please log in to view connection requests.", "error")
        return redirect(url_for("login"))

    with engine.connect() as conn:
        received = conn.execute(
            select(
                connection_requests.c.id.label("request_id"),
                connection_requests.c.status,
                connection_requests.c.created_at,
                case(
                    (connection_requests.c.status == "approved", recipients.c.name)
                ).label("recipient_name"),
                case(
                    (connection_requests.c.status == "approved", recipients.c.email)
                ).label("recipient_email"),
                recipients.c.city.label("recipient_city"),
                case(
                    (connection_requests.c.status == "approved", recipients.c.zip_code)
                ).label("recipient_zip"),
                recipients.c.supply_type,
                recipients.c.urgency,
            )
            .join(recipients, recipients.c.id == connection_requests.c.recipient_id)
            .join(donors, donors.c.id == connection_requests.c.donor_id)
            .where(donors.c.user_id == user["id"])
            .order_by(connection_requests.c.created_at.desc())
        ).mappings().all()
        sent = conn.execute(
            select(
                connection_requests.c.id.label("request_id"),
                connection_requests.c.status,
                connection_requests.c.created_at,
                donors.c.id.label("donor_id"),
                case(
                    (connection_requests.c.status == "approved", donors.c.name)
                ).label("donor_name"),
                case(
                    (connection_requests.c.status == "approved", donors.c.email)
                ).label("donor_email"),
                donors.c.city.label("donor_city"),
                case(
                    (connection_requests.c.status == "approved", donors.c.zip_code)
                ).label("donor_zip"),
                donors.c.supply_type,
                donors.c.brand,
                donors.c.quantity,
                donors.c.condition,
                donors.c.expiry_date,
                donors.c.offer_type,
            )
            .join(donors, donors.c.id == connection_requests.c.donor_id)
            .join(recipients, recipients.c.id == connection_requests.c.recipient_id)
            .where(recipients.c.user_id == user["id"])
            .order_by(connection_requests.c.created_at.desc())
        ).mappings().all()

    return render_template(
        "connections.html",
        user=user,
        received=received,
        sent=sent,
    )


@app.route("/connections/request/<int:recipient_id>/<int:donor_id>", methods=["POST"])
def request_connection(recipient_id, donor_id):
    user = current_user()
    if not user:
        flash("Please log in to request a connection.", "error")
        return redirect(url_for("login"))

    try:
        with engine.begin() as conn:
            need = conn.execute(
                select(recipients).where(
                    recipients.c.id == recipient_id,
                    recipients.c.user_id == user["id"],
                )
            ).mappings().first()
            if not need:
                flash("That need was not found.", "error")
                return redirect(url_for("recipient"))

            donor_offer = conn.execute(
                select(donors.c.id).where(
                    donors.c.id == donor_id,
                    donors.c.user_id != user["id"],
                    donors.c.supply_type == need["supply_type"],
                )
            ).first()
            if not donor_offer:
                flash("That offer is not available for this need.", "error")
                return redirect(url_for("recipient"))

            existing = conn.execute(
                select(connection_requests).where(
                    connection_requests.c.donor_id == donor_id,
                    connection_requests.c.recipient_id == recipient_id,
                )
            ).mappings().first()
            if existing:
                if existing["status"] == "declined":
                    conn.execute(
                        update(connection_requests)
                        .where(connection_requests.c.id == existing["id"])
                        .values(status="pending", created_at=func.now())
                    )
                    flash("Request sent again. Your contact details stay private until the donor approves.", "success")
                else:
                    flash("A connection request already exists for this offer and need.", "error")
            else:
                conn.execute(
                    insert(connection_requests).values(
                        donor_id=donor_id,
                        recipient_id=recipient_id,
                        status="pending",
                    )
                )
                flash("Request sent. Your contact details stay private until the donor approves.", "success")
    except IntegrityError:
        with engine.connect() as conn:
            existing = conn.execute(
                select(connection_requests.c.id).where(
                    connection_requests.c.donor_id == donor_id,
                    connection_requests.c.recipient_id == recipient_id,
                )
            ).first()
        if not existing:
            raise
        flash("A connection request already exists for this offer and need.", "error")

    return redirect(url_for("matches", recipient_id=recipient_id))


@app.route("/connections/<int:request_id>/<action>", methods=["POST"])
def update_connection_request(request_id, action):
    user = current_user()
    if not user:
        flash("Please log in to respond to connection requests.", "error")
        return redirect(url_for("login"))
    if action not in {"approve", "decline"}:
        flash("Invalid request action.", "error")
        return redirect(url_for("connections"))

    new_status = "approved" if action == "approve" else "declined"
    with engine.begin() as conn:
        owned_request = conn.execute(
            select(connection_requests.c.id)
            .join(donors, donors.c.id == connection_requests.c.donor_id)
            .where(
                connection_requests.c.id == request_id,
                connection_requests.c.status == "pending",
                donors.c.user_id == user["id"],
            )
        ).first()
        if not owned_request:
            flash("That pending request was not found.", "error")
            return redirect(url_for("connections"))
        result = conn.execute(
            update(connection_requests)
            .where(
                connection_requests.c.id == request_id,
                connection_requests.c.status == "pending",
            )
            .values(status=new_status)
        )
        if result.rowcount != 1:
            flash("That pending request was already handled.", "error")
            return redirect(url_for("connections"))

    flash(
        "Connection approved; both parties can now see each other's contact details."
        if new_status == "approved"
        else "Connection request declined.",
        "success",
    )
    return redirect(url_for("connections"))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
