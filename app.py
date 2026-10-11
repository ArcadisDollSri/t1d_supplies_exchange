import hashlib
import os
import secrets
import smtplib
import ssl
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from urllib.parse import urljoin

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import (
    Boolean,
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
    inspect,
    insert,
    select,
    text,
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
    Column("is_available", Boolean, nullable=False, server_default="true"),
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
    Column("completed", Boolean, nullable=False, server_default="false"),
    Column("created_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
    CheckConstraint(
        "status IN ('pending', 'approved', 'declined')",
        name="connection_requests_status_check",
    ),
    UniqueConstraint("donor_id", "recipient_id", name="connection_requests_pair_unique"),
)

password_resets = Table(
    "password_resets",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("user_id", Integer, ForeignKey("users.id"), nullable=False),
    Column("token_hash", String, unique=True, nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
)


def init_db():
    metadata.create_all(engine)
    existing_columns = {
        table_name: {column["name"] for column in inspect(engine).get_columns(table_name)}
        for table_name in ("donors", "connection_requests")
    }
    migrations = {
        "donors": ("is_available", "BOOLEAN NOT NULL DEFAULT TRUE"),
        "connection_requests": ("completed", "BOOLEAN NOT NULL DEFAULT FALSE"),
    }
    with engine.begin() as conn:
        for table_name, (column_name, column_definition) in migrations.items():
            if column_name not in existing_columns[table_name]:
                conn.execute(
                    text(
                        f"ALTER TABLE {table_name} ADD COLUMN "
                        f"{column_name} {column_definition}"
                    )
                )


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


def send_password_reset_email(recipient_email, reset_url):
    smtp_host = os.environ.get("SMTP_HOST")
    sender_email = os.environ.get("SMTP_FROM")
    if not smtp_host or not sender_email:
        raise RuntimeError("SMTP_HOST and SMTP_FROM must be configured.")

    username = os.environ.get("SMTP_USERNAME")
    password = os.environ.get("SMTP_PASSWORD")
    if bool(username) != bool(password):
        raise RuntimeError("Configure both SMTP_USERNAME and SMTP_PASSWORD, or neither.")

    message = EmailMessage()
    message["Subject"] = "Reset your T1D Supply Exchange password"
    message["From"] = sender_email
    message["To"] = recipient_email
    message.set_content(
        "We received a request to reset your password. Use the one-time link "
        f"within one hour:\n\n{reset_url}\n\n"
        "If you did not request this, you can ignore this email."
    )

    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    timeout = float(os.environ.get("SMTP_TIMEOUT", "15"))
    use_ssl = os.environ.get("SMTP_USE_SSL", "false").lower() in {"true", "1", "yes"}
    smtp_class = smtplib.SMTP_SSL if use_ssl else smtplib.SMTP
    smtp_options = {"context": ssl.create_default_context()} if use_ssl else {}
    with smtp_class(smtp_host, smtp_port, timeout=timeout, **smtp_options) as smtp:
        if not use_ssl:
            smtp.starttls(context=ssl.create_default_context())
        if username:
            smtp.login(username, password)
        smtp.send_message(message)


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip()
        if email:
            with engine.begin() as conn:
                user = conn.execute(
                    select(users.c.id, users.c.email).where(users.c.email == email)
                ).first()
                if user:
                    token = secrets.token_urlsafe(32)
                    conn.execute(
                        password_resets.delete().where(
                            password_resets.c.user_id == user.id
                        )
                    )
                    conn.execute(
                        insert(password_resets).values(
                            user_id=user.id,
                            token_hash=hashlib.sha256(token.encode()).hexdigest(),
                            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                        )
                    )
            if email and user:
                public_base_url = os.environ.get("PUBLIC_BASE_URL", "").strip()
                if not public_base_url.startswith("https://"):
                    app.logger.error(
                        "Password reset email not sent: PUBLIC_BASE_URL must be an HTTPS URL."
                    )
                    with engine.begin() as conn:
                        conn.execute(
                            password_resets.delete().where(
                                password_resets.c.user_id == user.id
                            )
                        )
                else:
                    reset_url = urljoin(
                        public_base_url.rstrip("/") + "/",
                        url_for("reset_password", token=token).lstrip("/"),
                    )
                    try:
                        send_password_reset_email(user.email, reset_url)
                    except (OSError, RuntimeError, smtplib.SMTPException, ValueError):
                        app.logger.exception("Unable to send password reset email.")
                        with engine.begin() as conn:
                            conn.execute(
                                password_resets.delete().where(
                                    password_resets.c.user_id == user.id
                                )
                            )

        flash(
            "If an account exists for that email, a password reset link will be sent.",
            "success",
        )
        return redirect(url_for("login"))

    return render_template("forgot_password.html", user=current_user())


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with engine.connect() as conn:
        reset = conn.execute(
            select(password_resets.c.id, password_resets.c.user_id).where(
                password_resets.c.token_hash == token_hash,
                password_resets.c.expires_at > func.now(),
            )
        ).first()

    if not reset:
        flash("That password reset link is invalid or expired. Request a new one.", "error")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form.get("password") or ""
        confirm_password = request.form.get("confirm_password") or ""
        if len(password) < 12:
            flash("Use a password with at least 12 characters.", "error")
        elif password != confirm_password:
            flash("The passwords do not match.", "error")
        else:
            with engine.begin() as conn:
                consumed_reset = conn.execute(
                    password_resets.delete().where(
                        password_resets.c.id == reset.id,
                        password_resets.c.expires_at > func.now(),
                    )
                )
                if consumed_reset.rowcount != 1:
                    flash("That password reset link is invalid or expired. Request a new one.", "error")
                    return redirect(url_for("forgot_password"))
                conn.execute(
                    update(users)
                    .where(users.c.id == reset.user_id)
                    .values(password_hash=generate_password_hash(password))
                )
            session.clear()
            flash("Your password has been reset. Please log in.", "success")
            return redirect(url_for("login"))

    response = app.make_response(
        render_template("reset_password.html", user=None, token=token)
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


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
                donors.c.is_available.is_(True),
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
            select(
                connection_requests.c.donor_id,
                case(
                    (connection_requests.c.completed.is_(True), "completed"),
                    else_=connection_requests.c.status,
                ).label("status"),
            ).where(
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
                connection_requests.c.completed.is_(False),
                donors.c.is_available.is_(True),
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
                case(
                    (connection_requests.c.completed.is_(True), "completed"),
                    else_=connection_requests.c.status,
                ).label("status"),
                connection_requests.c.created_at,
                case(
                    (
                        (connection_requests.c.status == "approved")
                        & connection_requests.c.completed.is_(False),
                        recipients.c.name,
                    )
                ).label("recipient_name"),
                case(
                    (
                        (connection_requests.c.status == "approved")
                        & connection_requests.c.completed.is_(False),
                        recipients.c.email,
                    )
                ).label("recipient_email"),
                recipients.c.city.label("recipient_city"),
                case(
                    (
                        (connection_requests.c.status == "approved")
                        & connection_requests.c.completed.is_(False),
                        recipients.c.zip_code,
                    )
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
                case(
                    (connection_requests.c.completed.is_(True), "completed"),
                    else_=connection_requests.c.status,
                ).label("status"),
                connection_requests.c.created_at,
                donors.c.id.label("donor_id"),
                case(
                    (
                        (connection_requests.c.status == "approved")
                        & connection_requests.c.completed.is_(False),
                        donors.c.name,
                    )
                ).label("donor_name"),
                case(
                    (
                        (connection_requests.c.status == "approved")
                        & connection_requests.c.completed.is_(False),
                        donors.c.email,
                    )
                ).label("donor_email"),
                donors.c.city.label("donor_city"),
                case(
                    (
                        (connection_requests.c.status == "approved")
                        & connection_requests.c.completed.is_(False),
                        donors.c.zip_code,
                    )
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
                    donors.c.is_available.is_(True),
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
                donors.c.is_available.is_(True),
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


@app.route("/connections/<int:request_id>/complete", methods=["POST"])
def complete_connection(request_id):
    user = current_user()
    if not user:
        flash("Please log in to complete an exchange.", "error")
        return redirect(url_for("login"))

    with engine.begin() as conn:
        completed_request = conn.execute(
            select(connection_requests.c.id, connection_requests.c.donor_id)
            .join(donors, donors.c.id == connection_requests.c.donor_id)
            .where(
                connection_requests.c.id == request_id,
                connection_requests.c.status == "approved",
                connection_requests.c.completed.is_(False),
                donors.c.user_id == user["id"],
                donors.c.is_available.is_(True),
            )
        ).first()
        if not completed_request:
            flash("That approved exchange could not be found or is already complete.", "error")
            return redirect(url_for("connections"))

        result = conn.execute(
            update(donors)
            .where(
                donors.c.id == completed_request.donor_id,
                donors.c.user_id == user["id"],
                donors.c.is_available.is_(True),
            )
            .values(is_available=False)
        )
        if result.rowcount != 1:
            flash("That supply is no longer available.", "error")
            return redirect(url_for("connections"))

        conn.execute(
            update(connection_requests)
            .where(
                connection_requests.c.donor_id == completed_request.donor_id,
                connection_requests.c.status == "approved",
            )
            .values(completed=True)
        )
        conn.execute(
            update(connection_requests)
            .where(
                connection_requests.c.donor_id == completed_request.donor_id,
                connection_requests.c.status == "pending",
            )
            .values(status="declined")
        )

    flash("Exchange completed. The offer was removed and contact details are hidden again.", "success")
    return redirect(url_for("connections"))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
