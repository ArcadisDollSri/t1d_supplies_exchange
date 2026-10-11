# T1D Supplies Exchange

## Configuration and security

The app requires a `SECRET_KEY` environment variable for signing sessions and
CSRF tokens. Generate one with Python and set it in your local environment or
deployment secret manager; never commit it:

```powershell
$env:SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
```

Set `SESSION_COOKIE_SECURE=false` only for local HTTP development. It defaults
to `true` so browsers send session cookies only over HTTPS. Cookies are also
HTTP-only and use `SameSite=Lax`; state-changing forms require CSRF tokens.

The app uses SQLite locally by default and can use any PostgreSQL-compatible
managed database for demos or production. Set `DATABASE_URL` to the provider's
connection URL when deploying; the app creates its tables at startup. Store the
URL in the deployment platform's secret manager or protected environment
variables, not in source control. SQLAlchemy is configured not to include query
parameters in its SQL logs.

```powershell
$env:DATABASE_URL = "postgresql://USER:PASSWORD@HOST:5432/DATABASE?sslmode=require"
python app.py
```

PostgreSQL connection URLs using either `postgres://` or `postgresql://` are
supported. The app uses the PostgreSQL Psycopg driver. A provider's free plan
can be used during development and demos; when the project needs more capacity,
upgrade that same database service so the connection URL and application code
remain unchanged. Confirm the provider's backup, storage, connection, and
availability limits before using a free plan for important data.

If `DATABASE_URL` is not set, the app uses `t1d_exchange.db` in the working
directory. Switching an existing SQLite deployment to PostgreSQL does not copy
its data; export/import existing records before switching if they need to be
kept.

Install dependencies with `pip install -r requirements.txt`.

Database credentials cannot be removed when the database authenticates with a
username and password; they can be kept out of the codebase by supplying the
URL at runtime as described above. Cloud-provider identity-based database
authentication may avoid a static database password, but its setup depends on
the hosting and database provider.

## Exchange completion and password recovery

The supply owner can mark an approved exchange complete from **Connections**.
The offer is then removed from matching, and contact details are hidden again
for all requests associated with that offer.

Password recovery emails require these deployment environment variables:

- `SMTP_HOST` and `SMTP_FROM` are required.
- `SMTP_PORT` defaults to `587`; `SMTP_USE_SSL=true` enables implicit TLS
  (commonly port `465`). Otherwise the app uses STARTTLS.
- `SMTP_USERNAME` and `SMTP_PASSWORD` must either both be set or both omitted.
- `PUBLIC_BASE_URL` must be the public HTTPS origin, for example
  `https://your-app.onrender.com`, so reset links use the correct trusted host.

Reset links expire after one hour, can only be used once, and are stored in the
database as hashes. The forgot-password response does not reveal whether the
email address has an account. Password resets require at least 12 characters.
SMTP failures are logged by the server, and no usable reset link is left behind.

## Matching and contact privacy

Supply offers and needs accept a city/area or ZIP/postal code; latitude and
longitude are not required. Matches are approximate: an identical ZIP/postal
code ranks first, followed by an identical city/area. This does not calculate
street-level or true geographic distance, and no location is sent to an
external geocoding service. Search results show approximate city/area and
whether the ZIP or city matched, not the other party's name, email, notes, or
ZIP.

A recipient can request a connection from a match. The supply owner reviews
incoming requests under **Connections** and can approve or decline. Names,
email addresses, and ZIP/postal codes are shown to each other only after the
owner approves. A `connection_requests` table is created automatically for
existing databases at startup. Availability and completion columns are added
automatically to existing databases. Previously stored latitude/longitude
values, if any, are no longer used for matching or displayed.
