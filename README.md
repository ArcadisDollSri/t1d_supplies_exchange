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
