# T1D Supplies Exchange

## Database configuration

The app uses SQLite locally by default and can use any PostgreSQL-compatible
managed database for demos or production. Set `DATABASE_URL` to the provider's
connection URL when deploying; the app creates its tables at startup. Keep the
URL private and configure it as a deployment environment variable, not in source
control.

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
