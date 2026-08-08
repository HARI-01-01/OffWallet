# Production Deployment

## Environment

Set `DATABASE_URL` to either a SQLite file or a PostgreSQL connection string.

Example PostgreSQL URL:

`postgresql+psycopg2://user:password@host:5432/offline_payments`

## Alembic

Run migrations with:

```bash
alembic upgrade head
```

## systemd

Copy `deploy/systemd/offline-payment-backend.service` to `/etc/systemd/system/`, update the paths, then run:

```bash
sudo systemctl daemon-reload
sudo systemctl enable offline-payment-backend
sudo systemctl start offline-payment-backend
```

## Nginx

Copy `deploy/nginx/offline-payment-backend.conf` into `/etc/nginx/conf.d/` or `/etc/nginx/sites-available/`, then reload Nginx.