# Migration plan

This is the plan I wrote for my Postgres migration so I don't forget all that I have to do

## Preparation

### 1. Set up a swap file
I've been meaning to do this for a while so now is a good time lol

```bash
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
free -h
```

Change swappiness so it doesn't start hammering the disk with free dedicated RAM still available

```bash
# take note of the current value
sysctl vm.swappiness

# create and edit a swappiness config file
sudo nano /etc/sysctl.d/99-swappiness.conf

# in the nano window add a line: `vm.swappiness=10`

# save and exit, now back in your terminal:
sudo sysctl --system

# verify that this outputs 10 and not what it previously was:
sysctl vm.swappiness
```

### 2. Install pgsql
Debian 13 should have it installed by default and it will run on `127.0.0.1:5432` as postgresql.service

```bash
# make sure everything is updated and enable it
sudo apt update
sudo apt install -y postgresql
sudo systemctl enable --now postgresql

# create the db
sudo -u postgres psql -c "CREATE USER eepy WITH PASSWORD 'ENTER A PASSWORD HERE AND STORE IT SOMEWHERE SAFE';"
sudo -u postgres psql -c "CREATE DATABASE eepy_page_backend OWNER eepy;"
```

after you do this make sure it's NOT publicly accessible (check `ufw`, `ss`, and running a `curl` or `ping` from a different device on the public server), but it IS reachable on localhost.

### 3. Update env file
Generate the email pepper and copy it:
```bash
python3 -c 'print(__import__("secrets").token_urlsafe(64))'
```

Add these lines to the .env (fill in placeholders)
```
POSTGRES_URL="postgresql://eepy:YOUR_PASSWORD@127.0.0.1:5432/eepy_page_backend"
EMAIL_PEPPER="Your email pepper"
```

### 4. Back up everything
- Make a backup on MongoDB Atlas
- Back up the current backend with `cp -a ~/eepy.page-backend ~/eepy.page-backend_backup_before_pgsql`

---

## Downloading new code

```bash
cd ~/eepy.page-backend

# pull latest version, update dependencies
git pull
./venv/bin/pip install -r requirements.txt

# re-cache systemd .service files
sudo systemctl daemon-reload
```

### Dry-run the migration
This migrates data without any writes whatsoever, it simply reads from MongoDB and does in-memory ops. Run this first and verify the output against what you're expecting

```bash
./venv/bin/python scripts/migrate_mongo_to_postgres.py --dry-run
```

---

## The actual migration steps

### Stop the backend and run the migration
```bash
cd ~/eepy.page-backend
sudo systemctl stop eepy-page-backend

# wait a minute just to be safe
# it should stop immediately but we don't want to risk writes while it's migrating

./venv/bin/python3 scripts/migrate_mongo_to_postgres.py
```

### 4. Update Admin Panel and Frontend

### 5. Start backend and monitor
```bash
sudo systemctl start eepy-page-backend
journalctl -u eepy-page-backend -f
```

---

## Verification

Check some things to ensure functionality works:
- [ ] Pytest passes
- [ ] No errors in logs
- [ ] Production username and email logins work on frontend
- [ ] Users can create/edit/delete/modify DNS records and other data
- [ ] Public API works (user API keys)
- [ ] Admin panel works with updated backend

---

## Finalization

### Set up backups

Run the backup postgres script, the --install-cron flag installs itself to run daily at 1am

```bash
cd ~/eepy.page-backend
./scripts/backup-postgres.sh --install-cron
```

### Remove old packages

Some packages were removed during the migration like pymongo, let's recreate the venv to make sure everything is updated (not strictly required; this will stop the backend for a bit):

```bash
cd ~/eepy.page-backend
sudo systemctl stop eepy-page-backend
rm -rf venv
python3 -m venv venv
./venv/bin/python3 -m pip install -r requirements.txt
sudo systemctl start eepy-page-backend
```

### Remove data from MongoDB
Delete/pause the Atlas database after at least a week of stable, successful operations

---

## Emergency plan if the migration fails

1. Stop the backend: `sudo systemctl stop eepy-page-backend`
2. "Disable" the failed backend: `mv ~/eepy.page-backend ~/eepy.page-backend_failed_migration`
3. Restore the pre-migration backend: `mv ~/eepy.page-backend_backup_before_pgsql ~/eepy.page-backend`
4. Roll back Vercel to pre-Postgres version and do the same for admin panel (less of a priority since it's internal)
5. Restart backend: `sudo systemctl start eepy-page-backend`
6. Realize what you've just done and figure out the issue lol
