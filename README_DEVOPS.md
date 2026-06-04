# HBILLSOFT Mobile Server — DevOps Setup

## What gets deployed
Only `mobile_server.py` (Flask) runs on EC2. The desktop POS (`main.py`) stays on your local machine as usual.

---

## 1. EC2 Setup (one time)

Launch an Ubuntu EC2 instance (t2.micro is fine for a single restaurant).

Open port **5050** in the EC2 security group inbound rules.

SSH into your EC2 and run:

```bash
# Install Docker
sudo apt update
sudo apt install -y docker.io docker-compose-plugin
sudo usermod -aG docker ubuntu
newgrp docker

# Create app directory
mkdir -p ~/hbillsoft
```

---

## 2. Files to put in your GitHub repo

Add these files to the root of your repo:

```
Dockerfile
docker-compose.yml
requirements.txt
Jenkinsfile
mobile_server.py
mobile_order.html
```

---

## 3. Jenkins Setup

Install Jenkins on a separate server or locally, with these plugins:
- Git
- Pipeline
- SSH Agent

Add two credentials in Jenkins (Manage Jenkins → Credentials):
- `EC2_HOST` — your EC2 public IP (Secret Text)
- `EC2_SSH_KEY` — your `.pem` file contents (SSH Username with private key)

Create a Pipeline job, point it to your GitHub repo, and set the Jenkinsfile path.

---

## 4. First Manual Deploy (before Jenkins is ready)

```bash
# From your local machine
scp -i your-key.pem Dockerfile docker-compose.yml requirements.txt \
    mobile_server.py mobile_order.html \
    ubuntu@YOUR_EC2_IP:/home/ubuntu/hbillsoft/

ssh -i your-key.pem ubuntu@YOUR_EC2_IP
cd ~/hbillsoft
docker compose up --build -d
```

Server will be live at: `http://YOUR_EC2_IP:5050`

---

## 5. Syncing the Database

The SQLite database lives on EC2 in a Docker volume (`hbillsoft-data`).

**To push your local DB to EC2:**
```bash
scp -i your-key.pem .hbillsoft/sales_data.db ubuntu@YOUR_EC2_IP:/tmp/

ssh -i your-key.pem ubuntu@YOUR_EC2_IP
# Copy into Docker volume
docker cp /tmp/sales_data.db hbillsoft-mobile:/app/.hbillsoft/sales_data.db
```

**To pull EC2 DB back to local:**
```bash
docker cp hbillsoft-mobile:/app/.hbillsoft/sales_data.db /tmp/sales_data.db
scp -i your-key.pem ubuntu@YOUR_EC2_IP:/tmp/sales_data.db ./.hbillsoft/
```

---

## 6. Useful Commands

```bash
# Check if container is running
docker ps

# View logs
docker logs hbillsoft-mobile

# Restart
docker compose restart

# Stop
docker compose down
```
