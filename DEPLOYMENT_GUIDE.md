# 🧪 Development/Testing Deployment Guide

## 🚨 CRITICAL DISCLAIMERS - READ FIRST

**⚠️ NOT FOR PRODUCTION USE**: This is a **development/testing tool only** and is **NOT officially supported by Palo Alto Networks**. This guide is for development and testing environments only.

**🚫 PALO ALTO NETWORKS DISCLAIMER**: This tool is **NOT developed, supported, or endorsed by Palo Alto Networks**. Any issues, security concerns, or problems are **YOUR responsibility**.

**👤 USER RESPONSIBILITY**: You are solely responsible for all testing, validation, security, and compliance in your environment.

## 🎯 Overview

This guide provides instructions for deploying the development/testing chatbot in controlled development and testing environments. **NOT suitable for production use without extensive additional testing and validation.**

---

## 🏗️ Development/Testing Environment Checklist

### **Development Infrastructure**
- [ ] **Compute**: 2+ CPU cores, 4GB+ RAM for testing environment
- [ ] **Network**: Outbound HTTPS (443) access to APIs for development
- [ ] **Storage**: 10GB+ for logs and temporary files during testing
- [ ] **Python**: Version 3.8+ with pip package manager
- [ ] **Development Environment**: Isolated testing environment ready

### **Testing Security Requirements**
- [ ] **API Keys**: Secure storage for development/testing credentials
- [ ] **Network**: Controlled development network access
- [ ] **Testing Protocols**: Testing procedures documented
- [ ] **Development Monitoring**: Basic logging for development analysis
- [ ] **Testing Data**: Non-sensitive test data prepared

### **Development Team Requirements**
- [ ] **Documentation**: Development procedures and testing guidelines
- [ ] **Team Knowledge**: Development team understands this is a testing tool
- [ ] **Responsibility Understanding**: Team knows they are responsible for all testing and validation
- [ ] **Disclaimer Acknowledgment**: Team understands Palo Alto Networks provides no support

---

## 🔧 Environment Setup

### **1. System Preparation**

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install Python and required system packages
sudo apt install python3 python3-pip python3-venv nginx -y

# Create application directory
sudo mkdir -p /opt/secure-chatbot
sudo chown $USER:$USER /opt/secure-chatbot
cd /opt/secure-chatbot
```

### **2. Application Installation**

```bash
# Create Python virtual environment
python3 -m venv venv
source venv/bin/activate

# Copy application files
# (Copy all files from secure-chatbot-perplexity folder)

# Install dependencies
pip install -r requirements.txt

# Verify installation
python3 -c "import requests, anthropic, aisecurity; print('All dependencies installed successfully')"
```

### **3. Configuration Management**

```bash
# Create secure configuration directory
sudo mkdir -p /etc/secure-chatbot
sudo chmod 700 /etc/secure-chatbot

# Copy environment template
cp .env.example /etc/secure-chatbot/.env
sudo chmod 600 /etc/secure-chatbot/.env

# Create symlink for application
ln -s /etc/secure-chatbot/.env .env
```

---

## 🔐 Security Hardening

### **1. API Key Management**

#### **Option A: Environment Variables (Basic)**
```bash
# Edit secure environment file
sudo nano /etc/secure-chatbot/.env

# Set proper permissions
sudo chown root:secure-chatbot /etc/secure-chatbot/.env
sudo chmod 640 /etc/secure-chatbot/.env
```

#### **Option B: Azure Key Vault (Recommended)**
```python
# Install Azure Key Vault client
pip install azure-keyvault-secrets azure-identity

# Update application to use Key Vault
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential

credential = DefaultAzureCredential()
client = SecretClient(vault_url="https://your-vault.vault.azure.net/", credential=credential)

panw_api_key = client.get_secret("panw-ai-sec-api-key").value
perplexity_api_key = client.get_secret("perplexity-api-key").value
```

#### **Option C: AWS Secrets Manager**
```python
# Install AWS SDK
pip install boto3

# Update application to use Secrets Manager
import boto3
import json

client = boto3.client('secretsmanager', region_name='us-east-1')
response = client.get_secret_value(SecretId='secure-chatbot-secrets')
secrets = json.loads(response['SecretString'])

panw_api_key = secrets['PANW_AI_SEC_API_KEY']
perplexity_api_key = secrets['PERPLEXITY_API_KEY']
```

### **2. Network Security**

#### **Firewall Configuration (UFW)**
```bash
# Enable firewall
sudo ufw enable

# Allow SSH (adjust port as needed)
sudo ufw allow 22/tcp

# Allow HTTPS outbound (for API calls)
sudo ufw allow out 443/tcp

# Allow application port (if running web interface)
sudo ufw allow 8000/tcp

# Deny all other traffic by default
sudo ufw default deny incoming
sudo ufw default deny outgoing
```

#### **Nginx Reverse Proxy (Optional)**
```nginx
# /etc/nginx/sites-available/secure-chatbot
server {
    listen 443 ssl http2;
    server_name your-domain.com;
    
    ssl_certificate /path/to/your/certificate.crt;
    ssl_certificate_key /path/to/your/private.key;
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### **3. Application Security**

#### **User and Permissions**
```bash
# Create dedicated user
sudo useradd -r -s /bin/false secure-chatbot
sudo usermod -a -G secure-chatbot $USER

# Set application permissions
sudo chown -R secure-chatbot:secure-chatbot /opt/secure-chatbot
sudo chmod -R 750 /opt/secure-chatbot
```

#### **SELinux/AppArmor (Optional)**
```bash
# Install AppArmor utilities
sudo apt install apparmor-utils -y

# Create AppArmor profile for the application
sudo nano /etc/apparmor.d/opt.secure-chatbot.secure-chatbot-api
```

---

## 📊 Monitoring and Logging

### **1. Application Logging**

#### **Log Configuration**
```python
# Add to application startup
import logging
import logging.handlers

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.handlers.RotatingFileHandler(
            '/var/log/secure-chatbot/app.log',
            maxBytes=10485760,  # 10MB
            backupCount=5
        ),
        logging.StreamHandler()
    ]
)
```

#### **Log Rotation**
```bash
# Create logrotate configuration
sudo nano /etc/logrotate.d/secure-chatbot

/var/log/secure-chatbot/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 secure-chatbot secure-chatbot
    postrotate
        systemctl reload secure-chatbot
    endscript
}
```

### **2. System Monitoring**

#### **Prometheus Metrics (Optional)**
```python
# Install prometheus client
pip install prometheus-client

# Add metrics to application
from prometheus_client import Counter, Histogram, start_http_server

# Define metrics
security_scans_total = Counter('security_scans_total', 'Total security scans', ['result'])
scan_duration_seconds = Histogram('scan_duration_seconds', 'Security scan duration')
api_requests_total = Counter('api_requests_total', 'Total API requests', ['endpoint', 'status'])

# Start metrics server
start_http_server(8001)
```

#### **Health Check Endpoint**
```python
# Add health check to application
@app.route('/health')
def health_check():
    checks = {
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0',
        'dependencies': {
            'palo_alto_api': check_palo_alto_connectivity(),
            'perplexity_api': check_perplexity_connectivity()
        }
    }
    return jsonify(checks)
```

### **3. Alerting Setup**

#### **Basic Email Alerts**
```python
# Install email dependencies
pip install smtplib-ssl

def send_alert(subject, message):
    import smtplib
    from email.mime.text import MIMEText
    
    msg = MIMEText(message)
    msg['Subject'] = f"[SECURE-CHATBOT] {subject}"
    msg['From'] = "alerts@yourcompany.com"
    msg['To'] = "ops-team@yourcompany.com"
    
    with smtplib.SMTP_SSL('smtp.yourcompany.com', 465) as server:
        server.login("alerts@yourcompany.com", "password")
        server.send_message(msg)
```

---

## 🔄 Service Management

### **1. Systemd Service**

```bash
# Create systemd service file
sudo nano /etc/systemd/system/secure-chatbot.service
```

```ini
[Unit]
Description=Secure AI Chatbot with Perplexity
After=network.target

[Service]
Type=simple
User=secure-chatbot
Group=secure-chatbot
WorkingDirectory=/opt/secure-chatbot
Environment=PATH=/opt/secure-chatbot/venv/bin
Environment=PYTHONPATH=/opt/secure-chatbot
ExecStart=/opt/secure-chatbot/venv/bin/python secure_chatbot_perplexity_api.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/secure-chatbot

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable secure-chatbot
sudo systemctl start secure-chatbot

# Check status
sudo systemctl status secure-chatbot
```

### **2. Process Management**

#### **Supervisor (Alternative)**
```bash
# Install supervisor
sudo apt install supervisor -y

# Create supervisor configuration
sudo nano /etc/supervisor/conf.d/secure-chatbot.conf
```

```ini
[program:secure-chatbot]
command=/opt/secure-chatbot/venv/bin/python secure_chatbot_perplexity_api.py
directory=/opt/secure-chatbot
user=secure-chatbot
autostart=true
autorestart=true
redirect_stderr=true
stdout_logfile=/var/log/secure-chatbot/supervisor.log
```

```bash
# Update supervisor and start
sudo supervisorctl reread
sudo supervisorctl update
sudo supervisorctl start secure-chatbot
```

---

## 📈 Performance Optimization

### **1. Application Tuning**

#### **Connection Pooling**
```python
# Configure HTTP connection pooling
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

session = requests.Session()
retry_strategy = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
)
adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=100, pool_maxsize=100)
session.mount("http://", adapter)
session.mount("https://", adapter)
```

#### **Async Processing**
```python
# Use async for better performance
import asyncio
import aiohttp

async def process_multiple_requests(requests):
    async with aiohttp.ClientSession() as session:
        tasks = [process_request(session, req) for req in requests]
        return await asyncio.gather(*tasks)
```

### **2. Caching Strategy**

#### **Redis Caching (Optional)**
```python
# Install Redis client
pip install redis

import redis
import json
import hashlib

redis_client = redis.Redis(host='localhost', port=6379, db=0)

def get_cache_key(prompt):
    return f"scan:{hashlib.md5(prompt.encode()).hexdigest()}"

def cache_scan_result(prompt, result, ttl=3600):
    key = get_cache_key(prompt)
    redis_client.setex(key, ttl, json.dumps(result))

def get_cached_scan_result(prompt):
    key = get_cache_key(prompt)
    cached = redis_client.get(key)
    return json.loads(cached) if cached else None
```

---

## 🔍 Testing and Validation

### **1. Smoke Tests**

```bash
# Create test script
nano test_deployment.sh
```

```bash
#!/bin/bash
set -e

echo "🧪 Running deployment smoke tests..."

# Test 1: Application startup
echo "Testing application startup..."
systemctl is-active --quiet secure-chatbot || (echo "❌ Service not running" && exit 1)

# Test 2: Health check
echo "Testing health check endpoint..."
curl -f http://localhost:8000/health || (echo "❌ Health check failed" && exit 1)

# Test 3: API connectivity
echo "Testing API connectivity..."
python3 << EOF
import os
import requests

# Test Palo Alto Networks API
pan_key = os.getenv('PANW_AI_SEC_API_KEY')
if not pan_key:
    raise Exception("Missing PANW_AI_SEC_API_KEY")

# Test Perplexity API
perplexity_key = os.getenv('PERPLEXITY_API_KEY')
if not perplexity_key:
    raise Exception("Missing PERPLEXITY_API_KEY")

print("✅ All API keys present")
EOF

echo "✅ All smoke tests passed!"
```

### **2. Load Testing**

```bash
# Install load testing tools
pip install locust

# Create load test script
nano locustfile.py
```

```python
from locust import HttpUser, task, between
import json

class ChatbotUser(HttpUser):
    wait_time = between(1, 3)
    
    @task(3)
    def safe_message(self):
        payload = {"message": "What's the weather like today?"}
        self.client.post("/chat", json=payload)
    
    @task(1)
    def complex_message(self):
        payload = {"message": "Explain quantum computing in simple terms"}
        self.client.post("/chat", json=payload)

# Run load test
# locust -f locustfile.py --host=http://localhost:8000
```

---

## 🚨 Incident Response

### **1. Common Issues**

#### **High Error Rate**
```bash
# Check application logs
sudo journalctl -u secure-chatbot -f

# Check system resources
top
df -h
free -m

# Restart service if needed
sudo systemctl restart secure-chatbot
```

#### **API Rate Limiting**
```bash
# Check API usage in logs
grep "429" /var/log/secure-chatbot/app.log

# Implement rate limiting monitoring
# Alert when approaching limits
```

#### **Performance Degradation**
```bash
# Monitor response times
curl -w "@curl-format.txt" -o /dev/null -s http://localhost:8000/health

# Check database/cache performance
redis-cli info stats
```

### **2. Emergency Procedures**

#### **Service Restart**
```bash
# Graceful restart
sudo systemctl restart secure-chatbot

# Force restart if needed
sudo systemctl kill secure-chatbot
sudo systemctl start secure-chatbot
```

#### **Rollback Procedure**
```bash
# Stop current service
sudo systemctl stop secure-chatbot

# Restore previous version
cp -r /opt/secure-chatbot.backup /opt/secure-chatbot

# Restart with previous version
sudo systemctl start secure-chatbot
```

#### **Emergency Contacts**
```
Primary: Technical Lead (+1-XXX-XXX-XXXX)
Secondary: Operations Team (ops-team@company.com)
Escalation: Engineering Manager (+1-XXX-XXX-XXXX)
Vendor Support: This tool is NOT officially supported by Palo Alto Networks
```

---

## 📋 Maintenance Procedures

### **1. Regular Maintenance**

#### **Daily Tasks**
```bash
# Check service status
systemctl status secure-chatbot

# Review error logs
tail -n 100 /var/log/secure-chatbot/app.log | grep ERROR

# Check disk space
df -h
```

#### **Weekly Tasks**
```bash
# Update system packages
sudo apt update && sudo apt list --upgradable

# Review security logs
grep -i "blocked" /var/log/secure-chatbot/app.log | tail -50

# Check certificate expiration
openssl x509 -in /path/to/cert.pem -text -noout | grep "Not After"
```

#### **Monthly Tasks**
```bash
# Update Python dependencies
pip list --outdated
pip install -r requirements.txt --upgrade

# Rotate API keys (if policy requires)
# Update monitoring dashboards
# Review and update security policies
```

### **2. Backup Procedures**

#### **Configuration Backup**
```bash
# Create backup script
nano /opt/scripts/backup-config.sh
```

```bash
#!/bin/bash
BACKUP_DIR="/opt/backups/$(date +%Y%m%d)"
mkdir -p $BACKUP_DIR

# Backup application files
cp -r /opt/secure-chatbot $BACKUP_DIR/
cp /etc/secure-chatbot/.env $BACKUP_DIR/env-backup

# Backup system configuration
cp /etc/systemd/system/secure-chatbot.service $BACKUP_DIR/
cp /etc/nginx/sites-available/secure-chatbot $BACKUP_DIR/

# Create archive
tar -czf $BACKUP_DIR.tar.gz $BACKUP_DIR
rm -rf $BACKUP_DIR

echo "Backup completed: $BACKUP_DIR.tar.gz"
```

---

## 🎯 Go-Live Checklist

### **Pre-Production**
- [ ] All tests passing (unit, integration, smoke)
- [ ] Security scan completed and issues resolved
- [ ] Performance testing completed with acceptable results
- [ ] Monitoring and alerting configured and tested
- [ ] Backup and recovery procedures tested
- [ ] Documentation updated and reviewed
- [ ] Team training completed

### **Production Deployment**
- [ ] API keys configured in secure storage
- [ ] SSL certificates installed and validated
- [ ] Service started and health checks passing
- [ ] Monitoring dashboards showing normal metrics
- [ ] Load balancer configured (if applicable)
- [ ] DNS records updated (if applicable)
- [ ] Initial smoke tests completed successfully

### **Post-Deployment**
- [ ] Monitor system for first 24 hours
- [ ] Verify all integrations working correctly
- [ ] Review logs for any unexpected issues
- [ ] Confirm alerting is working as expected
- [ ] Schedule first maintenance window
- [ ] Update incident response procedures with testing environment details

---

**🧪 Your development/testing chatbot setup is complete!**

**⚠️ REMINDER**: This is a testing tool only - NOT for production use without extensive additional validation and testing!

For ongoing support and maintenance, refer to the operational runbooks and contact your designated support team.