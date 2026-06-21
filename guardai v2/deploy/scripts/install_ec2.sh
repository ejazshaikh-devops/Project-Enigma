#!/usr/bin/env bash
#
# GuardAI — EC2 install script
# Sets up nginx as a reverse proxy with HTTPS (via Let's Encrypt/certbot)
# in front of the GuardAI backend Docker container.
#
# Run this ONCE on a fresh Ubuntu 22.04/24.04 EC2 instance, as a user with
# sudo access. Re-run sections individually if something fails partway.
#
# PREREQUISITES (do these before running this script):
#   1. Point a DNS A record at your EC2 instance's public IP
#      (e.g. api.guardai.io -> your EC2 Elastic IP). Certbot needs this
#      to issue a cert — it will NOT work against a bare IP address.
#   2. Open ports 80 and 443 in your EC2 Security Group (inbound).
#   3. Have your GuardAI Docker image ready (pulled from ECR) or this repo's
#      backend/ directory present to build locally.

set -euo pipefail

DOMAIN="${1:-}"
if [ -z "$DOMAIN" ]; then
  echo "Usage: ./install_ec2.sh yourdomain.example.com"
  echo "  (must already point at this instance's public IP via DNS)"
  exit 1
fi

echo "==> Installing nginx, certbot, and Docker (skips if already installed)"
sudo apt-get update -y
sudo apt-get install -y nginx certbot python3-certbot-nginx

if ! command -v docker &> /dev/null; then
  curl -fsSL https://get.docker.com -o get-docker.sh
  sudo sh get-docker.sh
  sudo usermod -aG docker "$USER"
  rm get-docker.sh
  echo "Docker installed. You may need to log out/in for group membership to apply."
fi

echo "==> Configuring nginx rate-limit zones (global, in nginx.conf http{} block)"
if ! grep -q "guardai_req" /etc/nginx/nginx.conf; then
  sudo sed -i '/http {/a \\n    limit_req_zone $binary_remote_addr zone=guardai_req:10m rate=10r/s;\n    limit_conn_zone $binary_remote_addr zone=guardai_conn:10m;' /etc/nginx/nginx.conf
  echo "Added rate-limit zones to nginx.conf"
else
  echo "Rate-limit zones already present, skipping"
fi

echo "==> Writing initial HTTP-only nginx site config"
sudo tee /etc/nginx/sites-available/guardai > /dev/null <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

sudo ln -sf /etc/nginx/sites-available/guardai /etc/nginx/sites-enabled/guardai
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl reload nginx

echo "==> Running container check"
if ! docker ps --format '{{.Names}}' | grep -q guardai-backend; then
  echo "WARNING: no container named 'guardai-backend' is currently running on port 8000."
  echo "Start it first, e.g.:"
  echo "  docker run -d --name guardai-backend --restart unless-stopped \\"
  echo "    -p 127.0.0.1:8000:8000 --env-file /home/ubuntu/guardai.env \\"
  echo "    <your-ecr-image-uri>:latest"
  echo "Then re-run this script, or just continue — certbot doesn't need it running yet."
fi

echo "==> Requesting HTTPS certificate via certbot (this rewrites the nginx config for you)"
sudo certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "admin@${DOMAIN}" --redirect

echo "==> Applying GuardAI-specific hardening on top of certbot's HTTPS block"
echo "    (body size limit, timeouts, rate limiting, blocking non-API paths)"
echo "    Edit /etc/nginx/sites-available/guardai manually using the commented"
echo "    HTTPS template in deploy/nginx/guardai.conf from this repo, then:"
echo "      sudo nginx -t && sudo systemctl reload nginx"

echo "==> Setting up certbot auto-renewal check"
sudo systemctl status certbot.timer --no-pager || sudo systemctl enable --now certbot.timer

echo ""
echo "Done. Your backend should now be reachable at: https://${DOMAIN}/v1/health/live"
echo "Test with: curl https://${DOMAIN}/v1/health/live"
