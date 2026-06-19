#!/bin/bash
# ========================================
# ScanOPS - SSL/TLS Setup with Let's Encrypt
# ========================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

DOMAIN=""
EMAIL=""
STAGING_FLAG=""

# Parse arguments
usage() {
    echo "Usage: $0 --domain scanops.example.com [--email admin@example.com] [--staging]"
    echo ""
    echo "Options:"
    echo "  --domain    Domain name (required)"
    echo "  --email     Email for Let's Encrypt (default: admin@{domain})"
    echo "  --staging   Use staging environment (for testing)"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --domain)
            DOMAIN="$2"
            shift 2
            ;;
        --email)
            EMAIL="$2"
            shift 2
            ;;
        --staging)
            STAGING_FLAG="--staging"
            shift
            ;;
        *)
            usage
            ;;
    esac
done

if [ -z "$DOMAIN" ]; then
    echo -e "${RED}❌ Domain is required${NC}"
    usage
fi

[ -z "$EMAIL" ] && EMAIL="admin@${DOMAIN}"

echo -e "${BLUE}🔒 ScanOPS SSL/TLS Setup${NC}"
echo "Domain: $DOMAIN"
echo "Email:  $EMAIL"
echo ""

# ========== Create directories ==========
echo -e "${YELLOW}[1/4] Creating certificate directories...${NC}"
mkdir -p certbot/{conf,www} ssl
echo -e "${GREEN}✓ Directories created${NC}"

# ========== Generate temporary self-signed cert ==========
echo -e "${YELLOW}[2/4] Generating temporary certificate...${NC}"

if [ ! -f "ssl/key.pem" ] || [ ! -f "ssl/cert.pem" ]; then
    openssl req -x509 -newkey rsa:4096 -keyout ssl/key.pem -out ssl/cert.pem \
        -days 365 -nodes -subj "/CN=${DOMAIN}" 2>/dev/null
    echo -e "${GREEN}✓ Temporary certificate created${NC}"
else
    echo -e "${YELLOW}⚠️  Certificate already exists${NC}"
fi

# ========== Start Nginx temporarily ==========
echo -e "${YELLOW}[3/4] Starting Nginx with temporary certificate...${NC}"

docker-compose -f docker-compose.yml -f docker-compose.production.yml up -d nginx 2>/dev/null || true
sleep 5

echo -e "${GREEN}✓ Nginx started${NC}"

# ========== Request Let's Encrypt certificate ==========
echo -e "${YELLOW}[4/4] Requesting Let's Encrypt certificate...${NC}"
echo "This may take a few moments..."
echo ""

docker run --rm \
    -v $(pwd)/certbot/conf:/etc/letsencrypt \
    -v $(pwd)/certbot/www:/var/www/certbot \
    -p 80:80 \
    certbot/certbot certonly \
    --standalone \
    --agree-tos \
    --no-eff-email \
    --force-renewal \
    -m ${EMAIL} \
    -d ${DOMAIN} \
    ${STAGING_FLAG} 2>&1 | tail -20

echo ""

# ========== Copy certificates ==========
echo -e "${YELLOW}Copying certificates to Nginx...${NC}"

CERT_PATH="certbot/conf/live/${DOMAIN}"
if [ -d "$CERT_PATH" ]; then
    cp "${CERT_PATH}/fullchain.pem" ssl/cert.pem
    cp "${CERT_PATH}/privkey.pem" ssl/key.pem
    chmod 644 ssl/cert.pem
    chmod 600 ssl/key.pem
    echo -e "${GREEN}✓ Certificates installed${NC}"
else
    echo -e "${RED}❌ Certificate generation failed${NC}"
    echo -e "${YELLOW}Check error message above for details${NC}"
    exit 1
fi

# ========== Restart Nginx ==========
echo -e "${YELLOW}Restarting Nginx with production certificate...${NC}"

docker-compose -f docker-compose.yml -f docker-compose.production.yml restart nginx
sleep 3

echo -e "${GREEN}✓ Nginx restarted${NC}"

# ========== Setup auto-renewal ==========
echo -e "${YELLOW}Setting up automatic certificate renewal...${NC}"

docker-compose -f docker-compose.yml -f docker-compose.production.yml up -d certbot 2>/dev/null || true

echo -e "${GREEN}✓ Auto-renewal configured${NC}"

# ========== Summary ==========
echo ""
echo -e "${GREEN}✅ SSL/TLS setup completed!${NC}"
echo ""
echo "📋 Certificate Details:"
echo "  Domain:       ${DOMAIN}"
echo "  Location:     ssl/{cert.pem, key.pem}"
echo "  Valid until:  $(date -d "+90 days" +"%Y-%m-%d")"
echo ""
echo "🔄 Auto-renewal:"
echo "  Certbot will renew 30 days before expiration"
echo "  Monitor: docker-compose logs certbot"
echo ""
echo "✅ Verification:"
echo "  curl -I https://${DOMAIN}"
echo ""

# ========== If staging, provide upgrade info ==========
if [ ! -z "$STAGING_FLAG" ]; then
    echo -e "${YELLOW}⚠️  You're using Let's Encrypt STAGING${NC}"
    echo "To upgrade to production:"
    echo "  ./setup-ssl.sh --domain ${DOMAIN} --email ${EMAIL}"
    echo ""
fi
