#!/bin/bash
# ========================================
# ScanOPS - Production Deployment Script
# ========================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🔍 ScanOPS Production Deployment${NC}"
echo ""

# ========== Pre-deployment checks ==========
echo -e "${YELLOW}[1/6] Checking prerequisites...${NC}"

# Check Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker is not installed${NC}"
    exit 1
fi

# Check Docker Compose
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}❌ Docker Compose is not installed${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Docker and Docker Compose installed${NC}"

# ========== Environment validation ==========
echo -e "${YELLOW}[2/6] Validating environment configuration...${NC}"

if [ ! -f ".env.production" ]; then
    echo -e "${RED}❌ .env.production not found${NC}"
    echo -e "${YELLOW}Run: cp .env.production.example .env.production${NC}"
    exit 1
fi

# Check critical variables
CRITICAL_VARS=("DB_PASSWORD" "JWT_SECRET_KEY" "REDIS_PASSWORD")
for var in "${CRITICAL_VARS[@]}"; do
    if ! grep -q "^${var}=" .env.production || grep "^${var}=CHANGE_ME" .env.production > /dev/null; then
        echo -e "${RED}❌ ${var} is not properly configured in .env.production${NC}"
        exit 1
    fi
done

echo -e "${GREEN}✓ Environment configuration validated${NC}"

# ========== SSL Certificate Check ==========
echo -e "${YELLOW}[3/6] Checking SSL certificates...${NC}"

if [ ! -d "ssl" ] || [ ! -f "ssl/cert.pem" ] || [ ! -f "ssl/key.pem" ]; then
    echo -e "${YELLOW}⚠️  SSL certificates not found${NC}"
    mkdir -p ssl

    # Generate self-signed certificate temporarily
    openssl req -x509 -newkey rsa:4096 -keyout ssl/key.pem -out ssl/cert.pem \
        -days 365 -nodes -subj "/CN=scanops.local" 2>/dev/null

    echo -e "${YELLOW}⚠️  Temporary self-signed certificate generated${NC}"
    echo -e "${YELLOW}    Run './setup-ssl.sh' to replace with Let's Encrypt${NC}"
else
    echo -e "${GREEN}✓ SSL certificates found${NC}"
fi

# ========== Stop existing services ==========
echo -e "${YELLOW}[4/6] Stopping existing services...${NC}"

docker-compose -f docker-compose.yml -f docker-compose.production.yml down 2>/dev/null || true
sleep 2

echo -e "${GREEN}✓ Services stopped${NC}"

# ========== Build and start services ==========
echo -e "${YELLOW}[5/6] Building and starting services...${NC}"

docker-compose -f docker-compose.yml -f docker-compose.production.yml up -d --build

sleep 15

# ========== Health checks ==========
echo -e "${YELLOW}[6/6] Performing health checks...${NC}"

MAX_RETRIES=30
RETRY=0

echo -n "Waiting for services to be healthy: "
while [ $RETRY -lt $MAX_RETRIES ]; do
    if curl -sf http://localhost/health > /dev/null 2>&1; then
        echo -e "\n${GREEN}✓ All services are healthy${NC}"
        break
    fi
    echo -n "."
    RETRY=$((RETRY+1))
    sleep 2
done

if [ $RETRY -eq $MAX_RETRIES ]; then
    echo -e "\n${YELLOW}⚠️  Health check timeout (this may be normal on slow systems)${NC}"
    echo -e "${YELLOW}   Check logs: docker-compose logs -f nginx${NC}"
fi

# ========== Display summary ==========
echo ""
echo -e "${GREEN}✅ Deployment completed!${NC}"
echo ""
echo "📋 Service Status:"
docker-compose -f docker-compose.yml -f docker-compose.production.yml ps
echo ""

echo "📊 Port Usage:"
echo "  - HTTPS: 443 (nginx)"
echo "  - HTTP:  80 (nginx → 443 redirect)"
echo ""

echo "📝 Next steps:"
echo "  1. Update DNS to point to this server"
echo "  2. Replace temporary SSL certificate: ./setup-ssl.sh"
echo "  3. Verify deployment: curl -I https://your-domain.com"
echo "  4. Monitor logs: docker-compose logs -f"
echo ""

echo "🔍 View logs:"
echo "  - All services: docker-compose logs -f"
echo "  - Nginx:        docker-compose logs -f nginx"
echo "  - M1:           docker-compose logs -f m1"
echo "  - Database:     docker-compose logs -f postgres"
echo ""
