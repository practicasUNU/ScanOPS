#!/bin/bash
# Test Orchestrator in Docker

set -e

echo "=== Testing Orchestrator Docker Build ==="

# 1. Build
echo "Building orchestrator..."
docker compose build orchestrator

# 2. Start orchestrator + dependencies
echo "Starting orchestrator with postgres + redis..."
docker compose up -d postgres redis

# Wait for postgres
echo "Waiting for postgres healthcheck..."
docker compose exec -T postgres pg_isready -U scanops || sleep 5

# Start orchestrator
docker compose up -d orchestrator

# Wait for orchestrator to start
echo "Waiting for orchestrator to be ready..."
sleep 5

# 3. Test endpoints
echo ""
echo "Testing /health endpoint..."
curl -s http://localhost:8009/health || echo "FAILED"

echo ""
echo "Testing /docs endpoint..."
curl -s http://localhost:8009/docs | grep -q "openapi" && echo "OK" || echo "FAILED"

# 4. Cleanup
echo ""
echo "=== Cleanup ==="
docker compose down

echo "✅ Orchestrator Docker test completed"
