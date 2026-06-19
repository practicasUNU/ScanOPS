# 🚀 ScanOPS - Production Deployment Guide

Guía completa para desplegar ScanOPS en producción con Nginx, SSL/TLS automático y múltiples módulos.

## 📋 Table of Contents

1. [Requisitos](#requisitos)
2. [Configuración previa](#configuración-previa)
3. [Despliegue rápido](#despliegue-rápido)
4. [SSL/TLS con Let's Encrypt](#ssltls-con-lets-encrypt)
5. [Verificación](#verificación)
6. [Mantenimiento](#mantenimiento)

---

## ⚙️ Requisitos

- **Linux Server** (Ubuntu 22.04 LTS recomendado) con 8GB RAM mínimo
- **Docker** >= 20.10
- **Docker Compose** >= 2.0
- **Git** para clonar el repositorio
- **OpenSSL** (preinstalado en Linux)
- **Dominio** apuntando al servidor

### Instalar Docker

```bash
curl -fsSL https://get.docker.com -o get-docker.sh && sudo sh get-docker.sh
sudo usermod -aG docker $USER
```

### Instalar Docker Compose

```bash
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
  -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

---

## 🔧 Configuración previa

### 1. Clonar repositorio

```bash
git clone https://github.com/tu-usuario/ScanOPS.git
cd ScanOPS
```

### 2. Crear archivo de secretos

```bash
# Copiar plantilla
cp .env.production.example .env.production

# Editar con valores reales
nano .env.production
```

**Valores que DEBES cambiar:**

```bash
# Generar contraseñas fuertes (32 caracteres)
openssl rand -base64 32

# Luego, en .env.production, cambiar:
DB_PASSWORD=<genera con openssl>
REDIS_PASSWORD=<genera con openssl>
JWT_SECRET_KEY=<openssl rand -hex 32>
PLATFORM_URL=https://tu-dominio.com
```

### 3. Hacer scripts ejecutables

```bash
chmod +x deploy.production.sh setup-ssl.sh
```

---

## 🚀 Despliegue rápido

### Opción 1: Automatizado (Recomendado)

```bash
sudo ./deploy.production.sh
```

**Expected output:**
```
✅ Deployment completed!
📋 Service Status: all running
```

### Opción 2: Manual paso a paso

```bash
# 1. Crear directorios SSL
mkdir -p ssl certbot/{conf,www}

# 2. Generar certificado temporal
openssl req -x509 -newkey rsa:4096 -keyout ssl/key.pem \
  -out ssl/cert.pem -days 365 -nodes -subj "/CN=tu-dominio.com"

# 3. Iniciar servicios
docker-compose -f docker-compose.yml \
  -f docker-compose.production.yml up -d

# 4. Esperar a que arranquen (30-60 segundos)
sleep 60

# 5. Verificar estado
docker-compose ps
```

---

## 🔒 SSL/TLS con Let's Encrypt

### Despliegue con certificado real

```bash
sudo chmod +x setup-ssl.sh
sudo ./setup-ssl.sh --domain scanops.example.com --email admin@example.com
```

**Qué hace:**
1. Genera certificado temporal
2. Inicia Nginx con certificado temporal
3. Solicita certificado a Let's Encrypt
4. Reemplaza certificados
5. Configura renovación automática

### Renovación manual

```bash
docker-compose logs certbot  # Ver estado
```

Certbot renovará automáticamente 30 días antes del vencimiento.

---

## ✅ Verificación

### Health checks

```bash
# General
curl -I https://scanops.example.com/health

# Específico por módulo
curl -I https://scanops.example.com/api/m1/health
curl -I https://scanops.example.com/api/m2/health
curl -I https://scanops.example.com/api/orchestrator/health
```

### Status de servicios

```bash
# Ver todos los servicios
docker-compose ps

# Ver logs en tiempo real
docker-compose logs -f

# Ver logs específicos
docker-compose logs -f m1        # Inventory
docker-compose logs -f m2        # Network Scanning
docker-compose logs -f m4        # Vulnerability Assessment
docker-compose logs -f orchestrator
```

### Verificar certificado SSL

```bash
openssl x509 -in ssl/cert.pem -text -noout | grep -A 2 "Validity"
```

---

## 🔧 Mantenimiento

### Backup de base de datos

```bash
# Backup completo
docker-compose exec postgres pg_dump -U scanops -d scanops > \
  backup_$(date +%Y%m%d_%H%M%S).sql

# Backup comprimido
docker-compose exec postgres pg_dump -U scanops -d scanops | gzip > \
  backup_$(date +%Y%m%d_%H%M%S).sql.gz
```

### Restaurar base de datos

```bash
docker-compose exec -T postgres psql -U scanops -d scanops < backup_20240612.sql
```

### Actualizar aplicación

```bash
# 1. Parar servicios
docker-compose -f docker-compose.yml \
  -f docker-compose.production.yml down

# 2. Actualizar código
git pull origin main

# 3. Reconstruir y reiniciar
docker-compose -f docker-compose.yml \
  -f docker-compose.production.yml up -d --build
```

### Limpiar datos temporales

```bash
# Limpiar caché Redis
docker-compose exec redis redis-cli FLUSHDB

# Limpiar logs antiguos
docker-compose logs --tail 1000 > current.log
```

### Monitoreo

```bash
# Uso de recursos
docker stats

# Logs de error
docker-compose logs | grep -i error

# Espacio en disco
df -h

# Conexiones de base de datos
docker-compose exec postgres psql -U scanops -d scanops -c \
  "SELECT datname, count(*) FROM pg_stat_activity GROUP BY datname;"
```

---

## 🚨 Troubleshooting

### ❌ Servicios no arrancan

```bash
# Ver logs detallados
docker-compose logs -f --tail 100

# Verificar puerto 80 disponible
sudo netstat -tlnp | grep :80

# Liberar puerto (si es necesario)
sudo lsof -i :80 | grep LISTEN
sudo kill -9 <PID>
```

### ❌ Nginx retorna 502 Bad Gateway

```bash
# Verificar si backends están corriendo
docker-compose ps

# Ver logs de Nginx
docker-compose logs nginx -f

# Verificar conectividad interna
docker-compose exec nginx curl http://m1:8001/health

# Revisar proxy_params.conf
cat proxy_params.conf
```

### ❌ SSL certificate error

```bash
# Ver detalles del certificado
openssl x509 -in ssl/cert.pem -text

# Renovar forzadamente
docker run --rm \
  -v $(pwd)/certbot/conf:/etc/letsencrypt \
  -v $(pwd)/certbot/www:/var/www/certbot \
  certbot/certbot renew --force-renewal
```

### ❌ Database connection timeout

```bash
# Esperar a que PostgreSQL esté listo
docker-compose exec postgres pg_isready

# Reiniciar database
docker-compose restart postgres
sleep 30
docker-compose up -d
```

### ❌ Redis connection refused

```bash
# Verificar si Redis está corriendo
docker-compose exec redis redis-cli ping

# Reiniciar Redis
docker-compose restart redis

# Verificar password
docker-compose exec redis redis-cli -a $REDIS_PASSWORD ping
```

---

## 📊 Configuración avanzada

### Escalado (Multi-instancia)

```yaml
# En docker-compose.yml
m1:
  deploy:
    replicas: 3  # 3 instancias de M1
```

Actualizar nginx.conf:
```nginx
upstream m1 {
    least_conn;
    server m1:8001 max_fails=3 fail_timeout=30s;
    server m1_1:8001 max_fails=3 fail_timeout=30s;
    server m1_2:8001 max_fails=3 fail_timeout=30s;
}
```

### Rate Limiting personalizado

En nginx.conf:
```nginx
limit_req_zone $binary_remote_addr zone=upload:10m rate=10r/m;
limit_req zone=upload burst=20 nodelay;
```

### Logging avanzado

```bash
# Ver accesos a API específico
docker-compose logs nginx | grep "/api/m1/"

# Filtrar errores
docker-compose logs | grep -i "error\|failed\|exception"

# Exportar logs
docker-compose logs > production.log
```

---

## 🔐 Seguridad en Producción

✅ **Checklist de seguridad:**

- [ ] HTTPS habilitado y válido
- [ ] Contraseñas de base de datos fuertes
- [ ] JWT_SECRET_KEY no expuesto
- [ ] .env.production en .gitignore
- [ ] Firewall configurado (solo 80, 443)
- [ ] SSH con claves, no contraseña
- [ ] Backups automatizados configurados
- [ ] Logs monitoreados
- [ ] Updates de seguridad aplicadas

### Comando de hardening (opcional)

```bash
# Actualizar sistema
sudo apt update && sudo apt upgrade -y

# Configurar firewall
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw enable

# Desabilitar acceso directo a puertos internos
sudo ufw deny 5432      # PostgreSQL
sudo ufw deny 6379      # Redis
```

---

## 📞 Recursos útiles

- **Docker Compose**: https://docs.docker.com/compose/
- **Nginx**: https://nginx.org/en/docs/
- **Let's Encrypt**: https://letsencrypt.org/
- **PostgreSQL**: https://www.postgresql.org/docs/
- **Redis**: https://redis.io/

---

## 🎯 Próximos pasos después del despliegue

1. Configurar backups automáticos (cron)
2. Configurar monitoreo (Prometheus, Grafana)
3. Configurar alertas (email, Telegram)
4. Documentar procedimientos de recuperación
5. Realizar simulacro de disaster recovery

---

**Última actualización**: 2026-06-12  
**Versión**: 1.0.0  
**Mantenedor**: ScanOPS Team
