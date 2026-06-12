# ⚡ ScanOPS - Quick Start Deployment

Guía rápida para desplegar ScanOPS en producción en 5 pasos.

## 🚀 Despliegue en 5 minutos

### 1️⃣ Preparar servidor

```bash
ssh user@servidor.com
git clone https://github.com/tu-usuario/ScanOPS.git
cd ScanOPS
```

### 2️⃣ Configurar secretos

```bash
cp .env.production.example .env.production

# Generar contraseñas fuertes
openssl rand -base64 32  # Copiar al .env.production
openssl rand -hex 32     # Para JWT_SECRET_KEY

# Editar .env.production
nano .env.production
# Cambiar: DB_PASSWORD, REDIS_PASSWORD, JWT_SECRET_KEY, PLATFORM_URL
```

### 3️⃣ Desplegar

```bash
chmod +x deploy.production.sh
sudo ./deploy.production.sh
```

Esperado:
```
✅ Deployment completed!
📋 Service Status: all running
```

### 4️⃣ Configurar SSL

```bash
chmod +x setup-ssl.sh
sudo ./setup-ssl.sh --domain scanops.example.com --email admin@example.com
```

### 5️⃣ Apuntar DNS

```
A record: scanops.example.com → 192.168.x.x
```

---

## ✅ Verificar

```bash
# Health check
curl -I https://scanops.example.com/health

# Ver servicios
docker-compose ps

# Ver logs
docker-compose logs -f
```

---

## 🛠️ Troubleshooting rápido

| Problema | Solución |
|----------|----------|
| 502 Bad Gateway | `docker-compose logs nginx` |
| Certificado inválido | `./setup-ssl.sh --staging` para testing |
| Puerto ocupado | `sudo lsof -i :80 \| kill -9 <PID>` |
| Base de datos no conecta | `docker-compose restart postgres && sleep 30` |

---

## 📚 Documentación completa

Ver [DEPLOYMENT_SCANOPS.md](./DEPLOYMENT_SCANOPS.md) para instrucciones detalladas.

---

**Tiempo estimado**: 15 minutos  
**Requisitos**: Docker, 8GB RAM, dominio disponible
