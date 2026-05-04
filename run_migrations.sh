#!/bin/bash
# run_migrations.sh - Ejecuta las migraciones de Alembic dentro del contenedor

echo "Esperando a que la base de datos esté lista..."
# Se asume que el healthcheck de Docker maneja la espera del servicio postgres

echo "Ejecutando migraciones de base de datos..."
# Especificamos la ruta del archivo de configuración corregido
alembic -c alembic/alembic.ini upgrade head

if [ $? -eq 0 ]; then
    echo "Migraciones completadas con éxito."
else
    echo "ERROR: Fallaron las migraciones. Verifique la configuración en alembic/alembic.ini"
    exit 1
fi
