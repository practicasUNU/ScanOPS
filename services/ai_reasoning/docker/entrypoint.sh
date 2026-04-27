#!/bin/bash
# Arrancar el servidor Ollama en segundo plano
ollama serve &
OLLAMA_PID=$!

# Esperar a que el servidor esté listo
echo "Esperando a que Ollama arranque..."
sleep 5

# Descargar modelo si no está ya descargado
if ! ollama list | grep -q "llama3"; then
    echo "Descargando llama3..."
    ollama pull llama3
else
    echo "llama3 ya disponible"
fi

# Mantener el proceso principal activo
wait $OLLAMA_PID
