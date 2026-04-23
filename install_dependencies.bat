@echo off
setlocal enabledelayedexpansion

echo === ScanOPS Installation Script ===

:: 1. Verifica Python 3.8+
echo Verificando version de Python...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python no esta instalado en el PATH.
    pause
    exit /b 1
)

for /f "tokens=2" %%v in ('python --version') do (
    for /f "tokens=1,2 delims=." %%a in ("%%v") do (
        if %%a lss 3 (
            echo [ERROR] Python 3.8 o superior es requerido. Version detectada: %%v
            pause
            exit /b 1
        )
        if %%a equ 3 (
            if %%b lss 8 (
                echo [ERROR] Python 3.8 o superior es requerido. Version detectada: %%v
                pause
                exit /b 1
            )
        )
    )
)
echo Python detectado: OK

:: 2. Crea virtualenv si no existe
if not exist venv (
    echo Creando entorno virtual (venv)...
    python -m venv venv
) else (
    echo Entorno virtual ya existe.
)

:: Activar entorno virtual
echo Activando entorno virtual...
call venv\Scripts\activate

:: Asegurar pip actualizado
python -m pip install --upgrade pip

:: 3. pip install -e .
echo Instalando dependencias del nucleo (editable)...
pip install -e .

:: 4. pip install -r requirements-dev.txt (para tests)
if exist requirements-dev.txt (
    echo Instalando dependencias de desarrollo...
    pip install -r requirements-dev.txt
) else (
    echo [AVISO] requirements-dev.txt no encontrado.
)

:: 5. Verifica que psycopg2 se instaló
echo Verificando instalacion de psycopg2...
python -c "import psycopg2; print('psycopg2 importado con exito')" >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] psycopg2 no se instalo correctamente.
    echo Intente ejecutar: pip install psycopg2-binary
    pause
    exit /b 1
)

:: 6. Echo "✅ Instalación completada"
echo.
echo ✅ Instalacion completada correctamente.
echo Para empezar, activa el entorno con: venv\Scripts\activate
echo.
pause
