# En services/recon_engine/tasks/scan_tasks.py
from shared.celery_app import app
from ..services.scanner_network import run_nmap # Nombre corregido según code.txt

@app.task(bind=True, name="run_recon_complete")
def run_recon_complete(self, target_ips):
    # Nota: Tu función run_nmap actual recibe un Set[int] de puertos 
    # Para el Hito 2, asegúrate de pasarle los datos que espera.
    resultado = run_nmap(ports={22, 80, 443}) 
    return resultado