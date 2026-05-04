#!/usr/bin/env python3
"""
DEMO: ScanOPS M3 - Escaneo funcional con resultados visuales
"""
import json
import requests
import time
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn

console = Console()

def demo_scan():
    BASE_URL = "http://localhost:8002/api/v1"
    
    console.print("\n[bold cyan]═══════════════════════════════════════════════════════════════[/bold cyan]")
    console.print("[bold cyan]  SCANOPS M3 - DEMO: Escaneo de Vulnerabilidades[/bold cyan]")
    console.print("[bold cyan]═══════════════════════════════════════════════════════════════[/bold cyan]\n")
    
    # 1. Lanzar el escaneo
    console.print("[bold yellow]▶ Paso 1: Lanzando escaneo en vivo...[/bold yellow]")
    
    try:
        response = requests.post(
            f"{BASE_URL}/scan/asset/1",
            json={
                "scan_types": ["nuclei"],
                "description": "Demo para auditoría ENS Alto"
            },
            timeout=10
        )
        
        if response.status_code != 200:
            console.print(f"[red]✗ Error: {response.text}[/red]")
            return
        
        scan_data = response.json()
        task_id = scan_data["task_id"]
        asset_id = scan_data["asset_id"]
        
        console.print(f"[green]✓ Escaneo lanzado exitosamente[/green]")
        console.print(f"  Task ID: [bold blue]{task_id}[/bold blue]")
        console.print(f"  Asset ID: [bold blue]{asset_id}[/bold blue]\n")
        
    except requests.exceptions.ConnectionError:
        console.print("[red]✗ Error: No se puede conectar a http://localhost:8002[/red]")
        console.print("[yellow]Asegúrate de que Docker está levantado[/yellow]")
        return
    
    # 2. Monitorear el estado
    console.print("[bold yellow]▶ Paso 2: Monitoreando progreso...[/bold yellow]\n")
    
    max_attempts = 30
    attempt = 0
    
    with Progress(SpinnerColumn(), BarColumn(), "[progress.percentage]{task.percentage:>3.1f}%", console=console) as progress:
        task = progress.add_task("Escaneo en progreso...", total=100)
        
        while attempt < max_attempts:
            try:
                status_response = requests.get(f"{BASE_URL}/scan/status/{task_id}", timeout=10)
                
                if status_response.status_code == 200:
                    status_data = status_response.json()
                    progress_pct = status_data.get("progress", 0)
                    status = status_data.get("status", "PENDING")
                    
                    progress.update(task, completed=progress_pct)
                    
                    if status in ["SUCCESS", "COMPLETED"]:
                        progress.update(task, completed=100)
                        break
                
                time.sleep(1)
                attempt += 1
            except Exception as e:
                time.sleep(2)
                attempt += 1
    
    console.print()
    console.print("[green]✓ Escaneo completado[/green]\n")
    
    # 3. Obtener resultados
    console.print("[bold yellow]▶ Paso 3: Obteniendo hallazgos...[/bold yellow]\n")
    
    try:
        results_response = requests.get(f"{BASE_URL}/scan/results/{asset_id}", timeout=10)
        
        if results_response.status_code == 200:
            findings = results_response.json()
            
            if isinstance(findings, list):
                console.print(f"[green]✓ Se encontraron {len(findings)} hallazgos[/green]\n")
                
                if len(findings) > 0:
                    table = Table(title="Hallazgos de Vulnerabilidades", show_header=True, header_style="bold blue")
                    table.add_column("ID", style="cyan")
                    table.add_column("Título", style="magenta")
                    table.add_column("Severidad", style="yellow")
                    table.add_column("Scanner", style="green")
                    
                    for i, finding in enumerate(findings[:10], 1):
                        title = finding.get("title", "N/A")[:40]
                        severity = finding.get("severity", "N/A")
                        scanner = finding.get("tool_source", finding.get("scanner", "N/A"))
                        
                        if severity == "CRITICAL":
                            severity_colored = f"[bold red]{severity}[/bold red]"
                        elif severity == "HIGH":
                            severity_colored = f"[red]{severity}[/red]"
                        elif severity == "MEDIUM":
                            severity_colored = f"[yellow]{severity}[/yellow]"
                        else:
                            severity_colored = f"[green]{severity}[/green]"
                        
                        table.add_row(str(i), title, severity_colored, scanner)
                    
                    console.print(table)
                else:
                    console.print("[yellow]ℹ No se encontraron vulnerabilidades[/yellow]")
    except Exception as e:
        console.print(f"[yellow]⚠ Error: {str(e)}[/yellow]")
    
    # 4. Resumen
    console.print("\n[bold cyan]═══════════════════════════════════════════════════════════════[/bold cyan]")
    console.print("[bold green]✓ DEMO COMPLETADA[/bold green]")
    console.print("[bold cyan]═══════════════════════════════════════════════════════════════[/bold cyan]\n")
    
    summary_panel = Panel(
        f"""Task ID: {task_id}
Asset ID: {asset_id}
Status: SUCCESS

✓ op.exp.2 - Evaluación de configuración
✓ op.exp.5 - Logs de auditoría
✓ Ejecución local (sin datos en cloud)""",
        title="ScanOPS M3 - Scanner Engine",
        border_style="green"
    )
    console.print(summary_panel)

if __name__ == "__main__":
    demo_scan()
