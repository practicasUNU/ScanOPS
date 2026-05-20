import { test, expect } from '@playwright/test';
import { loginAs } from './helpers/auth';

test.describe('US-8.9 — Cumplimiento ENS Alto', () => {

  test.beforeEach(async ({ page }) => {
    await loginAs(page, 'system_manager');
    await page.goto('/compliance');
    await page.waitForURL(/compliance/, { timeout: 10000 });
  });

  test('La página de cumplimiento ENS carga correctamente', async ({ page }) => {
    await expect(page.locator('text=Cumplimiento ENS Alto').first()).toBeVisible({ timeout: 10000 });
    await expect(page.locator('text=RD 311/2022').first()).toBeVisible({ timeout: 10000 });
  });

  test('El score de cumplimiento es visible', async ({ page }) => {
    await expect(page.locator('text=%').first()).toBeVisible({ timeout: 10000 });
  });

  test('Las KPI cards de estado están presentes', async ({ page }) => {
    await expect(page.locator('text=Conformes').first()).toBeVisible({ timeout: 10000 });
    await expect(page.locator('text=Parciales').first()).toBeVisible({ timeout: 10000 });
    await expect(page.locator('text=No aplica').first()).toBeVisible({ timeout: 10000 });
  });

  test('La tabla de medidas ENS es filtrable por texto', async ({ page }) => {
    const rows = page.locator('table tbody tr');
    await expect(rows.first()).toBeVisible({ timeout: 10000 });

    const searchInput = page.locator('input[placeholder*="Buscar"]').first();
    await searchInput.fill('op.exp.1');
    await expect(page.locator('text=op.exp.1').first()).toBeVisible({ timeout: 5000 });
  });

  test('US-8.9 — Click en medida abre panel de detalle con evidencia', async ({ page }) => {
    const firstRow = page.locator('table tbody tr').first();
    await firstRow.waitFor({ timeout: 10000 });
    await firstRow.click();
    await expect(page.locator('text=Evidencia técnica').first()).toBeVisible({ timeout: 5000 });
  });

  test('US-8.10 — Sección de informes M7 está presente', async ({ page }) => {
    await expect(page.locator('text=Informe Ejecutivo').first()).toBeVisible({ timeout: 10000 });
    await expect(page.locator('text=Declaración de Aplicabilidad').first()).toBeVisible({ timeout: 10000 });
  });

  test('US-8.11 — Página de Logs de Auditoría carga correctamente', async ({ page }) => {
    await page.goto('/audit-logs');
    await expect(page.locator('text=Logs de Auditoría').first()).toBeVisible({ timeout: 10000 });
    await expect(page.locator('text=ENS op.exp.5').first()).toBeVisible({ timeout: 10000 });
  });

});
