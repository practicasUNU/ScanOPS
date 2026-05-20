import { test, expect } from '@playwright/test';
import { loginAs } from './helpers/auth';

test.describe('Dashboard y Pipeline Semanal', () => {

  test.beforeEach(async ({ page }) => {
    await loginAs(page, 'system_manager');
  });

  test('US-8.4 — Dashboard carga con KPIs globales', async ({ page }) => {
    await page.goto('/dashboard');
    await expect(page.locator('text=ScanOps').first()).toBeVisible({ timeout: 10000 });
    await expect(page.locator('text=Ciclo activo').first()).toBeVisible({ timeout: 10000 });
  });

  test('US-8.5 — El pipeline semanal muestra las fases M1 y M2', async ({ page }) => {
    await page.goto('/dashboard');
    await expect(page.locator('text=M1').first()).toBeVisible({ timeout: 10000 });
    await expect(page.locator('text=M2').first()).toBeVisible({ timeout: 10000 });
  });

  test('US-8.6 — Kill switch está presente en el dashboard', async ({ page }) => {
    await page.goto('/dashboard');
    const killSwitchBtn = page
      .locator('button:has-text("Kill Switch"), button:has-text("KILL")')
      .first();
    await expect(killSwitchBtn).toBeVisible({ timeout: 10000 });
  });

  test('US-8.8 — Página de alertas SIEM carga correctamente', async ({ page }) => {
    await page.goto('/alerts');
    await expect(page.locator('text=SIEM').first()).toBeVisible({ timeout: 10000 });
  });

  test('US-8.7 — Página de explotación carga la cola de aprobaciones', async ({ page }) => {
    await page.goto('/exploitation');
    await expect(page).toHaveURL(/exploitation/);
    await page.waitForLoadState('networkidle', { timeout: 10000 });
  });

  test('US-8.8 — M8 IA Reasoning muestra el stepper de fases', async ({ page }) => {
    await page.goto('/ai-reasoning');
    await expect(page.locator('text=Filtro Falsos Positivos').first()).toBeVisible({ timeout: 10000 });
    await expect(page.locator('text=Validación Humana').first()).toBeVisible({ timeout: 10000 });
  });

  test('Sidebar — todos los módulos están en el menú', async ({ page }) => {
    await page.goto('/dashboard');
    await expect(page.locator('text=M1 - Asset Manager').first()).toBeVisible({ timeout: 10000 });
    await expect(page.locator('text=M2+M3').first()).toBeVisible({ timeout: 10000 });
    await expect(page.locator('text=M8 - IA Reasoning').first()).toBeVisible({ timeout: 10000 });
    await expect(page.locator('text=M4').first()).toBeVisible({ timeout: 10000 });
    await expect(page.locator('text=M7').first()).toBeVisible({ timeout: 10000 });
  });

});
