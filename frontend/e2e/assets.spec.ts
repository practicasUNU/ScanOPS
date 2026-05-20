import { test, expect } from '@playwright/test';
import { loginAs } from './helpers/auth';

test.describe('M1 — Asset Manager', () => {

  test.beforeEach(async ({ page }) => {
    await loginAs(page, 'system_manager');
    await page.goto('/assets');
    await page.waitForURL(/assets/, { timeout: 10000 });
  });

  test('US-8.4 — La página de activos carga con la tabla de inventario', async ({ page }) => {
    await expect(page.locator('text=Asset Manager').first()).toBeVisible({ timeout: 10000 });
    await expect(page.locator('text=Inventario Oficial').first()).toBeVisible();
    await expect(page.locator('text=Shadow IT').first()).toBeVisible();
    await expect(page.locator('text=Credenciales').first()).toBeVisible();
  });

  test('US-8.4 — La tabla de inventario muestra cabeceras de columna', async ({ page }) => {
    await page.waitForSelector('table tbody tr, [data-testid="asset-row"]', { timeout: 10000 })
      .catch(() => {});
    await expect(page.locator('text=ACTIVO').first()).toBeVisible();
    await expect(page.locator('text=CRITICIDAD').first()).toBeVisible();
  });

  test('US-8.4 — Botón "Nuevo Activo" abre el dialog de creación', async ({ page }) => {
    const newAssetBtn = page.locator('button:has-text("Nuevo Activo")').first();
    await expect(newAssetBtn).toBeVisible({ timeout: 10000 });
    await newAssetBtn.click();
    await expect(page.locator('text=Registrar un nuevo activo').first()).toBeVisible({ timeout: 5000 });
    await page.keyboard.press('Escape');
  });

  test('US-8.4 — Tab Shadow IT carga sin errores', async ({ page }) => {
    const shadowTab = page.locator('text=Shadow IT').first();
    await shadowTab.click();
    await expect(page.locator('text=Hosts descubiertos').first()).toBeVisible({ timeout: 10000 });
  });

  test('US-8.4 — Tab Credenciales muestra el banner de Vault', async ({ page }) => {
    const vaultTab = page.locator('text=Credenciales').first();
    await vaultTab.click();
    await expect(page.locator('text=HashiCorp Vault').first()).toBeVisible({ timeout: 10000 });
  });

});
