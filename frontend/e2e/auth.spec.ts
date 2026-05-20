import { test, expect } from '@playwright/test';
import { loginAs } from './helpers/auth';

test.describe('Autenticación y Control de Acceso', () => {

  test('US-8.2 — La página de login carga correctamente', async ({ page }) => {
    await page.goto('/login');
    await expect(page).toHaveTitle(/ScanOps/i);
    await expect(page.locator('input[type="password"]').first()).toBeVisible();
  });

  test('US-8.2 — Credenciales incorrectas muestran error', async ({ page }) => {
    await page.goto('/login');

    const usernameInput = page.locator('input[type="text"], input[name="username"]').first();
    const passwordInput = page.locator('input[type="password"]').first();

    await usernameInput.fill('usuario_invalido');
    await passwordInput.fill('contraseña_invalida');

    const submitBtn = page
      .locator('button[type="submit"], button:has-text("Iniciar"), button:has-text("Login")')
      .first();
    await submitBtn.click();

    await expect(page).toHaveURL(/login/);
  });

  test('US-8.3 — Ruta protegida redirige a login sin sesión', async ({ page }) => {
    await page.goto('/assets');
    await expect(page).toHaveURL(/login/);
  });

  test('US-8.3 — Ruta /compliance requiere autenticación', async ({ page }) => {
    await page.goto('/compliance');
    await expect(page).toHaveURL(/login/);
  });

  test('US-8.2 — Login exitoso como system_manager navega al dashboard', async ({ page }) => {
    await loginAs(page, 'system_manager');
    await expect(page).not.toHaveURL(/login/);
    await expect(page.locator('text=ScanOps').first()).toBeVisible({ timeout: 10000 });
  });

  test('US-8.3 — system_manager puede acceder a /assets', async ({ page }) => {
    await loginAs(page, 'system_manager');
    await page.goto('/assets');
    await expect(page).toHaveURL(/assets/);
    await expect(page.locator('text=Asset Manager').first()).toBeVisible({ timeout: 10000 });
  });

});
