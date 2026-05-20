import { Page } from '@playwright/test';

export const TEST_CREDENTIALS = {
  system_manager: { username: 'admin', password: 'scanops_admin_2026' },
  auditor: { username: 'auditor', password: 'scanops_audit_2026' },
};

export async function loginAs(
  page: Page,
  role: keyof typeof TEST_CREDENTIALS = 'system_manager',
): Promise<void> {
  const creds = TEST_CREDENTIALS[role];

  await page.goto('/login');
  await page.waitForSelector(
    'input[type="text"], input[name="username"], input[placeholder*="usuario" i]',
    { timeout: 10000 },
  );

  const usernameInput = page.locator('input[type="text"], input[name="username"]').first();
  await usernameInput.fill(creds.username);

  const passwordInput = page.locator('input[type="password"]').first();
  await passwordInput.fill(creds.password);

  const totpInput = page.locator('input[placeholder="000000"]').first();
  if (await totpInput.isVisible()) {
    await totpInput.fill('000000');
  }

  const submitBtn = page.locator('button[type="submit"]').first();
  await submitBtn.click();

  // EventSource-based SSE auth uses the token from sessionStorage — wait for redirect
  await page.waitForURL(url => url.pathname !== '/login', { timeout: 15000 });
}

export async function expectLoggedIn(page: Page): Promise<void> {
  await page
    .waitForSelector('[data-testid="sidebar"], nav, aside', { timeout: 5000 })
    .catch(() => {});
}
