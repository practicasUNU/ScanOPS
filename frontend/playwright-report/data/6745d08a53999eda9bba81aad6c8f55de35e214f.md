# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: compliance.spec.ts >> US-8.9 — Cumplimiento ENS Alto >> US-8.10 — Sección de informes M7 está presente
- Location: e2e\compliance.spec.ts:43:3

# Error details

```
TimeoutError: page.waitForURL: Timeout 15000ms exceeded.
=========================== logs ===========================
waiting for navigation until "load"
============================================================
```

# Page snapshot

```yaml
- generic [ref=e4]:
  - generic [ref=e5]:
    - img [ref=e7]
    - heading "ScanOps" [level=1] [ref=e9]
    - paragraph [ref=e10]: Penetration Testing & ENS Alto Compliance
  - generic [ref=e12]:
    - generic [ref=e13]:
      - generic [ref=e14]: Usuario
      - generic [ref=e15]:
        - img [ref=e16]
        - textbox "admin" [ref=e19]
    - generic [ref=e20]:
      - generic [ref=e21]: Password
      - generic [ref=e22]:
        - img [ref=e23]
        - textbox "••••••••••" [ref=e26]: scanops_admin_2026
    - generic [ref=e27]:
      - generic [ref=e28]: TOTP Code
      - generic [ref=e29]:
        - img [ref=e30]
        - textbox "000000" [ref=e34]
    - generic [ref=e35]:
      - img [ref=e36]
      - text: Failed to fetch
    - button "Acceder" [ref=e38]
    - button "Use FIDO2 key instead" [ref=e40]
```

# Test source

```ts
  1  | import { Page } from '@playwright/test';
  2  | 
  3  | export const TEST_CREDENTIALS = {
  4  |   system_manager: { username: 'admin', password: 'scanops_admin_2026' },
  5  |   auditor: { username: 'auditor', password: 'scanops_audit_2026' },
  6  | };
  7  | 
  8  | export async function loginAs(
  9  |   page: Page,
  10 |   role: keyof typeof TEST_CREDENTIALS = 'system_manager',
  11 | ): Promise<void> {
  12 |   const creds = TEST_CREDENTIALS[role];
  13 | 
  14 |   await page.goto('/login');
  15 |   await page.waitForSelector(
  16 |     'input[type="text"], input[name="username"], input[placeholder*="usuario" i]',
  17 |     { timeout: 10000 },
  18 |   );
  19 | 
  20 |   const usernameInput = page.locator('input[type="text"], input[name="username"]').first();
  21 |   await usernameInput.fill(creds.username);
  22 | 
  23 |   const passwordInput = page.locator('input[type="password"]').first();
  24 |   await passwordInput.fill(creds.password);
  25 | 
  26 |   const totpInput = page.locator('input[placeholder="000000"]').first();
  27 |   if (await totpInput.isVisible()) {
  28 |     await totpInput.fill('000000');
  29 |   }
  30 | 
  31 |   const submitBtn = page.locator('button[type="submit"]').first();
  32 |   await submitBtn.click();
  33 | 
  34 |   // EventSource-based SSE auth uses the token from sessionStorage — wait for redirect
> 35 |   await page.waitForURL(url => url.pathname !== '/login', { timeout: 15000 });
     |              ^ TimeoutError: page.waitForURL: Timeout 15000ms exceeded.
  36 | }
  37 | 
  38 | export async function expectLoggedIn(page: Page): Promise<void> {
  39 |   await page
  40 |     .waitForSelector('[data-testid="sidebar"], nav, aside', { timeout: 5000 })
  41 |     .catch(() => {});
  42 | }
  43 | 
```