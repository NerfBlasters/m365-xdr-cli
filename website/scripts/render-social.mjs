import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { chromium } from '@playwright/test';

// Render the share card from editable HTML; no image-editing application needed.
const browser = await chromium.launch({
  executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH || undefined,
});
try {
  const page = await browser.newPage({ viewport: { width: 1200, height: 630 }, deviceScaleFactor: 1 });
  await page.setContent(await readFile(new URL('../src/social-card.html', import.meta.url), 'utf8'));
  await page.screenshot({ path: fileURLToPath(new URL('../public/social.png', import.meta.url)) });
  console.log('Rendered public/social.png from src/social-card.html.');
} finally {
  await browser.close();
}
