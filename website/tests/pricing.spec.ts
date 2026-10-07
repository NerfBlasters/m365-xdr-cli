import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

for (const theme of ['light', 'dark'] as const) {
  for (const width of [375, 768, 1440]) {
    test(`pricing is accessible at ${width}px in ${theme}`, async ({ page }, testInfo) => {
      await page.setViewportSize({ width, height: 1200 });
      await page.emulateMedia({ colorScheme: theme, reducedMotion: 'reduce' });
      await page.goto('/pricing/');
      await expect(page.getByRole('heading', { level: 1 })).toHaveText('Pick your favorite column.');
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
      expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze()).violations).toEqual([]);
      await page.screenshot({ path: testInfo.outputPath(`pricing-${width}-${theme}.png`), fullPage: true });
    });
  }
}

test('tiers include identical features and reveal free prices with keyboard controls', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('link', { name: 'Pricing', exact: true }).click();
  await expect(page).toHaveURL(/\/pricing\/$/);
  const tiers = page.locator('.tier');
  await expect(tiers).toHaveCount(3);
  const features = await tiers.locator('.features').allTextContents();
  expect(features[0]).toBe(features[1]);
  expect(features[1]).toBe(features[2]);
  await expect(tiers.nth(0).locator('.price')).toHaveText('Free');
  for (let i = 1; i < 3; i++) {
    const tier = tiers.nth(i);
    await expect(tier.locator('.revealed-price')).not.toBeVisible();
    await tier.locator('summary').focus();
    await page.keyboard.press('Enter');
    await expect(tier.locator('.revealed-price')).toContainText('Yeah, also free.');
    await expect(tier.locator('.price')).toHaveText('$0/user/mo');
  }
  await expect(page.locator('.annual-deal')).toContainText('20 users × $0/mo = $0/mo');
  await expect(page.locator('.annual-deal')).toContainText('20% discount');
  await expect(page.locator('.creator-note')).toContainText('placeholder');
  expect(await page.locator('.creator-note .placeholder').textContent()).toBe("<Placeholder for heartfelt note from the creator about giving back to the community, and that if it wasn't for free tools and free education he wouldn't be where he was today.  Shoutout to John Strand, the whole BHIS crew, and antisyphon training, with links to BHIS and antisyphon training> below the joke pricing tiers - no, damnit, don't paraphrase, it's not heartfelt if AI writes it.  Just print exactly what I type into this section.  No inference needed, just copy/paste/done.  Seriously, this isn't that hard, just fill in the block of text.");
});

test('pricing reveals work without JavaScript', async ({ browser }) => {
  const context = await browser.newContext({ javaScriptEnabled: false });
  try {
    const page = await context.newPage();
    await page.goto('http://127.0.0.1:4321/pricing/');
    for (const details of await page.locator('.price-reveal').all()) {
      await details.locator('summary').click();
      await expect(details.locator('.price')).toHaveText('$0/user/mo');
    }
  } finally { await context.close(); }
});
