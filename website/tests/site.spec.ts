import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { customRoutes, pages, routeUrl } from '../scripts/content-manifest.mjs';

for (const mode of ['standard', 'verbose']) {
  test(`${mode} video loads on demand and supports pause and seeking`, async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'no-preference' });
    const videoRequests: string[] = [];
    page.on('request', (request) => {
      if (request.url().endsWith('.mp4')) videoRequests.push(request.url());
    });
    await page.goto('/');
    const video = page.locator(`video[aria-labelledby="demo-${mode}"]`);
    await video.scrollIntoViewIfNeeded();
    await expect(video).toHaveAttribute('preload', 'none');
    await expect(video).toHaveAttribute('controlslist', 'nodownload');
    await expect(video).toHaveJSProperty('paused', true);
    expect(videoRequests).toEqual([]);
    const playback = await video.evaluate(async (element: HTMLVideoElement) => {
      await element.play();
      await new Promise<void>((resolve) => element.addEventListener('timeupdate', () => resolve(), { once: true }));
      const played = !element.paused && element.currentTime > 0;
      element.pause();
      element.currentTime = 60;
      await new Promise<void>((resolve) => element.addEventListener('seeked', () => resolve(), { once: true }));
      return { played, paused: element.paused, time: element.currentTime };
    });
    expect(playback).toEqual({ played: true, paused: true, time: 60 });
    expect(videoRequests.length).toBeGreaterThan(0);
    await expect(page.locator('a[download], .demo-pause')).toHaveCount(0);
  });
}

test('demo players stay still on load, with correct prompt and harness labels', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  const animatedRequests: string[] = [];
  page.on('request', (request) => {
    if (/\.(gif|mp4)$/.test(request.url())) animatedRequests.push(request.url());
  });
  await page.goto('/');
  for (const mode of ['standard', 'verbose']) {
    const video = page.locator(`video[aria-labelledby="demo-${mode}"]`);
    await video.scrollIntoViewIfNeeded();
    await expect(video).toHaveAttribute('poster', `/media/copilot-${mode}.png`);
    await expect(video).toHaveJSProperty('autoplay', false);
  }
  expect(animatedRequests).toEqual([]);
  await expect(page.locator('.demos')).toContainText('Copilot harness display settings');
  await expect(page.locator('.demo-prompt')).toContainText('extract the IOCs and tactics');
  await expect(page.locator('.demo-prompt a')).toHaveAttribute('href', 'https://thehackernews.com/2026/10/clickfix-smuggles-payloads-through.html');
});

for (const theme of ['light', 'dark'] as const) {
  for (const width of [375, 768, 1440]) {
    test(`homepage is accessible at ${width}px in ${theme}`, async ({ page }, testInfo) => {
      await page.setViewportSize({ width, height: 1000 });
      await page.emulateMedia({ colorScheme: theme, reducedMotion: 'reduce' });
      await page.goto('/');
      await expect(page.getByRole('heading', { level: 1 })).toContainText('coding agent');
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
      expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze()).violations).toEqual([]);
      await page.screenshot({ path: testInfo.outputPath(`home-${width}-${theme}.png`), fullPage: true });
    });
  }
}

for (const route of ['/docs/getting-started/', '/docs/authentication/entra/', '/docs/authentication/portal-cookie/', '/docs/library/', '/docs/playbooks/', '/docs/advanced/schema-reference/', '/404.html']) {
  test(`readable mobile documentation: ${route}`, async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 900 });
    await page.goto(route);
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    // Expressive Code adds keyboard focus after its debounced resize observer.
    // Wait for the actual accessible state before running axe; a persistent
    // failure to initialize still fails this check.
    await expect.poll(() => page.locator('.expressive-code pre').evaluateAll((blocks) =>
      blocks.filter((block) => block.scrollWidth > block.clientWidth && block.getAttribute('tabindex') !== '0').length,
    )).toBe(0);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(375);
    expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze()).violations).toEqual([]);
  });
}

test('copy, theme persistence and keyboard search', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('/');
  await page.getByRole('button', { name: 'Copy installation command' }).click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe('pipx install "git+https://github.com/NerfBlasters/m365-xdr-cli.git"');
  await expect(page.getByRole('status')).toContainText('copied');
  await page.getByRole('combobox', { name: 'Select theme' }).selectOption('light');
  await page.reload();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await page.keyboard.press('Control+k');
  await expect(page.getByRole('dialog', { name: 'Search' })).toBeVisible();
  await page.locator('.pagefind-ui__search-input').fill('portal');
  await expect(page.locator('.pagefind-ui__result').first()).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.getByRole('dialog', { name: 'Search' })).not.toBeVisible();
});

test('search indexes operational docs and returns only published routes', async ({ page }) => {
  await page.goto('/');
  const result = await page.evaluate(async () => {
    // Pagefind's public browser API is emitted by the production build.
    const modulePath = '/pagefind/pagefind.js';
    const search = await import(/* @vite-ignore */ modulePath);
    const terms = ['portal', 'investigate', 'kerberos', 'API_TIMEOUT', '2026-10-04-website-design'];
    return await Promise.all(terms.map(async (term) => {
      const result = await search.search(term);
      const documents = await Promise.all(result.results.map((entry: { data: () => Promise<{ url: string }> }) => entry.data()));
      return { term, count: result.results.length, urls: documents.map((document: { url: string }) => document.url) };
    }));
  });
  expect(result.slice(0, 4).every((entry) => entry.count > 0)).toBe(true);
  const published = new Set([...customRoutes, ...pages.map((entry) => routeUrl(entry.route))]);
  // Pagefind tokenizes filenames/dates, so a private filename can match public
  // changelog words. Check actual returned routes rather than assuming zero hits.
  for (const query of result) for (const url of query.urls) expect(published.has(new URL(url, 'https://xdr-cli.com').pathname)).toBe(true);
});

test('core reading and links work without JavaScript', async ({ browser }) => {
  const context = await browser.newContext({ javaScriptEnabled: false, viewport: { width: 375, height: 900 } });
  const page = await context.newPage();
  await page.goto('http://127.0.0.1:4321/');
  await page.getByRole('link', { name: 'Start investigating' }).click();
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Get started');
  await expect(page.getByRole('heading', { name: 'Two ways to sign in', exact: true })).toBeVisible();
  await context.close();
});

test('mobile navigation and skip link work with the keyboard', async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 900 });
  await page.goto('/docs/getting-started/');
  await page.keyboard.press('Tab');
  await expect(page.getByRole('link', { name: 'Skip to content' })).toBeFocused();
  await page.keyboard.press('Enter');
  await page.getByRole('button', { name: 'Menu', exact: true }).click();
  await expect(page.getByRole('link', { name: 'Query library', exact: true }).first()).toBeVisible();
});
