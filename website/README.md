# xdr-cli.com

The public landing page and searchable documentation for xdr-cli. Source lives
on `main` alongside the CLI. GitHub Actions builds the site and deploys it to
GitHub Pages after the full CI gate passes. Cloudflare provides DNS.

## Local development

Use the Node version in `.node-version` (24.21.0) and npm:

```bash
cd website
npm ci --ignore-scripts
npm run dev
```

Open the local address printed by Astro. Search requires a production build:

```bash
npm test
npm run check
npm run build
npm run preview
```

Astro may start its preview server in the background when it detects an agent.
Use `npx astro preview stop` to stop it, or `--ignore-lock` to keep it in the
foreground. All local servers bind to 127.0.0.1 by default.

For browser and accessibility checks:

```bash
npx --no-install playwright install chromium
npm run test:browser
```

The suite starts a production preview if needed. On systems with an existing
Chromium installation, set `PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH` to its absolute
path. Screenshots and failure traces are written to ignored `test-results/`.

## Updating content

Edit the original `README.md`, `docs/`, `playbooks/`, or root policy document.
`scripts/content-manifest.mjs` explicitly maps published documents to routes,
page titles and optional README section selections. New documents require a
manifest entry and appropriate sidebar placement in `astro.config.mjs`.

`npm run content` regenerates `src/content/docs/` and `public/media/`. These
directories are disposable and gitignored; never edit them. Publication accepts
tracked, explicitly listed sources only. Newly added source documents must be
staged in Git before building. Private plans, testing notes and proposal content
are excluded. A link to a tracked proposal can still lead to its GitHub source.

Relative Markdown links are resolved against their original file, then mapped
to the website if that document is published or to GitHub otherwise. Excerpts
retain references to the complete handbook for cross-section anchors. Code
blocks are parsed as Markdown nodes, so headings and paths inside commands are
not rewritten. Generated docs have edit links to their original source.

The production build crawls local links, anchors and assets and fails on missing
targets. The getting-started walkthrough uses expanded incident evidence and
links to the investigation methodology and playbooks.

## Styling and assets

- `src/pages/index.astro`: custom homepage and its small interactive controls.
- `src/styles/site.css`: shared light/dark colors, fonts and documentation styles.
- `src/components/`: small Starlight overrides for project branding.
- `public/favicon.svg` and `public/social.png`: locally served brand assets.
- `src/social-card.html`: editable link-preview card; run `npm run social` after
  changing its copy (requires the same Chromium setup as the browser checks).
- `src/pages/404.astro`: standalone accessible error page.
- `src/pages/pricing.astro`: tongue-in-cheek free-tier comparison and the
  explicitly marked creator-note placeholder. Custom page routes are listed
  in `customRoutes` in the content manifest.

The homepage includes standard and verbose Copilot investigation recordings.
Their approved MP4s and static posters live in `docs/media/` and are explicitly
listed in the content manifest. Native video players appear side by side on
wider screens and stack on smaller screens. They do not autoplay or preload the
videos, and the page offers no direct download links. Standard/verbose describes
the Copilot harness display settings, not an xdr-cli setting. Publish
only reviewed, sanitized recordings, never private source casts or review files.

The site uses system fonts. No analytics, third-party font requests, tenant
authentication, backend service or Cloudflare credentials are required to build
or serve it. Search runs against Pagefind's static index.

## CI and deployment

The `website` job in `.github/workflows/ci.yml` runs for all CI events.
It installs locked dependencies, audits them, runs
content and browser checks, and saves browser evidence. The existing `CI gate`
requires it to succeed. PR jobs have read-only repository permissions.

Only a successful `main` push or manual `main` CI run uploads the Pages artifact
and enters the deployment job, which uses the `github-pages` environment and
`pages: write` / `id-token: write`. Scheduled checks never publish. Production
is built from the exact checkout that passed the rest of CI. The build publishes
only `website/dist/`, not the repository checkout. No `gh-pages` source branch
or separate wiki is involved.

One-time repository/domain setup:

1. In repository Settings → Pages, select GitHub Actions as the publishing source.
2. In the owner's Pages settings, verify `xdr-cli.com` with GitHub's supplied TXT
   record. Retain that TXT record after verification.
3. Set the repository Pages custom domain to `xdr-cli.com`. With an Actions
   workflow, a committed CNAME file is not used to configure the domain.
4. Inspect Cloudflare records before changing them. Configure the apex using
   GitHub's current published A/AAAA records or supported ALIAS/CNAME-flattening
   option, and `www` as a CNAME to `nerfblasters.github.io`. Start DNS-only while
   GitHub validates DNS and provisions the certificate. Preserve other records.
5. Enable Enforce HTTPS after certificate issuance; verify apex and www redirect,
   docs deep links, search and a nonexistent path. DNS/cert readiness can take time.

Cloudflare credentials remain in the maintainer's secret store. They are needed
only for DNS administration, not ordinary deploys.

See the official [custom-domain instructions](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/managing-a-custom-domain-for-your-github-pages-site)
and [domain-verification instructions](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/verifying-your-custom-domain-for-github-pages)
for current records and ownership steps.

Rollback: revert the site change through a PR and deploy the resulting passing
main build. If an urgent deploy rollback is needed, use a retained known-good
Pages deployment. Preserve the domain configuration and unrelated DNS records;
do not leave DNS pointing at a disabled/unclaimed Pages site.
