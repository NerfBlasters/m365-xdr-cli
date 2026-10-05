import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import accessibleTables from './scripts/accessible-tables.mjs';
import { unified } from '@astrojs/markdown-remark';

export default defineConfig({
  site: 'https://xdr-cli.com',
  trailingSlash: 'always',
  markdown: { processor: unified({ rehypePlugins: [accessibleTables] }) },
  integrations: [starlight({
    title: 'xdr-cli',
    description: 'Microsoft Defender XDR tools built for AI agents, with investigation playbooks, advanced hunting, and compact results.',
    favicon: '/favicon.svg',
    disable404Route: true,
    social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/NerfBlasters/m365-xdr-cli' }],
    customCss: ['./src/styles/site.css'],
    components: {
      SiteTitle: './src/components/SiteTitle.astro',
      PageTitle: './src/components/PageTitle.astro',
      Footer: './src/components/Footer.astro',
    },
    head: [
      { tag: 'meta', attrs: { property: 'og:image', content: 'https://xdr-cli.com/social.png' } },
      { tag: 'meta', attrs: { name: 'twitter:card', content: 'summary_large_image' } },
      { tag: 'meta', attrs: { name: 'theme-color', content: '#101a1b' } },
    ],
    sidebar: [
      { label: 'Start here', items: [
        { label: 'Get started', slug: 'docs/getting-started' },
        { label: 'Portal-cookie sign-in', slug: 'docs/authentication/portal-cookie' },
        { label: 'Entra app registration', slug: 'docs/authentication/entra' },
        { label: 'Read your results', slug: 'docs/results' },
        { label: 'Work with an AI agent', slug: 'docs/agents' },
      ] },
      { label: 'Investigate', items: [
        { label: 'Investigation methodology', slug: 'docs/investigation' },
        { label: 'Query library', slug: 'docs/library' },
        { label: 'Reference lists', slug: 'docs/lists' },
        { label: 'Find a playbook', slug: 'docs/playbooks' },
      ] },
      { label: 'Reference', items: [
        { label: 'Commands and configuration', slug: 'docs/commands' },
        { label: 'Troubleshooting', slug: 'docs/troubleshooting' },
        { label: 'Agent instructions', slug: 'docs/agent-instructions' },
        { label: 'Complete handbook', slug: 'docs' },
      ] },
      { label: 'Go deeper', collapsed: true, items: [{ autogenerate: { directory: 'docs/advanced' } }] },
      { label: 'All playbooks', collapsed: true, items: [{ autogenerate: { directory: 'docs/playbooks' } }] },
      { label: 'Contribute', collapsed: true, items: [{ autogenerate: { directory: 'docs/contributing' } }] },
      { label: 'Changelog', slug: 'docs/changelog' },
      { label: 'Report a vulnerability', slug: 'docs/security' },
    ],
    credits: false,
  })],
});
