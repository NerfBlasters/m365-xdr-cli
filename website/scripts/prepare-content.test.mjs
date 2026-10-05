import { test } from 'node:test';
import assert from 'node:assert/strict';
import { renderPage, rewriteUrl, validateManifest } from './prepare-content.mjs';

const manifest = [
  { source: 'README.md', route: 'docs/index', title: 'Handbook' },
  { source: 'docs/guide.md', route: 'docs/guide', title: 'Guide' },
];

test('selects real headings, preserving fenced code and resolving reference links', () => {
  const input = '# Project\n\n## Install\n\n```sh\n## Not a heading\nxdr --version\n```\n\n[Guide][ref]\n\n## Other\n\nExcluded content\n\n[ref]: docs/guide.md#setup\n';
  const rendered = renderPage(input, { ...manifest[0], sections: ['Install'] }, manifest);
  assert.match(rendered, /```sh\n## Not a heading\nxdr --version\n```/);
  assert.match(rendered, /\[ref\]: \/docs\/guide\/#setup/);
  assert.doesNotMatch(rendered, /Excluded content/);
  assert.throws(() => renderPage(input, { ...manifest[0], sections: ['Missing'] }, manifest), /Missing README section/);
});

test('maps docs, media and local anchors while retaining external/source links', () => {
  assert.equal(rewriteUrl('../README.md#install', 'docs/guide.md', manifest), '/docs/#install');
  assert.equal(rewriteUrl('#setup', 'docs/guide.md', manifest), '/docs/guide/#setup');
  assert.equal(rewriteUrl('docs/media/investigate.gif', 'README.md'), '/media/investigate.gif');
  assert.equal(rewriteUrl('https://example.com/#test', 'README.md'), 'https://example.com/#test');
  assert.match(rewriteUrl('../src/example.py', 'docs/guide.md', manifest), /\/blob\/main\/src\/example.py$/);
  assert.throws(() => rewriteUrl('../../secret', 'docs/guide.md', manifest), /boundary/);
  assert.throws(() => rewriteUrl('superpowers/private.md', 'docs/guide.md', manifest), /boundary/);
  assert.throws(() => rewriteUrl('javascript:alert(1)', 'README.md'), /Unsupported link/);
});

test('publication requires tracked, explicit inputs and unique safe routes', () => {
  const tracked = new Set(['README.md', 'docs/guide.md', 'docs/superpowers/private.md']);
  assert.doesNotThrow(() => validateManifest(manifest, tracked));
  assert.throws(() => validateManifest([{ ...manifest[0], source: 'private.md' }], tracked), /not tracked/);
  assert.throws(() => validateManifest([{ ...manifest[0], source: 'docs/superpowers/private.md' }], tracked), /Private source/);
  assert.throws(() => validateManifest([...manifest, manifest[0]], tracked), /Duplicate route/);
  assert.throws(() => validateManifest([{ ...manifest[0], route: '../escape' }], tracked), /Invalid route/);
  assert.throws(() => validateManifest(manifest, tracked, ['docs/media/untracked.gif']), /Unapproved asset/);
});
