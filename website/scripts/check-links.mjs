import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { load } from 'cheerio';
import { pages, routeUrl } from './content-manifest.mjs';

const dist = fileURLToPath(new URL('../dist/', import.meta.url));
async function walk(directory) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const filename = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await walk(filename));
    else files.push(filename);
  }
  return files;
}
const files = await walk(dist);
const html = new Map();
for (const file of files.filter((file) => file.endsWith('.html'))) {
  const url = '/' + path.relative(dist, file).split(path.sep).join('/').replace(/index\.html$/, '');
  html.set(url, load(await readFile(file, 'utf8')));
}
const errors = [];
for (const page of pages) if (!html.has(routeUrl(page.route))) errors.push(`Missing page ${routeUrl(page.route)}`);
for (const [url, $] of html) {
  for (const element of $('[href], [src], [data-src]').toArray()) {
    const attr = $(element).attr('href') ?? $(element).attr('src') ?? $(element).attr('data-src');
    if (!attr || /^(mailto:|tel:|data:|javascript:)/.test(attr)) continue;
    const target = new URL(attr, 'https://xdr-cli.com' + url);
    if (target.origin !== 'https://xdr-cli.com') continue;
    const pathname = decodeURIComponent(target.pathname);
    if (html.has(pathname)) {
      const fragment = decodeURIComponent(target.hash.slice(1));
      if (fragment && !html.get(pathname)('[id]').toArray().some((node) => html.get(pathname)(node).attr('id') === fragment)) errors.push(`${url}: missing anchor ${attr}`);
    } else {
      const filename = path.resolve(dist, '.' + pathname);
      if (!filename.startsWith(dist)) { errors.push(`${url}: unsafe path ${attr}`); continue; }
      try { if (!(await stat(filename)).isFile()) errors.push(`${url}: not a file ${attr}`); }
      catch { errors.push(`${url}: missing ${attr}`); }
    }
  }
}
for (const file of files) if (/(^|\/)(superpowers|proposals|testing)(\/|$)/.test(path.relative(dist, file))) errors.push(`Private path published: ${file}`);
if (errors.length) {
  console.error([...new Set(errors)].join('\n'));
  process.exitCode = 1;
} else console.log(`Verified ${html.size} HTML pages: internal links, fragments, assets and publication paths.`);
