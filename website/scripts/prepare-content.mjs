import { execFileSync } from 'node:child_process';
import { readFile, writeFile, mkdir, rm, copyFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { unified } from 'unified';
import remarkParse from 'remark-parse';
import remarkGfm from 'remark-gfm';
import remarkStringify from 'remark-stringify';
import { visit } from 'unist-util-visit';
import { toString } from 'mdast-util-to-string';
import { pages, assets, repository, routeUrl } from './content-manifest.mjs';

const website = fileURLToPath(new URL('../', import.meta.url));
const root = path.resolve(website, '..');
const parser = unified().use(remarkParse).use(remarkGfm).use(remarkStringify, { fences: true });

export function selectSections(tree, names) {
  if (!names) return tree;
  const selected = [];
  for (const name of names) {
    const start = tree.children.findIndex((node) => node.type === 'heading' && node.depth === 2 && toString(node) === name);
    if (start < 0) throw new Error(`Missing README section: ${name}`);
    let end = start + 1;
    while (end < tree.children.length && !(tree.children[end].type === 'heading' && tree.children[end].depth <= 2)) end++;
    selected.push(...tree.children.slice(start, end));
  }
  // Retain reference definitions used by the extracted sections.
  selected.push(...tree.children.filter((node) => node.type === 'definition'));
  return { type: 'root', children: selected };
}

export function validateManifest(manifest, tracked, assetPaths = []) {
  const urls = new Set();
  for (const page of manifest) {
    if (!tracked.has(page.source)) throw new Error(`Source is not tracked: ${page.source}`);
    if (/^(\/|\.\.)|(^|\/)(superpowers|testing|proposals)(\/|$)/.test(page.source)) throw new Error(`Private source: ${page.source}`);
    if (!/^docs\/[a-z0-9/-]+$/.test(page.route) || page.route.includes('..')) throw new Error(`Invalid route: ${page.route}`);
    const url = routeUrl(page.route);
    if (urls.has(url)) throw new Error(`Duplicate route: ${url}`);
    urls.add(url);
  }
  for (const asset of assetPaths) {
    if (!tracked.has(asset) || !asset.startsWith('docs/media/') || asset.includes('..')) throw new Error(`Unapproved asset: ${asset}`);
  }
}

export function rewriteUrl(url, source, manifest = pages, assetPaths = assets) {
  if (/^(https?:|mailto:|tel:)/i.test(url)) return url;
  if (/^[a-z][a-z\d+.-]*:/i.test(url) || url.startsWith('//')) throw new Error(`Unsupported link: ${url}`);
  const hashAt = url.indexOf('#');
  const fragment = hashAt < 0 ? '' : url.slice(hashAt);
  const pathname = hashAt < 0 ? url : url.slice(0, hashAt);
  const target = pathname ? path.posix.normalize(path.posix.join(path.posix.dirname(source), decodeURIComponent(pathname))) : source;
  const asset = assetPaths.find((value) => value === target);
  if (asset) return `/media/${path.posix.basename(asset)}${fragment}`;
  const destination = manifest.find((page) => page.source === target && !page.sections);
  if (destination) return routeUrl(destination.route) + fragment;
  if (target.startsWith('../') || target.startsWith('/') || /(^|\/)(superpowers|testing)(\/|$)/.test(target)) {
    throw new Error(`Link escapes publication boundary: ${source} -> ${url}`);
  }
  return `${repository}/blob/main/${target}${fragment}`;
}

export function renderPage(markdown, page, manifest = pages, assetPaths = assets) {
  const tree = selectSections(parser.parse(markdown), page.sections);
  // Starlight provides the page heading.
  const first = tree.children[0];
  if (first?.type === 'heading' && first.depth === 1) tree.children.shift();
  visit(tree, (node) => {
    if (['link', 'image', 'definition'].includes(node.type)) node.url = rewriteUrl(node.url, page.source, manifest, assetPaths);
  });
  const frontmatter = [
    '---', `title: ${JSON.stringify(page.title)}`,
    `description: ${JSON.stringify(`${page.title} for xdr-cli, the Microsoft Defender XDR investigation CLI.`)}`,
    `editUrl: ${JSON.stringify(`${repository}/edit/main/${page.source}`)}`,
    ...(page.search === false ? ['pagefind: false'] : []), '---', '',
  ].join('\n');
  return frontmatter + parser.stringify(tree);
}

export async function prepareContent() {
  const tracked = new Set(execFileSync('git', ['ls-files', '-z'], { cwd: root, encoding: 'utf8' }).split('\0'));
  validateManifest(pages, tracked, assets);
  const destination = path.join(website, 'src/content/docs');
  // Render and validate all source documents before replacing generated inputs.
  const rendered = await Promise.all(pages.map(async (page) => ({
    page, content: renderPage(await readFile(path.join(root, page.source), 'utf8'), page),
  })));
  await rm(destination, { recursive: true, force: true });
  await mkdir(destination, { recursive: true });
  for (const { page, content } of rendered) {
    const filename = path.join(destination, `${page.route}.md`);
    await mkdir(path.dirname(filename), { recursive: true });
    await writeFile(filename, content);
  }
  const media = path.join(website, 'public/media');
  await rm(media, { recursive: true, force: true });
  await mkdir(media, { recursive: true });
  for (const asset of assets) await copyFile(path.join(root, asset), path.join(media, path.basename(asset)));
  console.log(`Prepared ${pages.length} documentation pages from explicitly selected tracked sources.`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await prepareContent();
