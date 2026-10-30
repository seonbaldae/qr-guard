import { copyFile, lstat, mkdir, readdir, rm } from 'node:fs/promises';
import { dirname, extname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Packaging only: no dependency installation, compilation, or server code.
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const output = join(root, 'dist');
const sources = new Map([
  ['src', new Set(['.js', '.css'])],
  ['assets', new Set(['.svg', '.png', '.jpg', '.jpeg', '.webp', '.gif', '.ico'])],
]);
let copied = 0;

async function copyStaticDirectory(relativePath, extensions) {
  const entries = await readdir(join(root, relativePath), { withFileTypes: true });
  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    if (entry.name.startsWith('.')) continue;
    const child = join(relativePath, entry.name);
    if (entry.isSymbolicLink()) throw new Error('Static deployment sources must not contain symbolic links.');
    if (entry.isDirectory()) {
      await copyStaticDirectory(child, extensions);
    } else if (entry.isFile() && extensions.has(extname(entry.name).toLowerCase())) {
      await mkdir(dirname(join(output, child)), { recursive: true });
      await copyFile(join(root, child), join(output, child));
      copied += 1;
    }
  }
}

// Remove stale generated output so previous builds cannot publish extra files.
try {
  const existing = await lstat(output);
  if (!existing.isDirectory() || existing.isSymbolicLink()) {
    throw new Error('The deployment output must be a regular dist directory.');
  }
} catch (error) {
  if (error.code !== 'ENOENT') throw error;
}
if (!(await lstat(join(root, 'index.html'))).isFile()) {
  throw new Error('The static entry point must be a regular index.html file.');
}
for (const directory of sources.keys()) {
  const source = await lstat(join(root, directory));
  if (!source.isDirectory() || source.isSymbolicLink()) {
    throw new Error('Static deployment source directories must be regular directories.');
  }
}
await rm(output, { recursive: true, force: true });
await mkdir(output);
await copyFile(join(root, 'index.html'), join(output, 'index.html'));
copied += 1;
for (const [directory, extensions] of sources) {
  await copyStaticDirectory(directory, extensions);
}
process.stdout.write(`Prepared ${copied} frontend files in dist/.\n`);
