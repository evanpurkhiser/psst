import {build} from 'esbuild';

import {execFile} from 'node:child_process';
import {
  access,
  chmod,
  copyFile,
  cp,
  mkdir,
  mkdtemp,
  readFile,
  rm,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {promisify} from 'node:util';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const source = path.join(root, 'browser-extension');
const output = path.join(root, 'target/browser-extension');
const release = process.argv.slice(2);

if (release.some(argument => argument !== '--release')) {
  throw new Error('usage: build-browser-extension.mjs [--release]');
}

await rm(output, {force: true, recursive: true});
await mkdir(output, {recursive: true});
await copyFile(path.join(source, 'manifest.json'), path.join(output, 'manifest.json'));

await build({
  bundle: true,
  entryPoints: {
    background: path.join(source, 'src/background.ts'),
    bridge: path.join(source, 'src/bridge.ts'),
    relay: path.join(source, 'src/relay.ts'),
  },
  format: 'iife',
  legalComments: 'none',
  outdir: output,
  target: 'chrome115',
});

if (release.includes('--release')) {
  const key = process.env.PSST_CHROME_EXTENSION_KEY_FILE;
  if (!key) {
    throw new Error('PSST_CHROME_EXTENSION_KEY_FILE is required for release builds');
  }
  await access(key);

  const run = promisify(execFile);
  const manifest = JSON.parse(await readFile(path.join(source, 'manifest.json'), 'utf8'));
  const [{stdout: publicKey}, {stdout: cargoMetadata}] = await Promise.all([
    run('openssl', ['rsa', '-in', key, '-pubout', '-outform', 'DER'], {
      encoding: 'buffer',
    }),
    run('cargo', ['metadata', '--format-version=1', '--no-deps'], {
      cwd: root,
      encoding: 'utf8',
    }),
  ]);
  const packageVersion = JSON.parse(cargoMetadata).packages.find(
    pkg => pkg.name === 'psst-cli',
  )?.version;
  if (manifest.key !== publicKey.toString('base64')) {
    throw new Error('manifest key does not match the signing key');
  }
  if (manifest.version !== packageVersion) {
    throw new Error('extension and package versions do not match');
  }

  const temporary = await mkdtemp(path.join(os.tmpdir(), 'psst-extension-'));
  try {
    const extension = path.join(temporary, 'extension');
    await cp(output, extension, {recursive: true});
    await run(process.env.CHROME_BIN ?? 'google-chrome-stable', [
      '--no-sandbox',
      `--pack-extension=${extension}`,
      `--pack-extension-key=${key}`,
    ]);

    const releaseOutput =
      process.env.PSST_CHROME_EXTENSION_OUTPUT ??
      path.join(root, 'target/psst-chrome-extension.crx');
    await copyFile(path.join(temporary, 'extension.crx'), releaseOutput);
    await chmod(releaseOutput, 0o644);
    console.log(releaseOutput);
  } finally {
    await rm(temporary, {force: true, recursive: true});
  }
}
