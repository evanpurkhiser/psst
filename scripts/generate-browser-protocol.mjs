import {execFile} from 'node:child_process';
import {writeFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {promisify} from 'node:util';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const {stdout} = await promisify(execFile)(
  'cargo',
  ['run', '--quiet', '-p', 'psst-cli', '--', 'browser', 'schema'],
  {cwd: root, encoding: 'utf8'},
);

await writeFile(path.join(root, 'browser-extension/src/browser-protocol.ts'), stdout);
