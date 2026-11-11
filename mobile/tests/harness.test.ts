/// <reference types="node" />
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import test from 'node:test';

// Importing harness.tsx would pull in expo-image and react-native, which node --test cannot resolve.
const source = readFileSync(new URL('../src/ui/harness.tsx', import.meta.url), 'utf8');
const mobileMark = new URL('../assets/providers/qoder.svg', import.meta.url);
const desktopMark = new URL('../../src/assets/providers/qoder.svg', import.meta.url);
const sha256 = (file: URL) => createHash('sha256').update(readFileSync(file)).digest('hex');

test('the qoder harness lists its own mark with no flags, byte-identical to the desktop copy', () => {
  const entry = source.match(/^  qoder: .*$/m)?.[0];
  assert.ok(entry, 'HARNESSES has no qoder entry');
  assert.match(entry, /name: 'Qoder'/);
  assert.match(entry, /logo: require\('\.\.\/\.\.\/assets\/providers\/qoder\.svg'\)/);
  assert.doesNotMatch(entry, /mono/, 'a tint would flatten the two-colour mark');
  assert.doesNotMatch(entry, /black/, 'the mark carries a light canvas, not a dark tile');
  assert.ok(existsSync(mobileMark), 'mobile/assets/providers/qoder.svg is missing');
  assert.equal(sha256(mobileMark), sha256(desktopMark), 'the mobile mark must be a byte-for-byte copy');
});