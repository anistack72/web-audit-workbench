import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
const root = new URL('.', import.meta.url);
function demo(format) {
  return execFileSync(process.execPath, ['demo.mjs', format], {
    cwd: root, encoding: 'utf8', timeout: 15000, maxBuffer: 2 * 1024 * 1024,
  });
}
test('documented JSON demo produces a labeled structured report', () => {
  const report = JSON.parse(demo('json'));
  assert.match(report.summary, /SYNTHETIC FIXTURE DEMO/);
  assert.ok(Array.isArray(report.checks) && report.checks.length > 0);
});
test('documented HTML demo is standalone and labels simulated data', () => {
  const html = demo('html');
  assert.match(html, /<!doctype html>/i);
  assert.match(html, /SYNTHETIC FIXTURE DEMO/);
  assert.doesNotMatch(html, /<(?:script|link)\b[^>]*(?:src|href)=["']https?:/i);
});
test('documented terminal demo completes without a live service', () => {
  assert.match(demo('text'), /SYNTHETIC FIXTURE DEMO/);
});
