import test from 'node:test';
import assert from 'node:assert/strict';
import { dupModelNames, limitTeamModels, TEAM_LIMIT, toggleTeamModel } from '../src/team-catalog.ts';

const models = n => [{ id: 'default' }, ...Array.from({ length: n }, (_, i) => ({ id: `m${i}` }))];
const ids = result => result.models.map(m => m.id);

test('a long catalog keeps default and its most recent models in the catalog', () => {
  const recent = ['gone', 'm3', 'm3', ...Array.from({ length: 15 }, (_, i) => `m${14 - i}`)];
  const result = limitTeamModels(models(20), { recent, added: [] });
  assert.equal(result.limited, true);
  assert.equal(result.total, 20);
  assert.equal(result.recent.size, TEAM_LIMIT);
  assert.deepEqual([...result.recent], ['m3', 'm14', 'm13', 'm12', 'm11', 'm10', 'm9', 'm8', 'm7', 'm6']);
  assert.deepEqual(ids(result), ['default', 'm3', 'm6', 'm7', 'm8', 'm9', 'm10', 'm11', 'm12', 'm13', 'm14']);
});

test('added models join the recent ones', () => {
  const result = limitTeamModels(models(20), { recent: ['m0'], added: ['m19', 'm5'] });
  assert.deepEqual(ids(result), ['default', 'm0', 'm5', 'm19']);
  assert.deepEqual([...result.recent], ['m0']);
});

test('ten models or fewer (default not counted) pass through', () => {
  const result = limitTeamModels(models(10), { recent: [], added: [] });
  assert.equal(result.limited, false);
  assert.deepEqual(ids(result), ids({ models: models(10) }));
});

test('an unlimited catalog (OpenCode with a saved selection) passes through', () => {
  const result = limitTeamModels(models(300), { recent: ['m1'], added: [], unlimited: true });
  assert.equal(result.limited, false);
  assert.equal(result.models.length, 301);
});

test('an excluded recent model leaves the catalog and the next recent one takes its place (issue #315)', () => {
  const recent = Array.from({ length: 15 }, (_, i) => `m${i}`);
  const result = limitTeamModels(models(20), { recent, added: [], excluded: ['m0'] });
  assert.equal(result.limited, true);
  assert.deepEqual([...result.recent], ['m1', 'm2', 'm3', 'm4', 'm5', 'm6', 'm7', 'm8', 'm9', 'm10']);
  assert.deepEqual(ids(result), ['default', 'm1', 'm2', 'm3', 'm4', 'm5', 'm6', 'm7', 'm8', 'm9', 'm10']);
});

test('an exclusion hides a model entirely until it is added again', () => {
  const dropped = limitTeamModels(models(20), { recent: ['m19'], added: ['m19'], excluded: ['m19'] });
  assert.deepEqual(ids(dropped), ['default']);
  const back = limitTeamModels(models(20), { recent: ['m19'], added: [], excluded: [] });
  assert.deepEqual(ids(back), ['default', 'm19']);
});

test('exclusions never apply to short or unlimited catalogs', () => {
  assert.deepEqual(ids(limitTeamModels(models(10), { recent: ['m3'], added: [], excluded: ['m3'] })), ids(limitTeamModels(models(10), { recent: [], added: [] })));
  assert.equal(limitTeamModels(models(300), { recent: [], added: [], excluded: ['m1'], unlimited: true }).models.length, 301);
});

test('toggling uses the exclusion list only for a model recency would keep', () => {
  const recent = Array.from({ length: 12 }, (_, i) => `m${i}`);
  const limit = { recent, added: [], excluded: [] };
  // In the recent slots: off excludes it, on clears that.
  const off = toggleTeamModel(models(20), limit, 'm0', false);
  assert.deepEqual(off, { added: [], excluded: ['m0'] });
  assert.deepEqual(toggleTeamModel(models(20), { ...limit, ...off }, 'm0', true), { added: [], excluded: [] });
  // A recent model past the slots is really off, so on must add it, and off then just un-adds it.
  const on = toggleTeamModel(models(20), limit, 'm11', true);
  assert.deepEqual(on, { added: ['m11'], excluded: [] });
  assert.deepEqual(toggleTeamModel(models(20), { ...limit, ...on }, 'm11', false), { added: [], excluded: [] });
  // Never recent: only the added list moves.
  assert.deepEqual(toggleTeamModel(models(20), limit, 'm15', true), { added: ['m15'], excluded: [] });
});

test('dupModelNames finds only the names a catalog uses more than once', () => {
  const dupes = dupModelNames([
    { id: 'deepseek/deepseek-flash', name: 'DeepSeek V4.1 Flash' },
    { id: 'default', name: 'Default model' },
    { id: 'opencode-go/deepseek-v4.1-flash', name: 'DeepSeek V4.1 Flash' },
    { id: 'anthropic/claude-sonnet-4', name: 'Claude Sonnet 4' },
  ]);
  assert.deepEqual([...dupes], ['DeepSeek V4.1 Flash']);
});

// Tiers as native reports them on Codex model lists: key (from the catalog name), name and description.
const tier = (id, name, key) => ({ id, key, name, description: `${name} speed.` });
const FAST = tier('priority', 'Fast', 'fast'), ULTRAFAST = tier('ultrafast', 'Ultrafast', 'ultrafast'), TURBO = tier('turbo', 'Turbo Max', 'turbo-max');

test('every catalog tier of every Codex model becomes a <model>@<key> variant after every model', async () => {
  const { buildTeamCatalog, CATALOG_MAX } = await import('../src/team-catalog.ts');
  const { catalog, roster } = buildTeamCatalog([
    { id: 'codex', name: 'Codex', models: [{ id: 'default', name: 'Default', speedTiers: [FAST] }, { id: 'gpt-6.1-sol', name: 'GPT-6.1 Sol', speedTiers: [FAST, ULTRAFAST] }, { id: 'gpt-6-luna', name: 'GPT-6 Luna', speedTiers: [FAST] }, { id: 'nova-9', name: 'Nova 9', speedTiers: [TURBO] }, { id: 'plain', name: 'Plain' }] },
    { id: 'claude', name: 'Claude Code', models: [{ id: 'opus', name: 'Opus', speedTiers: [FAST] }] },
  ]);
  assert.deepEqual(catalog.map(p => p.model), ['default', 'opus', 'gpt-6.1-sol', 'gpt-6-luna', 'nova-9', 'plain', 'gpt-6.1-sol@fast', 'gpt-6.1-sol@ultrafast', 'gpt-6-luna@fast', 'nova-9@turbo-max']);
  const turbo = catalog.find(p => p.model === 'nova-9@turbo-max');
  assert.deepEqual({ ...turbo }, { id: 'codex-nova-9-turbo-max', name: 'Nova 9 Turbo Max · Codex', provider: 'codex', model: 'nova-9@turbo-max', reasoningEffort: null });
  assert.equal(catalog.find(p => p.model === 'gpt-6.1-sol@ultrafast').name, 'GPT-6.1 Sol Ultrafast · Codex');
  assert.equal(new Set(catalog.map(p => p.id)).size, catalog.length);
  assert.ok(roster.every(p => !p.model.includes('@')), 'the roster lists models, not variants');
  // A full catalog has no room left: variants never displace a model.
  const many = Array.from({ length: CATALOG_MAX }, (_, i) => ({ id: `m${i}`, name: `M${i}`, speedTiers: [FAST] }));
  const full = buildTeamCatalog([{ id: 'codex', name: 'Codex', models: many }]).catalog;
  assert.equal(full.length, CATALOG_MAX);
  assert.ok(full.every(p => !p.model.includes('@')));
});
