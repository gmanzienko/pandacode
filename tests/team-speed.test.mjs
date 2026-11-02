import test from 'node:test';
import assert from 'node:assert/strict';
import { keepSpeed, modelSpeedTiers, namedTeamSetup, speedOptions } from '../src/team-mode.ts';

// Real shapes from the Codex catalog: GPT-6.1 Sol and GPT-6 Astra list Fast and Ultrafast, GPT-6 Luna
// only Fast, GPT-5.6 Sol none; Nova 9 is a fictional model with a fictional tier. Keys come from native.
const tier = (id, name, key, description) => ({ id, key, name, description });
const FAST = tier('priority', 'Fast', 'fast', '2x speed, increased usage');
const ULTRAFAST = tier('ultrafast', 'Ultrafast', 'ultrafast', 'The fastest available responses.');
const TURBO = tier('turbo', 'Turbo Max', 'turbo-max', 'Fictional "max" & <fast>.');
const providers = [
  { id: 'codex', models: [
    { id: 'gpt-6.1-sol', name: 'GPT-6.1-Sol', description: '', speedTiers: [FAST, ULTRAFAST] },
    { id: 'gpt-6-astra', name: 'GPT-6-Astra', description: '', speedTiers: [FAST, ULTRAFAST] },
    { id: 'gpt-6-luna', name: 'GPT-6-Luna', description: '', speedTiers: [FAST] },
    { id: 'gpt-5.6-sol', name: 'GPT-5.6-Sol', description: '' },
    { id: 'nova-9', name: 'Nova 9', description: '', speedTiers: [TURBO] },
  ] },
  { id: 'claude', models: [{ id: 'opus', name: 'Opus', description: '' }] },
];
const labels = html => [...html.matchAll(/<option value="([^"]*)"[^>]*>([^<]*)<\/option>/g)].map(m => [m[1], m[2]]);

test('the Speed select lists Default plus exactly the tiers the model\'s catalog reports', () => {
  const options = model => labels(speedOptions(modelSpeedTiers(providers, 'codex', model)));
  assert.deepEqual(options('gpt-6.1-sol'), [['', 'Default'], ['fast', 'Fast'], ['ultrafast', 'Ultrafast']]);
  assert.deepEqual(options('gpt-6-astra'), [['', 'Default'], ['fast', 'Fast'], ['ultrafast', 'Ultrafast']]);
  assert.deepEqual(options('gpt-6-luna'), [['', 'Default'], ['fast', 'Fast']]);
  assert.deepEqual(options('nova-9'), [['', 'Default'], ['turbo-max', 'Turbo Max']]);
  // No tiers: no Speed control at all (other harnesses and unknown models alike).
  assert.equal(speedOptions(modelSpeedTiers(providers, 'codex', 'gpt-5.6-sol')), '');
  assert.equal(speedOptions(modelSpeedTiers(providers, 'claude', 'opus')), '');
  assert.equal(speedOptions(modelSpeedTiers(providers, 'codex', 'gone')), '');
  // The catalog's description is the option's title, escaped; the saved tier is selected.
  const html = speedOptions(modelSpeedTiers(providers, 'codex', 'nova-9'), 'turbo-max');
  assert.match(html, /value="turbo-max" title="Fictional &#34;max&#34; &#38; &#60;fast&#62;\." selected/);
  // A saved tier the (not yet loaded) list lacks is shown as such, never silently replaced.
  assert.deepEqual(labels(speedOptions([], 'fast')), [['', 'Default'], ['fast', 'fast (not in the catalog)']]);
});

test('changing the model drops a tier the new model lacks, with a one-line note', () => {
  const tiers = model => modelSpeedTiers(providers, 'codex', model);
  assert.deepEqual(keepSpeed('fast', tiers('gpt-6-luna'), 'gpt-6-luna', tiers('gpt-6.1-sol')), { tier: 'fast', note: '' });
  assert.deepEqual(keepSpeed('ultrafast', tiers('gpt-6-luna'), 'gpt-6-luna', tiers('gpt-6.1-sol')), { tier: null, note: "Ultrafast is not in gpt-6-luna's catalog, so speed is Default." });
  assert.deepEqual(keepSpeed('turbo-max', tiers('gpt-5.6-sol'), 'gpt-5.6-sol', tiers('nova-9')), { tier: null, note: "Turbo Max is not in gpt-5.6-sol's catalog, so speed is Default." });
  assert.deepEqual(keepSpeed('fast', [], 'opus'), { tier: null, note: "fast is not in opus's catalog, so speed is Default." });
  assert.deepEqual(keepSpeed(null, [], 'opus'), { tier: null, note: '' });
});

test('a named team saves the chosen tier key for Codex workers only, as native will check it', () => {
  const lead = { provider: 'codex', harness: 'Codex', model: 'nova-9', name: 'Nova 9', serviceTier: 'turbo-max', speedTiers: [TURBO] };
  const claude = { provider: 'claude', harness: 'Claude Code', model: 'opus', name: 'Opus', serviceTier: 'fast' };
  const { config } = namedTeamSetup('Quick', lead, [lead, claude]);
  assert.equal(config.workers[0].serviceTier, 'turbo-max');
  assert.equal('serviceTier' in config.workers[1], false);
});
