import { expect, test, type Page } from '@playwright/test';

const trigger = (page: Page) => page.locator('#model-picker-trigger');
const picker = (page: Page) => page.getByRole('dialog', { name: 'Harness and model', exact: true });
const search = (page: Page) => picker(page).getByRole('combobox', { name: 'Search harnesses and models', exact: true });
const task = (page: Page) => page.evaluate(async () => {
  const { invoke } = await import((window as any).__pandacodePreviewUrl);
  const id = document.querySelector<HTMLElement>('#prompt')?.dataset.sessionId;
  return invoke('get_task', { sessionId: id });
});
const activeOption = (page: Page) => picker(page).locator('[role="option"][aria-selected="true"]');
/** Select-all as the platform spells it. */
const selectAllKey = process.platform === 'darwin' ? 'Meta+a' : 'Control+a';
const selectionText = (page: Page) => page.evaluate(() => window.getSelection()?.toString() ?? '');
/** Opens the picker, trying again while a composer redraw cancels a menu just opened. */
async function openOn(page: Page, tab: string): Promise<void> {
  await expect(async () => {
    if (!await picker(page).isVisible()) await trigger(page).click();
    await expect(picker(page).getByRole('tab', { name: tab, exact: true })).toBeVisible({ timeout: 1000 });
  }).toPass();
}

async function open(page: Page, url = '/?teams'): Promise<void> {
  await page.route('**/src/preview.ts*', async route => {
    const response = await route.fetch();
    await route.fulfill({ response, body: `${await response.text()}\nwindow.__pandacodePreviewUrl = import.meta.url;\n` });
  });
  await page.goto(url);
  await expect(page.locator('.task-item.selected')).toHaveAttribute('data-id', 'session-1');
  await expect(async () => {
    if (!await picker(page).isVisible()) await trigger(page).click();
    await expect(picker(page)).toBeVisible({ timeout: 1000 });
  }).toPass();
}

test('a delayed catalog rejection preserves the focused rail tab', async ({ page }) => {
  await open(page);
  await page.keyboard.press('Escape');
  await page.evaluate(async () => {
    const { invoke } = await import((window as any).__pandacodePreviewUrl);
    const { openModelPicker } = await import('/src/' + 'model-picker.ts');
    const providers = await invoke('list_providers', {});
    openModelPicker({
      anchor: document.querySelector('#model-picker-trigger')!, providers,
      current: { provider: 'zcode', model: 'default' }, canSwitchProvider: true,
      onSelect: async () => {},
      loadModels: async id => id === 'zcode'
        ? new Promise((_resolve, reject) => { (window as any).__rejectCatalog = () => reject(new Error('Catalog failed\nDetails unavailable')); })
        : providers.find((provider: any) => provider.id === id)?.models ?? [],
    });
  });
  const tab = picker(page).locator('[role="tab"][data-view="h:zcode"]');
  await tab.click();
  await tab.focus();
  await expect(tab).toBeFocused();
  await page.evaluate(() => (window as any).__rejectCatalog());
  await expect(tab).toHaveAttribute('data-tip', 'Catalog failed. Select to view details.');
  await expect(tab).toBeFocused();
  await expect(picker(page).locator('.model-menu-failure')).toHaveText('Catalog failed\nDetails unavailable');
});

for (const count of [70, 200]) test('family emoji summaries keep whole graphemes at ' + count + ' clusters', async ({ page }) => {
  const family = '👨‍👩‍👧';
  await page.addInitScript(text => { (window as any).__graphemeFailure = text; }, family.repeat(count));
  await page.route('**/src/preview.ts*', async route => {
    const response = await route.fetch();
    const source = (await response.text()).replace(/switch\s*\(command\)\s*\{/, "if (command === 'list_provider_models' && args.provider === 'zcode') throw new Error(window.__graphemeFailure);\n switch (command) {");
    await route.fulfill({ response, body: source });
  });
  await page.goto('/?teams');
  await openOn(page, 'ZCode');
  const expected = count === 70 ? family.repeat(count) : family.repeat(179) + '… Select to view details.';
  await expect(picker(page).getByRole('tab', { name: 'ZCode', exact: true })).toHaveAttribute('data-tip', expected);
});

for (const hostile of ['evil" onmouseover="window.__xss=1', 'toString', 'constructor']) test('remote provider ID stays inert: ' + hostile, async ({ page }) => {
  await open(page);
  await page.keyboard.press('Escape');
  await page.evaluate(async id => {
    const { invoke } = await import((window as any).__pandacodePreviewUrl);
    const { openModelPicker } = await import('/src/' + 'model-picker.ts');
    const providers = await invoke('list_providers', {});
    openModelPicker({
      anchor: document.querySelector('#model-picker-trigger')!, providers: [],
      current: { provider: 'codex', model: 'default' }, canSwitchProvider: true,
      onSelect: async () => {},
      loadModels: async () => [],
      loadProviders: async () => [{ ...providers.find((provider: any) => provider.id === 'codex'), id, name: 'Remote harness', installed: true }],
    });
  }, hostile);
  await expect(picker(page).getByRole('tab', { name: 'Remote harness', exact: true })).toBeVisible();
  await expect(picker(page).locator('[onmouseover]')).toHaveCount(0);
  expect(await picker(page).locator('.provider-logo').first().getAttribute('data-provider')).toBe(hostile);
  await expect(picker(page).locator('.provider-logo').first()).toHaveClass(/provider-logo-tile/);
  expect(await picker(page).locator('.provider-logo').first().evaluate(node => node.tagName)).toBe('SPAN');
  await expect(picker(page).locator('img[src^="function"]')).toHaveCount(0);
  expect(await page.evaluate(() => (window as any).__xss)).toBeUndefined();
});

test('whitespace-only discovery failures show a nonempty model fallback', async ({ page }) => {
  await page.route('**/src/preview.ts*', async route => {
    const response = await route.fetch();
    const source = (await response.text()).replace(/switch\s*\(command\)\s*\{/, "if (command === 'list_provider_models' && args.provider === 'zcode') throw new Error('   ');\n switch (command) {");
    await route.fulfill({ response, body: source });
  });
  await page.goto('/?teams');
  await openOn(page, 'ZCode');
  await picker(page).getByRole('tab', { name: 'ZCode', exact: true }).click();
  await expect(picker(page).locator('.model-menu-failure')).toHaveText('Could not load models.');
});

test('whitespace-only remote harness failures show a nonempty fallback', async ({ page }) => {
  await open(page);
  await page.keyboard.press('Escape');
  await page.evaluate(async () => {
    const { openModelPicker } = await import('/src/' + 'model-picker.ts');
    openModelPicker({
      anchor: document.querySelector('#model-picker-trigger')!, providers: [],
      current: { provider: 'codex', model: 'default' }, canSwitchProvider: true,
      onSelect: async () => {}, loadProviders: async () => { throw new Error('   '); },
    });
  });
  const failure = picker(page).locator('.model-menu-failure');
  await expect(failure).toBeVisible();
  await expect(failure).toHaveText('Could not load harnesses.');
});

test('long emoji discovery headlines never split a surrogate pair', async ({ page }) => {
  await page.addInitScript(() => { (window as any).__emojiFailure = '🚀'.repeat(181) + '\nDetails:\nUnavailable'; });
  await page.route('**/src/preview.ts*', async route => {
    const response = await route.fetch();
    const source = (await response.text()).replace(/switch\s*\(command\)\s*\{/, "if (command === 'list_provider_models' && args.provider === 'zcode') throw new Error(window.__emojiFailure);\n switch (command) {");
    await route.fulfill({ response, body: source });
  });
  await page.goto('/?teams');
  await openOn(page, 'ZCode');
  await expect(picker(page).getByRole('tab', { name: 'ZCode', exact: true })).toHaveAttribute('data-tip', '🚀'.repeat(179) + '… Select to view details.');
});

function cardContrast(node: Element): number {
  const ctx = document.createElement('canvas').getContext('2d')!;
  const rgba = (color: string) => {
    ctx.clearRect(0, 0, 1, 1); ctx.fillStyle = color; ctx.fillRect(0, 0, 1, 1);
    return [...ctx.getImageData(0, 0, 1, 1).data].map(value => value / 255);
  };
  const over = (fg: number[], bg: number[]) => fg.slice(0, 3).map((value, i) => value * fg[3] + bg[i] * (1 - fg[3])).concat(1);
  const ancestors: Element[] = [];
  for (let el: Element | null = node; el; el = el.parentElement) ancestors.unshift(el);
  let bg = [1, 1, 1, 1];
  for (const el of ancestors) bg = over(rgba(getComputedStyle(el).backgroundColor), bg);
  const fg = over(rgba(getComputedStyle(node).color), bg);
  const luminance = (color: number[]) => color.slice(0, 3).map(c => c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4)
    .reduce((sum, c, i) => sum + c * [0.2126, 0.7152, 0.0722][i], 0);
  return (Math.max(luminance(fg), luminance(bg)) + 0.05) / (Math.min(luminance(fg), luminance(bg)) + 0.05);
}

test('dark discovery failures meet AA contrast and keep high contrast overrides', async ({ page }) => {
  await openScrollableFailure(page);
  await page.evaluate(() => { document.documentElement.dataset.theme = 'dark'; });
  const failure = picker(page).locator('.model-menu-failure');
  const ratio = await failure.evaluate(cardContrast);
  expect(ratio).toBeGreaterThanOrEqual(4.5);
  await page.emulateMedia({ contrast: 'more' });
  expect(await failure.evaluate(node => getComputedStyle(node).backgroundColor)).toBe('rgba(0, 0, 0, 0)');
  expect(await failure.evaluate(node => getComputedStyle(node).borderTopWidth)).toBe('1px');
});

for (const [name, message] of [['empty', ''], ['whitespace', '   ']]) {
  test('model selection errors use a fallback for ' + name + ' messages', async ({ page }) => {
    await page.addInitScript(text => { (window as any).__emptySelectionError = text; }, message);
    await page.route('**/src/preview.ts*', async route => {
      const response = await route.fetch();
      const source = (await response.text()).replace(/switch\s*\(command\)\s*\{/, "if (command === 'configure_session') throw new Error(window.__emptySelectionError);\n switch (command) {");
      await route.fulfill({ response, body: source });
    });
    await page.goto('/?teams');
    await openOn(page, 'Codex');
    await picker(page).getByRole('tab', { name: 'Codex', exact: true }).click();
    await picker(page).getByRole('option', { name: 'Codex · GPT-6-Astra', exact: true }).click();
    const error = picker(page).locator('.model-menu-error');
    await expect(error).toBeVisible();
    await expect(error).toHaveText('Could not select model.');
    await expect(error).toHaveAttribute('tabindex', '0');
    expect((await error.boundingBox())!.height).toBeGreaterThan(0);
  });
}

test('select-all stays scoped on rail tabs and settings radios', async ({ page }) => {
  await open(page);
  for (const target of [picker(page).getByRole('tab', { name: 'Codex', exact: true }), picker(page).getByRole('radio', { name: 'Default', exact: true })]) {
    await page.evaluate(() => window.getSelection()?.removeAllRanges());
    await target.focus();
    await page.keyboard.press(selectAllKey);
    expect(await selectionText(page)).toBe('');
    await expect(target).toBeFocused();
  }
});

test('multiline failure rail tips punctuate an unpunctuated headline', async ({ page }) => {
  await page.route('**/src/preview.ts*', async route => {
    const response = await route.fetch();
    const source = (await response.text()).replace(/switch\s*\(command\)\s*\{/, "if (command === 'list_provider_models' && args.provider === 'zcode') throw new Error('ZCode exited before returning models\\n\\nDetails:\\nprovider config missing');\n switch (command) {");
    await route.fulfill({ response, body: source + '\nwindow.__pandacodePreviewUrl = import.meta.url;\n' });
  });
  await page.goto('/?teams');
  await openOn(page, 'ZCode');
  const tab = picker(page).getByRole('tab', { name: 'ZCode', exact: true });
  await expect(tab).toHaveAttribute('data-tip', 'ZCode exited before returning models. Select to view details.');
  await tab.hover();
  await expect(page.locator('.tip-bubble')).toHaveText('ZCode exited before returning models. Select to view details.');
});

test('a rejected remote harness load is a readable selectable failure', async ({ page }) => {
  await open(page);
  await page.keyboard.press('Escape');
  await expect(picker(page)).toHaveCount(0);
  const message = 'Could not load remote harnesses.\nCheck the remote connection and try again.';
  await page.evaluate(async message => {
    const { openModelPicker } = await import('/src/' + 'model-picker.ts');
    openModelPicker({
      anchor: document.querySelector('#model-picker-trigger')!,
      providers: [], current: { provider: 'codex', model: 'default' }, canSwitchProvider: true,
      onSelect: async () => {},
      loadProviders: async () => { throw new Error(message); },
    });
  }, message);
  const failure = picker(page).locator('.model-menu-failure');
  await expect(failure).toBeVisible();
  await expect(failure).toHaveText(message);
  await expect(picker(page).locator('.model-menu-group-heading')).toContainText('Unavailable');
  await expect(picker(page).getByRole('option')).toHaveCount(0);
  await failure.focus();
  await page.keyboard.press(selectAllKey);
  expect(await selectionText(page)).toBe(message);
});

// A failed catalog's full diagnostic must stay readable: the rail tip only summarizes it.
test('a long discovery failure is readable and scrollable in the list, with a short rail tip', async ({ page }) => {
  const frames = Array.from({ length: 40 }, (_, i) => `    at loadProviderConfig${i} (file:///Applications/ZCode.app/Contents/Resources/glm/zcode.cjs:${1000 + i}:${i * 7})`);
  const first = 'ZCode exited before returning models because the provider configuration could not be loaded from the desktop settings, and the bundled CLI stopped while reading provider_config.json from the profile';
  expect(first.length).toBeGreaterThan(180);
  const failure = [first, 'Error: provider config failed to load', 'Details:', ...frames, 'ZCODE-TAIL-MARKER: provider_config.json is missing'].join('\n');
  expect(failure.length).toBeGreaterThan(2000);
  // A second failed harness, so switching between failures can be checked.
  const grokFirst = 'Grok Build exited before returning models';
  const grokFailure = [grokFirst, 'Details:', ...frames.map(frame => frame.replace('ZCode.app', 'Grok.app')), 'GROK-TAIL-MARKER'].join('\n');
  await page.addInitScript(([text, grok]) => { (window as any).__zcodeFailure = text; (window as any).__grokFailure = grok; }, [failure, grokFailure]);
  await page.route('**/src/preview.ts*', async route => {
    const response = await route.fetch();
    const source = (await response.text()).replace(/switch\s*\(command\)\s*\{/, `if (command === 'list_provider_models' && args.provider === 'zcode') throw new Error(window.__zcodeFailure);
      if (command === 'list_provider_models' && args.provider === 'grok') throw new Error(window.__grokFailure);
      switch (command) {`);
    await route.fulfill({ response, body: `${source}\nwindow.__pandacodePreviewUrl = import.meta.url;\n` });
  });
  await page.goto('/?teams');
  await expect(page.locator('.task-item.selected')).toHaveAttribute('data-id', 'session-1');
  await openOn(page, 'ZCode');
  const tab = picker(page).getByRole('tab', { name: 'ZCode', exact: true });
  await tab.click();
  await expect(tab).toHaveAttribute('aria-selected', 'true');
  // The whole message, from its summary to the very end of the Details tail, sits in the list card.
  const alert = picker(page).locator('.model-menu-list p.model-menu-failure[role="alert"]');
  await expect(alert).toBeVisible();
  await expect(alert).toHaveAttribute('aria-live', 'polite');
  await expect(tab).toHaveAttribute('aria-description', await tab.getAttribute('data-tip') ?? '');
  await expect(tab).toHaveAttribute('aria-description', /ZCode exited before returning models/);
  await expect(alert).toContainText('ZCode exited before returning models');
  await expect(alert).toContainText('Details:');
  await expect(alert).toContainText('loadProviderConfig39');
  await expect(alert).toContainText('ZCODE-TAIL-MARKER: provider_config.json is missing');
  expect(await alert.evaluate(node => node.textContent)).toBe(failure);
  // Valid ARIA: the alert sits beside the listbox, never inside it.
  await expect(picker(page).getByRole('listbox').getByRole('alert')).toHaveCount(0);
  await expect(picker(page).getByRole('listbox').getByRole('option').first()).toBeVisible();
  await expect(picker(page).locator('.model-menu-group-heading')).toContainText('Unavailable');
  await expect(picker(page).locator('.model-menu-group-heading [data-tip]')).toHaveCount(0);
  // The list card scrolls inside the bounded panel; at the bottom the tail is in view.
  const card = picker(page).locator('.model-menu-list');
  const scrollTop = () => card.evaluate(node => node.scrollTop);
  expect(await card.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
  const tailVisible = () => alert.evaluate(node => node.getBoundingClientRect().bottom <= node.closest('.model-menu-list')!.getBoundingClientRect().bottom + 1);
  expect(await tailVisible()).toBe(false);
  // Keyboard-only readers scroll it from the search field too.
  await expect(search(page)).toBeFocused();
  await page.keyboard.press('ArrowDown');
  await expect.poll(scrollTop).toBeGreaterThan(0);
  const afterArrow = await scrollTop();
  await page.keyboard.press('PageDown');
  await expect.poll(scrollTop).toBeGreaterThan(afterArrow);
  await page.keyboard.press('End');
  await expect.poll(tailVisible).toBe(true);
  await page.keyboard.press('Home');
  await expect.poll(scrollTop).toBe(0);
  expect((await picker(page).boundingBox())!.height).toBeLessThanOrEqual(440);
  // A click on the failure keeps focus in the picker, where keys scroll it and typing returns to search.
  await alert.click({ position: { x: 20, y: 10 } });
  await expect.poll(() => page.evaluate(() => {
    const active = document.activeElement;
    return active !== document.body && Boolean(active?.closest('.model-menu'));
  })).toBe(true);
  await expect(alert).toBeFocused();
  // Select-all on the focused failure selects only the failure, never the whole workspace.
  await page.keyboard.press(selectAllKey);
  expect(await selectionText(page)).toBe(failure);
  expect(await alert.evaluate(node => {
    const selection = window.getSelection()!;
    return selection.rangeCount === 1 && node.contains(selection.getRangeAt(0).commonAncestorContainer);
  })).toBe(true);
  await expect(alert).toBeFocused();
  await page.keyboard.press('End');
  await expect.poll(tailVisible).toBe(true);
  await page.keyboard.press('Home');
  await expect.poll(scrollTop).toBe(0);
  await page.keyboard.press('PageDown');
  await expect.poll(scrollTop).toBeGreaterThan(0);
  await page.keyboard.press('Home');
  await expect.poll(scrollTop).toBe(0);
  await page.keyboard.type('z');
  await expect(search(page)).toBeFocused();
  await expect(search(page)).toHaveValue('z');
  await page.keyboard.press('Escape');
  await expect(search(page)).toHaveValue('');
  await expect(alert).toBeVisible();
  // A horizontal drag along the first line selects its text.
  await expect.poll(scrollTop).toBe(0);
  const line = await alert.evaluate((node, text) => {
    const range = document.createRange();
    range.setStart(node.firstChild!, 0);
    range.setEnd(node.firstChild!, text.length);
    const rect = range.getClientRects()[0];
    return { left: rect.left, right: rect.right, y: rect.top + rect.height / 2 };
  }, first);
  await page.mouse.move(line.left + 4, line.y);
  await page.mouse.down();
  await page.mouse.move(line.left + 60, line.y, { steps: 4 });
  await page.mouse.move(line.right - 4, line.y, { steps: 8 });
  await page.mouse.up();
  const selected = await page.evaluate(() => window.getSelection()?.toString() ?? '');
  expect(selected.length).toBeGreaterThan(10);
  expect(first).toContain(selected);
  await expect.poll(() => page.evaluate(() => document.activeElement !== document.body && Boolean(document.activeElement?.closest('.model-menu')))).toBe(true);
  // The rail tip is a short summary, cut on a word boundary, that fits its bubble whole.
  await page.mouse.move(0, 0);
  await tab.hover();
  const bubble = page.locator('.tip-bubble');
  await expect(bubble).toBeVisible();
  const tip = (await bubble.textContent())!;
  expect(tip).toMatch(/… Select to view details\.$/);
  const cut = tip.slice(0, tip.indexOf('…'));
  expect(cut.length).toBeLessThanOrEqual(180);
  expect(first.startsWith(cut)).toBe(true);
  expect(first[cut.length]).toBe(' ');
  expect(await bubble.evaluate(node => node.scrollHeight <= node.clientHeight)).toBe(true);
  // A disabled row's native title is the summary alone.
  const rowTitle = (await picker(page).locator('.model-menu-option[data-provider="zcode"]').first().getAttribute('title'))!;
  expect(rowTitle).toBe(cut + '…');
  expect(rowTitle).not.toContain('Select to view details.');
  // Another failed harness opens at its own headline, not where ZCode's card was scrolled.
  await card.evaluate(node => { node.scrollTop = node.scrollHeight; });
  await expect.poll(tailVisible).toBe(true);
  expect(await scrollTop()).toBeGreaterThan(0);
  const grokTab = picker(page).getByRole('tab', { name: 'Grok Build', exact: true });
  await grokTab.click();
  await expect(grokTab).toHaveAttribute('aria-selected', 'true');
  await expect(alert).toContainText(grokFirst);
  expect(await alert.evaluate(node => node.textContent)).toBe(grokFailure);
  expect(await card.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
  expect(await scrollTop()).toBe(0);
  expect(await alert.evaluate(node => node.getBoundingClientRect().top < node.closest('.model-menu-list')!.getBoundingClientRect().bottom)).toBe(true);
});

// A long selection error stays bounded, and keyboard users can reach, scroll and read all of it.
test('a long selection error is a bounded, focusable, keyboard-scrollable box', async ({ page }) => {
  const message = `Could not apply the model: ${Array.from({ length: 60 }, (_, i) => `reason ${i} from the harness`).join(', ')}. ERROR-TAIL-MARKER`;
  expect(message.length).toBeGreaterThan(1000);
  await page.addInitScript(text => { (window as any).__selectError = text; }, message);
  await page.route('**/src/preview.ts*', async route => {
    const response = await route.fetch();
    const source = (await response.text()).replace(/switch\s*\(command\)\s*\{/, `if (command === 'configure_session') throw new Error(window.__selectError);
      switch (command) {`);
    await route.fulfill({ response, body: `${source}\nwindow.__pandacodePreviewUrl = import.meta.url;\n` });
  });
  await page.goto('/?teams');
  await expect(page.locator('.task-item.selected')).toHaveAttribute('data-id', 'session-1');
  await openOn(page, 'Codex');
  await picker(page).getByRole('tab', { name: 'Codex', exact: true }).click();
  await picker(page).getByRole('option', { name: 'Codex · GPT-6-Astra', exact: true }).click();
  const error = picker(page).locator('.model-menu-error');
  await expect(error).toBeVisible();
  await expect(error).toHaveText(message);
  const box = await error.evaluate(node => ({ client: node.clientHeight, scroll: node.scrollHeight, height: node.getBoundingClientRect().height }));
  expect(box.height).toBeLessThanOrEqual(120);
  expect(box.scroll).toBeGreaterThan(box.client);
  expect((await picker(page).boundingBox())!.height).toBeLessThanOrEqual(440);
  // Tab: search → rail → the error.
  await expect(search(page)).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(picker(page).getByRole('tab', { name: 'Codex', exact: true })).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(error).toBeFocused();
  const scrollTop = () => error.evaluate(node => node.scrollTop);
  await page.keyboard.press('PageDown');
  await expect.poll(scrollTop).toBeGreaterThan(0);
  await page.keyboard.press('End');
  await expect.poll(() => error.evaluate(node => node.scrollTop + node.clientHeight >= node.scrollHeight - 1)).toBe(true);
  await page.keyboard.press('Home');
  await expect.poll(scrollTop).toBe(0);
  await expect(picker(page)).toBeVisible();
  // A horizontal drag from a fractional point along the first line selects its text.
  const line = await error.evaluate(node => {
    const range = document.createRange();
    range.selectNodeContents(node);
    const rect = range.getClientRects()[0];
    return { left: rect.left, right: rect.right, y: rect.top + rect.height / 2 };
  });
  await page.mouse.move(line.left + 4.3, line.y);
  await page.mouse.down();
  await page.mouse.move(line.left + 60, line.y, { steps: 4 });
  await page.mouse.move(line.right - 4, line.y, { steps: 8 });
  await page.mouse.up();
  const selected = await selectionText(page);
  expect(selected.length).toBeGreaterThan(10);
  expect(message).toContain(selected);
  // Select-all on the focused error selects only the error.
  await error.focus();
  await expect(error).toBeFocused();
  await page.keyboard.press(selectAllKey);
  expect(await selectionText(page)).toBe(message);
  await expect(picker(page)).toBeVisible();
});

// Issue #123: the picker lists only installed harnesses. The preview marks
// Antigravity and Oh My Pi as not installed.
test('the harness picker hides harnesses that are not installed', async ({ page }) => {
  await page.goto('/');
  await page.locator('.new-task-button').click();
  // A composer redraw while the app starts cancels a menu just opened, so try again until one stays.
  await expect(async () => {
    if (!await picker(page).isVisible()) await page.getByRole('button', { name: /^Model: / }).click();
    await expect(picker(page).getByRole('tab', { name: 'Grok Build' })).toBeVisible({ timeout: 1000 });
  }).toPass();
  await expect(picker(page).locator('[data-provider="antigravity"], [data-provider="omp"]')).toHaveCount(0);
  await expect(picker(page)).not.toContainText('Antigravity');
  await expect(picker(page)).not.toContainText('Oh My Pi');
});

test('opens on the current harness with one-line rows, a scrollable rail and a focused search', async ({ page }) => {
  await open(page);
  await expect(search(page)).toBeFocused();
  await expect(search(page)).toHaveAttribute('placeholder', /^Search \d+ models, \d+ harnesses…$/);
  // The popover's entrance spring scales it, so wait for it to settle.
  await expect.poll(async () => (await picker(page).boundingBox())!.width).toBeCloseTo(520, 0);
  expect((await picker(page).boundingBox())!.height).toBeLessThanOrEqual(440);
  const rail = picker(page).getByRole('tablist', { name: 'Harnesses' });
  await expect(rail.getByRole('tab', { name: 'Claude Code', exact: true })).toHaveAttribute('aria-selected', 'true');
  await expect(rail.getByRole('tab', { name: 'Teams, 2' })).toBeVisible();
  // Every harness is reachable: the last one scrolls into view.
  await rail.getByRole('tab').last().scrollIntoViewIfNeeded();
  await expect(rail.getByRole('tab').last()).toBeInViewport();
  const list = picker(page).getByRole('listbox');
  await expect(list.getByRole('option').first()).toHaveAccessibleName('Claude Code · Default');
  await expect(list.locator('[aria-current="true"]')).toHaveCount(1);
  await expect(activeOption(page)).toHaveAttribute('aria-current', 'true');
  await expect(search(page)).toHaveAttribute('aria-activedescendant', (await activeOption(page).getAttribute('id'))!);
  for (const height of await list.getByRole('option').evaluateAll(rows => rows.map(row => row.getBoundingClientRect().height))) expect(height).toBe(28);
  // The harness logo shows once, in the heading.
  await expect(list.locator('.model-menu-option .provider-logo')).toHaveCount(0);
  // Instant: no transitions or running animations in the panel, apart from the effort control's sliding thumb.
  expect(await picker(page).evaluate(panel => [panel, ...panel.querySelectorAll('*:not(.segment-thumb)')].filter(node => getComputedStyle(node).transitionDuration.split(',').some(value => parseFloat(value) > 0)).length)).toBe(0);
});

test('the picker is a small inset shell: a bare rail beside one inset list panel', async ({ page }) => {
  await open(page);
  const look = await picker(page).evaluate(panel => {
    // Resolve a token the way the browser paints it, so the comparison holds in any theme.
    const resolved = (property: 'color' | 'backgroundColor', token: string) => {
      const probe = document.createElement('span');
      probe.style[property] = `var(${token})`;
      panel.append(probe);
      const value = getComputedStyle(probe)[property];
      probe.remove();
      return value;
    };
    const list = getComputedStyle(panel.querySelector('.model-menu-list')!);
    const thumb = getComputedStyle(panel.querySelector('.model-menu-effort>.segment-thumb')!);
    const box = (selector: string) => panel.querySelector(selector)!.getBoundingClientRect();
    return {
      rail: getComputedStyle(panel.querySelector('.model-menu-rail')!).backgroundColor,
      listBorder: [list.borderTopWidth, list.borderTopColor], border: resolved('color', '--ds-border'),
      listFill: list.backgroundColor, inner: resolved('backgroundColor', '--ds-card-inner'),
      listRadius: list.borderTopLeftRadius, radius: getComputedStyle(document.documentElement).getPropertyValue('--ds-radius-inner').trim(),
      thumb: thumb.backgroundColor, thumbToken: resolved('backgroundColor', '--ds-thumb'),
      listEdges: [box('.model-menu-list').left, box('.model-menu-list').right], trackEdges: [box('.model-menu-effort').left, box('.model-menu-effort').right],
    };
  });
  expect(look.rail).toBe('rgba(0, 0, 0, 0)');
  expect(look.listBorder).toEqual(['1px', look.border]);
  expect(look.listFill).toBe(look.inner);
  expect(look.listRadius).toBe(look.radius);
  expect(look.thumb).toBe(look.thumbToken);
  // The effort track lines up under the panel.
  expect(look.trackEdges).toEqual(look.listEdges);
});

test('a team row keeps its name readable; the detail gives way first', async ({ page }) => {
  await open(page);
  await picker(page).getByRole('tab', { name: 'Teams, 2' }).click();
  const names = picker(page).locator('.model-menu-team .model-menu-name');
  await expect(names).toHaveCount(2);
  expect(await names.evaluateAll(nodes => nodes.every(node => node.scrollWidth <= Math.ceil(node.getBoundingClientRect().width)))).toBe(true);
});

// True when the element's own text fits, and nothing of it is cut by its row.
const notClipped = (node: Element) => {
  const row = node.closest('.model-menu-option')!.getBoundingClientRect(), box = node.getBoundingClientRect();
  return node.scrollWidth <= Math.ceil(box.width) && box.width > 0 && box.right <= row.right;
};

test('a long custom ID truncates its quoted text and keeps the harness name whole', async ({ page }) => {
  await open(page);
  await page.keyboard.type('no-such-thing-at-all-and-then-a-great-deal-more-text-than-any-row-can-hold');
  const row = picker(page).getByRole('option', { name: /^Use "/ });
  await expect(row.locator('.model-menu-meta')).toHaveText('Claude Code');
  expect(await row.locator('.model-menu-meta').evaluate(notClipped)).toBe(true);
  expect(await row.locator('.model-menu-name').evaluate(node => node.scrollWidth > node.clientWidth)).toBe(true);
  await expect(row).toHaveAccessibleName('Use "no-such-thing-at-all-and-then-a-great-deal-more-text-than-any-row-can-hold" with Claude Code');
});

test('a team row keeps the worker count when its lead cannot fit', async ({ page }) => {
  await open(page);
  await picker(page).getByRole('tab', { name: 'Teams, 2' }).click();
  const rows = picker(page).locator('.model-menu-team');
  await expect(rows).toHaveCount(2);
  for (const count of await rows.locator('.model-menu-meta-count').all()) {
    await expect(count).toContainText(/\d+ workers?$/);
    expect(await count.evaluate(notClipped)).toBe(true);
  }
  await expect(rows.first().locator('.model-menu-meta')).toHaveText('Claude Opus 5 · 3 workers');
  // In a narrow window the lead gives way and the count still shows whole.
  await page.setViewportSize({ width: 480, height: 800 });
  await expect.poll(() => rows.first().locator('.model-menu-meta-count').evaluate(notClipped)).toBe(true);
});

test('search flattens matches across harnesses and the rail becomes a hit map', async ({ page }) => {
  await open(page);
  await page.keyboard.type('sonne');
  await expect(search(page)).toHaveValue('sonne');
  const rail = picker(page).getByRole('tablist');
  await expect(rail.getByRole('tab', { name: 'Codex', exact: true })).toHaveClass(/is-dim/);
  await expect(rail.getByRole('tab', { name: 'Claude Code', exact: true }).locator('.model-menu-count')).toHaveText('1');
  await expect(activeOption(page)).toHaveAccessibleName('Claude Code · Claude Sonnet 5');
  // One custom row, for the viewed harness, after the real hits.
  await expect(picker(page).getByRole('option', { name: /^Use "/ })).toHaveCount(1);
  await expect(picker(page).getByRole('option').last()).toHaveAccessibleName('Use "sonne" with Claude Code');
  await expect(picker(page).locator('.model-menu-empty')).toHaveCount(0);
  // A query that names a harness offers no custom row.
  await search(page).fill('codex');
  await expect(picker(page).getByRole('option', { name: /^Use "/ })).toHaveCount(0);
  await search(page).fill('no-such-thing-at-all');
  await expect(picker(page).locator('.model-menu-empty')).toHaveText('No matching models.');
  await expect(picker(page).getByRole('option')).toHaveCount(1);
  await expect(picker(page).getByRole('option').first()).toHaveAccessibleName('Use "no-such-thing-at-all" with Claude Code');
  await search(page).fill('Ship');
  await expect(picker(page).getByRole('option').first()).toHaveAccessibleName('Agent team · Ship crew');
});

test('keyboard: arrows move rows, left/right change harness, Enter picks, Tab cycles without closing', async ({ page }) => {
  await open(page);
  await page.keyboard.press('ArrowRight');
  await expect(picker(page).getByRole('tab', { name: 'Codex', exact: true })).toHaveAttribute('aria-selected', 'true');
  await expect(activeOption(page)).toHaveAccessibleName('Codex · Default');
  await page.keyboard.press('ArrowUp');
  const last = await activeOption(page).getAttribute('aria-label');
  await page.keyboard.press('ArrowDown');
  await expect(activeOption(page)).toHaveAccessibleName('Codex · Default');
  expect(last).not.toBe('Codex · Default');
  await page.keyboard.press('End');
  await expect(activeOption(page)).toHaveAccessibleName(last!);
  // Tab: search → rail → effort → search, never closing.
  await page.keyboard.press('Tab');
  await expect(picker(page).getByRole('tab', { name: 'Codex', exact: true })).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(picker(page).getByRole('radio', { name: 'Default', exact: true })).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(search(page)).toBeFocused();
  await page.keyboard.press('Shift+Tab');
  await expect(picker(page).getByRole('radio', { name: 'Default', exact: true })).toBeFocused();
  await expect(picker(page)).toBeVisible();
  // Typing anywhere goes to search.
  await page.keyboard.type('astra');
  await expect(search(page)).toHaveValue('astra');
  await expect(activeOption(page)).toHaveAccessibleName('Codex · GPT-6-Astra');
  await page.keyboard.press('Enter');
  await expect(picker(page)).toHaveCount(0);
  await expect(trigger(page)).toContainText('GPT-6-Astra');
  expect(await task(page)).toMatchObject({ provider: 'codex', model: 'gpt-6-astra' });
});

test('effort is a segmented radiogroup that saves on choice', async ({ page }) => {
  await open(page);
  const group = picker(page).getByRole('radiogroup', { name: 'Effort' });
  await expect(group.getByRole('radio', { name: 'Default', exact: true })).toHaveAttribute('aria-checked', 'true');
  await expect(group.locator('[data-model-default]')).toHaveText('Medium');
  await expect(group.locator('.segment-thumb')).toHaveCount(1);
  await group.getByRole('radio', { name: 'High', exact: true }).click();
  await expect(group.getByRole('radio', { name: 'High', exact: true })).toHaveAttribute('aria-checked', 'true');
  await expect.poll(async () => (await task(page)).reasoningEffort).toBe('high');
  await expect(picker(page).locator('.model-menu-effort-hint')).toHaveText('Sample high effort.');
  await expect(trigger(page).locator('.model-effort')).toHaveText('High');
  // Arrow keys step and save.
  await group.getByRole('radio', { name: 'High', exact: true }).focus();
  await page.keyboard.press('ArrowLeft');
  await expect.poll(async () => (await task(page)).reasoningEffort).toBe('medium');
  await page.keyboard.press('Home');
  await expect.poll(async () => (await task(page)).reasoningEffort).toBeNull();
  await expect(trigger(page).locator('.model-effort')).toBeHidden();
  await expect(picker(page)).toBeVisible();
});

test('teams: picking one sets the team, a plain model clears it', async ({ page }) => {
  await open(page);
  await picker(page).getByRole('tab', { name: 'Teams, 2' }).click();
  const ship = picker(page).getByRole('option', { name: 'Agent team · Ship crew', exact: true });
  await expect(ship).toContainText('3 workers');
  await expect(ship.locator('.provider-logo')).toHaveCount(3);
  await ship.click();
  await expect(picker(page)).toHaveCount(0);
  await expect(trigger(page)).toContainText('Ship crew');
  await expect(trigger(page).locator('.model-menu-stack .provider-logo')).toHaveCount(3);
  await trigger(page).click();
  await expect(picker(page).getByRole('tab', { name: 'Teams, 2' })).toHaveAttribute('aria-selected', 'true');
  await expect(picker(page).getByRole('option', { name: 'Agent team · Ship crew', exact: true })).toHaveAttribute('aria-current', 'true');
  await expect(picker(page).locator('.model-menu-settings')).toContainText('Set per worker');
  await expect(picker(page).getByRole('radiogroup')).toHaveCount(0);
  await picker(page).getByRole('tab', { name: 'Claude Code', exact: true }).click();
  await picker(page).getByRole('option', { name: 'Claude Code · Claude Opus 5', exact: true }).click();
  await expect(picker(page)).toHaveCount(0);
  await expect(trigger(page)).not.toContainText('Ship crew');
  await expect(trigger(page)).toContainText('Claude Opus 5');
  await expect(trigger(page).locator('.model-menu-stack')).toHaveCount(0);
});

test('an installed ZCode harness does not block model changes in an automatic team', async ({ page }) => {
  await page.addInitScript(() => {
    const worker = { id: 'codex-default', name: 'Codex', provider: 'codex', model: 'default', reasoningEffort: null };
    localStorage.setItem('pandacode.preview.architect-configs', JSON.stringify({ 'session-1': {
      auto: true, workers: [worker], catalog: [worker], maxParallel: 0, maxRounds: 8, maxAssignments: 24, workspace: 'shared', summaryLimit: 3072,
    } }));
  });
  await page.route('**/src/preview.ts*', async route => {
    const response = await route.fetch(), source = await response.text();
    const marker = /switch\s*\(command\)\s*\{/;
    expect(source).toMatch(marker);
    // Native rejects ZCode team profiles until its host-tools bridge is supported.
    await route.fulfill({ response, body: `${source.replace(marker, `
      if (command === 'architect_configure' && [...(args.config?.workers ?? []), ...(args.config?.catalog ?? [])].some(profile => profile.provider === 'zcode')) {
        throw new Error('Worker profiles need unique IDs and an installed harness type.');
      }
      switch (command) {`)}\nwindow.__pandacodePreviewUrl = import.meta.url;\n` });
  });
  await page.goto('/');
  await expect(page.locator('#team-trigger')).toHaveAttribute('data-on', '');
  for (const [harness, label, provider, model] of [
    ['Codex', 'GPT-6-Astra', 'codex', 'gpt-6-astra'], ['Claude Code', 'Claude Opus 5', 'claude', 'opus'],
  ]) {
    await openOn(page, 'ZCode');
    await picker(page).getByRole('tab', { name: 'ZCode', exact: true }).click();
    await expect(picker(page).getByRole('option', { name: 'ZCode · zcproxy/GLM-5.3', exact: true })).toBeVisible();
    await picker(page).getByRole('tab', { name: harness, exact: true }).click();
    await picker(page).getByRole('option', { name: `${harness} · ${label}`, exact: true }).click();
    await expect(picker(page)).toHaveCount(0);
    expect(await task(page)).toMatchObject({ provider, model });
    const team = await page.evaluate(async () => {
      const { invoke } = await import((window as any).__pandacodePreviewUrl);
      return invoke('architect_get', { sessionId: 'session-1' });
    });
    expect(team.config.auto).toBe(true);
    expect([...team.config.workers, ...team.config.catalog].every(profile => profile.provider !== 'zcode')).toBe(true);
  }
  await trigger(page).click();
  await picker(page).getByRole('tab', { name: 'ZCode', exact: true }).click();
  await picker(page).getByRole('option', { name: 'ZCode · zcproxy/GLM-5.3', exact: true }).click();
  await expect(picker(page)).toHaveCount(0);
  expect(await task(page)).toMatchObject({ provider: 'zcode', model: 'zcproxy/GLM-5.3' });
  await expect(page.locator('#team-trigger')).not.toHaveAttribute('data-on');
  expect(await page.evaluate(async () => {
    const { invoke } = await import((window as any).__pandacodePreviewUrl);
    return invoke('architect_get', { sessionId: 'session-1' });
  })).toBeNull();
  await trigger(page).click();
  await picker(page).getByRole('tab', { name: 'Codex', exact: true }).click();
  await picker(page).getByRole('option', { name: 'Codex · GPT-6-Astra', exact: true }).click();
  await expect(picker(page)).toHaveCount(0);
  expect(await task(page)).toMatchObject({ provider: 'codex', model: 'gpt-6-astra' });
});

test('Esc clears the query first, then closes and returns focus to the trigger', async ({ page }) => {
  await open(page);
  await page.keyboard.type('opus');
  await page.keyboard.press('Escape');
  await expect(search(page)).toHaveValue('');
  await expect(picker(page)).toBeVisible();
  await expect(picker(page).getByRole('tab', { name: 'Claude Code', exact: true })).toHaveAttribute('aria-selected', 'true');
  await page.keyboard.press('Escape');
  await expect(picker(page)).toHaveCount(0);
  await expect(trigger(page)).toBeFocused();
});

test('narrow windows collapse the rail to logos', async ({ page }) => {
  await page.setViewportSize({ width: 480, height: 800 });
  await open(page);
  const tab = picker(page).getByRole('tab', { name: 'Claude Code', exact: true });
  expect((await tab.boundingBox())!.width).toBeLessThan(50);
  await expect(tab.locator('.model-menu-tab-label')).toBeHidden();
});

/** Holds these preview commands back, so the app reaches the given moment with them still unanswered. */
async function delayCommands(page: Page, commands: string[], ms = 500): Promise<void> {
  await page.route('**/src/preview.ts*', async route => {
    const response = await route.fetch();
    const marker = /switch\s*\(command\)\s*\{/;
    await route.fulfill({ response, body: `${(await response.text()).replace(marker, `if (${JSON.stringify(commands)}.includes(command)) await new Promise(done => setTimeout(done, ${ms}));\nswitch (command) {`)}\nwindow.__pandacodePreviewUrl = import.meta.url;\n` });
  });
}

test('a harness list that answers late still fills the picker', async ({ page }) => {
  await delayCommands(page, ['list_providers']);
  await page.goto('/');
  await page.locator('.new-task-button').click();
  await trigger(page).click();
  await expect(picker(page).locator('[role="tab"][data-view="h:grok"]')).toBeVisible();
  // Typing keeps its place in the same picker.
  await page.keyboard.type('sonne');
  await expect(search(page)).toHaveValue('sonne');
  await expect(picker(page).getByRole('tab', { name: 'Grok Build', exact: true })).toBeVisible();
});

test('the Model button pressed while New task is on its way opens on the new task and stays open', async ({ page }) => {
  await delayCommands(page, ['create_session']);
  await page.goto('/');
  await expect(page.locator('.task-item.selected')).toHaveAttribute('data-id', 'session-1');
  const before = (await page.evaluate(async () => { const { invoke } = await import((window as any).__pandacodePreviewUrl); return invoke('get_task', { sessionId: 'session-1' }); }) as any);
  await page.locator('.new-task-button').click();
  await trigger(page).click();
  await expect(picker(page)).toBeVisible();
  await expect(page.locator('#prompt')).not.toHaveAttribute('data-session-id', 'session-1');
  await picker(page).getByRole('tab', { name: 'Codex', exact: true }).click();
  await picker(page).getByRole('option', { name: 'Codex · GPT-6-Astra', exact: true }).click();
  await expect(picker(page)).toHaveCount(0);
  // The pick landed on the new task, not on the one the button belonged to when it was pressed.
  expect(await task(page)).toMatchObject({ provider: 'codex', model: 'gpt-6-astra' });
  const after = await page.evaluate(async () => { const { invoke } = await import((window as any).__pandacodePreviewUrl); return invoke('get_task', { sessionId: 'session-1' }); }) as any;
  expect([after.provider, after.model]).toEqual([before.provider, before.model]);
});

test('the picker shows provider logos for Cline, Kilo Code and Oh My Pi', async ({ page }) => {
  await page.route('**/src/preview.ts*', async route => {
    const response = await route.fetch(); const source = await response.text();
    const marker = /switch\s*\(command\)\s*\{/;
    expect(source).toMatch(marker);
    await route.fulfill({ response, body: source.replace(marker, `if (command === 'list_providers') return structuredClone(providers.map(p => ({ ...p, installed: true })));\nswitch (command) {`) });
  });
  await page.goto('/');
  await page.locator('.new-task-button').click();
  await trigger(page).click();
  const rail = picker(page).getByRole('tablist', { name: 'Harnesses' });
  for (const [name, id] of [['Cline', 'cline'], ['Kilo Code', 'kilo'], ['Oh My Pi', 'omp']]) {
    const tab = rail.getByRole('tab', { name, exact: true });
    await expect(tab.locator(`.provider-logo[data-provider="${id}"]:not(.provider-logo-tile)`)).toHaveCount(1);
    await tab.click();
    await expect(picker(page).locator(`.provider-logo[data-provider="${id}"]:not(.provider-logo-tile)`).first()).toBeVisible();
  }
});

/** Saved/native account assignments are metadata, never extra picker choices. */
async function accountFixture(page: Page, pooled: boolean) {
  const connections = ['claude', 'codex', 'kimi'].flatMap(provider => Array.from({ length: 6 }, (_, i) => ({
    id: `${provider}-${i}`, provider, name: `${provider} account ${i}`, args: [], env: {}, secretEnv: [], configDir: `/tmp/pandacode-fixture/${provider}-${i}`, revision: 1,
  })));
  await page.route('**/src/preview.ts*', async route => {
    const response = await route.fetch(), source = await response.text();
    const body = source.replace(/switch\s*\(command\)\s*\{/, `(window.__accountCalls ??= []).push({ command, args: structuredClone(args) }); switch (command) {`);
    await route.fulfill({ response, body: `${body}\npreviewConnections = ${JSON.stringify({ connections, tasks: { 'session-1': 'claude-0' }, pools: pooled ? ['claude', 'codex'] : [], poolExcluded: [] })};\nwindow.__pandacodePreviewUrl = import.meta.url;\nwindow.__accountSnapshot = () => structuredClone(previewConnections);\n` });
  });
  await page.goto('/');
  await expect(page.locator('.task-item.selected')).toHaveAttribute('data-id', 'session-1');
}
const accountCalls = (page: Page, command: string) => page.evaluate(name => (window as any).__accountCalls.filter((c: any) => c.command === name), command);

for (const pooled of [false, true]) test(`accounts never duplicate harness tabs, models or search hits with pooling ${pooled ? 'on' : 'off'}`, async ({ page }) => {
  await accountFixture(page, pooled);
  await trigger(page).click();
  const tabs = picker(page).getByRole('tablist', { name: 'Harnesses' }).getByRole('tab');
  const labels = await tabs.evaluateAll(nodes => nodes.map(node => node.textContent));
  expect(labels.filter(label => label?.includes('account'))).toEqual([]);
  expect(new Set(labels).size).toBe(labels.length);
  for (const name of ['Claude Code', 'Codex', 'Kimi Code']) await expect(picker(page).getByRole('tab', { name, exact: true })).toHaveCount(1);
  await expect(picker(page).getByRole('tab', { name: 'Claude Code', exact: true })).toHaveAttribute('aria-selected', 'true');
  await expect(picker(page).locator('[aria-current="true"]')).toHaveAccessibleName('Claude Code · Claude Sonnet 5');
  const options = await picker(page).getByRole('option').evaluateAll(nodes => nodes.map(node => node.getAttribute('aria-label')));
  expect(new Set(options).size).toBe(options.length);
  await search(page).fill('sonne');
  await expect(picker(page).getByRole('option', { name: 'Claude Code · Claude Sonnet 5', exact: true })).toHaveCount(1);
  const hits = await picker(page).getByRole('option').evaluateAll(nodes => nodes.map(node => node.getAttribute('aria-label')));
  expect(new Set(hits).size).toBe(hits.length);
  expect(hits.some(label => label?.includes('account'))).toBe(false);
  await expect(picker(page).getByRole('tab', { name: 'Claude Code', exact: true }).locator('.model-menu-count')).toHaveText('1');
  expect(await accountCalls(page, 'connection_pool_set')).toEqual([]);
});

test('changing model within a harness keeps its native account binding and resumable conversation', async ({ page }) => {
  await accountFixture(page, true);
  const before = await task(page);
  await trigger(page).click();
  await picker(page).getByRole('tab', { name: 'Claude Code', exact: true }).click();
  await picker(page).getByRole('option', { name: 'Claude Code · Claude Opus 5', exact: true }).click();
  await expect.poll(async () => (await task(page)).model).toBe('opus');
  const after = await task(page);
  expect(after.resumeId).toBe(before.resumeId);
  expect(await accountCalls(page, 'connection_assign')).toEqual([]);
  expect(await page.evaluate(() => (window as any).__accountSnapshot().tasks['session-1'])).toBe('claude-0');
  await trigger(page).click();
  await expect(picker(page).getByRole('tab', { name: 'Claude Code', exact: true })).toHaveAttribute('aria-selected', 'true');
  await expect(picker(page).locator('[aria-current="true"]')).toHaveAccessibleName('Claude Code · Claude Opus 5');
});

test('a true harness switch clears a stale account binding after configuring the new harness', async ({ page }) => {
  await accountFixture(page, true);
  await trigger(page).click();
  await picker(page).getByRole('tab', { name: 'Codex', exact: true }).click();
  await picker(page).getByRole('option', { name: 'Codex · GPT-6-Astra', exact: true }).click();
  await expect.poll(async () => (await task(page)).provider).toBe('codex');
  await expect.poll(() => accountCalls(page, 'connection_assign')).toEqual([{ command: 'connection_assign', args: { sessionId: 'session-1', connectionId: null } }]);
  const calls = await page.evaluate(() => (window as any).__accountCalls.filter((c: any) => ['configure_session', 'connection_assign'].includes(c.command)).map((c: any) => c.command));
  expect(calls).toEqual(['configure_session', 'connection_assign']);
  expect(await page.evaluate(() => (window as any).__accountSnapshot().tasks['session-1'])).toBeUndefined();
  expect(await accountCalls(page, 'connection_pool_set')).toEqual([]);
});

const speed = (page: Page) => picker(page).getByRole('radiogroup', { name: 'Speed' });

async function pick(page: Page, query: string, name: string): Promise<void> {
  await trigger(page).click();
  await picker(page).getByRole('combobox', { name: 'Search harnesses and models', exact: true }).fill(query);
  await picker(page).getByRole('option', { name, exact: true }).click();
  await expect(picker(page)).toHaveCount(0);
}

test('the Speed row lists a model\'s tiers and saves the choice', async ({ page }) => {
  // Claude Sonnet reports no fast mode.
  await open(page, '/');
  await expect(picker(page).getByRole('radiogroup', { name: 'Effort' })).toBeVisible();
  await expect(speed(page)).toHaveCount(0);
  await page.keyboard.press('Escape');
  await expect(picker(page)).toHaveCount(0);

  await pick(page, 'astra', 'Codex · GPT-6-Astra');
  await trigger(page).click();
  await expect(speed(page).getByRole('radio')).toHaveText(['Standard', 'Fast', 'Ultrafast']);
  await expect(speed(page).getByRole('radio', { name: 'Standard', exact: true })).toHaveAttribute('aria-checked', 'true');
  await speed(page).getByRole('radio', { name: 'Ultrafast', exact: true }).click();
  await expect(speed(page).getByRole('radio', { name: 'Ultrafast', exact: true })).toHaveAttribute('aria-checked', 'true');
  await expect.poll(async () => (await task(page)).codexSettings?.serviceTier).toBe('ultrafast');
  await expect(trigger(page).locator('.model-effort')).toHaveText('Ultrafast');
  // Arrow keys stay inside the Speed group and save.
  await page.keyboard.press('ArrowLeft');
  await expect.poll(async () => (await task(page)).codexSettings?.serviceTier).toBe('priority');
  await page.keyboard.press('Escape');
  await expect(picker(page)).toHaveCount(0);

  // A Codex model without tiers has no Speed row.
  await pick(page, 'sol', 'Codex · GPT-5.6-Sol');
  await trigger(page).click();
  await expect(picker(page).getByRole('radiogroup', { name: 'Effort' })).toBeVisible();
  await expect(speed(page)).toHaveCount(0);
});

test('non-focusable picker chrome keeps focus and keyboard handling inside the menu', async ({ page }) => {
  await open(page);
  await expect(search(page)).toBeFocused();
  await picker(page).locator('.model-menu-group-heading').first().click();
  await expect.poll(() => page.evaluate(() => document.activeElement !== document.body && Boolean(document.activeElement?.closest('.model-menu')))).toBe(true);
  await expect(search(page)).toBeFocused();
  await page.keyboard.type('needle');
  await expect(search(page)).toHaveValue('needle');
  await page.keyboard.press('Escape');
  await expect(search(page)).toHaveValue('');
  await expect(picker(page)).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(picker(page)).toBeHidden();
  await expect(trigger(page)).toBeFocused();
});

test('clicking a disabled failed-catalog row keeps focus and typing in search', async ({ page }) => {
  await page.route('**/src/preview.ts*', async route => {
    const response = await route.fetch();
    const source = (await response.text()).replace(/switch\s*\(command\)\s*\{/, `if (command === 'list_provider_models' && args.provider === 'zcode') throw new Error('Catalog unavailable'); switch (command) {`);
    await route.fulfill({ response, body: source });
  });
  await page.goto('/?teams');
  await expect(page.locator('.task-item.selected')).toHaveAttribute('data-id', 'session-1');
  await openOn(page, 'ZCode');
  await picker(page).getByRole('tab', { name: 'ZCode', exact: true }).click();
  await expect(picker(page).locator('.model-menu-failure')).toBeVisible();
  const row = picker(page).getByRole('option').first();
  await expect(row).toBeDisabled();
  await row.scrollIntoViewIfNeeded();
  await expect(search(page)).toBeFocused();
  const box = (await row.boundingBox())!;
  await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
  await expect.poll(() => page.evaluate(() => document.activeElement !== document.body && Boolean(document.activeElement?.closest('.model-menu')))).toBe(true);
  await page.keyboard.type('needle');
  await expect(search(page)).toHaveValue('needle');
});

async function openScrollableFailure(page: Page): Promise<void> {
  await page.route('**/src/preview.ts*', async route => {
    const response = await route.fetch();
    const source = (await response.text()).replace(/switch\s*\(command\)\s*\{/, `if (command === 'list_provider_models' && args.provider === 'zcode') throw new Error('Catalog failed\\n' + '    at loadProviderConfig (provider_config.json:100)\\n'.repeat(90)); switch (command) {`);
    await route.fulfill({ response, body: source });
  });
  await page.goto('/?teams');
  await expect(page.locator('.task-item.selected')).toHaveAttribute('data-id', 'session-1');
  await openOn(page, 'ZCode');
  await picker(page).getByRole('tab', { name: 'ZCode', exact: true }).click();
  await expect(picker(page).locator('.model-menu-failure')).toBeVisible();
  await expect.poll(async () => (await picker(page).boundingBox())!.width).toBeCloseTo(520, 0);
}

test('scrollable picker surfaces leave pointer defaults intact and restore focus without scrolling', async ({ page }) => {
  await openScrollableFailure(page);
  for (const selector of ['.model-menu-list', '.model-menu-rail']) {
    const surface = picker(page).locator(selector);
    const prevented = await surface.evaluate(node => ['pointerdown', 'mousedown'].map(type => {
      const event = type === 'pointerdown' ? new PointerEvent(type, { bubbles: true, cancelable: true }) : new MouseEvent(type, { bubbles: true, cancelable: true });
      node.dispatchEvent(event);
      return event.defaultPrevented;
    }));
    expect(prevented).toEqual([false, false]);
    const before = await surface.evaluate(node => {
      window.getSelection()?.removeAllRanges();
      (document.activeElement as HTMLElement)?.blur();
      node.scrollTop = 40;
      const before = node.scrollTop;
      node.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      return before;
    });
    await expect(search(page)).toBeFocused();
    expect(await surface.evaluate(node => node.scrollTop)).toBe(before);
  }
});

test('classic scrollbar thumbs drag the overflowing failure card and harness rail', async ({ page }, testInfo) => {
  test.skip(testInfo.project.use.headless !== false, 'Native scrollbar thumb dragging is checked in headed Chrome');
  await openScrollableFailure(page);
  // Force a classic gutter; real mouse input must drag each native thumb in headed Windows Chrome.
  await page.addStyleTag({ content: `.model-menu-list,.model-menu-rail{scrollbar-width:auto!important;scrollbar-gutter:stable!important}
    .model-menu-list::-webkit-scrollbar,.model-menu-rail::-webkit-scrollbar{width:16px!important}
    .model-menu-list::-webkit-scrollbar-button,.model-menu-rail::-webkit-scrollbar-button{display:none!important}
    .model-menu-list::-webkit-scrollbar-thumb,.model-menu-rail::-webkit-scrollbar-thumb{min-height:24px}` });
  for (const selector of ['.model-menu-list', '.model-menu-rail']) {
    const surface = picker(page).locator(selector);
    await expect.poll(() => surface.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
    await surface.evaluate(node => { node.scrollTop = 0; });
    expect(await surface.evaluate(node => node.scrollTop)).toBe(0);
    const thumb = await surface.evaluate(node => {
      const box = node.getBoundingClientRect();
      const style = getComputedStyle(node);
      const right = parseFloat(style.borderRightWidth);
      const gutter = (node as HTMLElement).offsetWidth - node.clientWidth - parseFloat(style.borderLeftWidth) - right;
      const height = Math.max(24, node.clientHeight * node.clientHeight / node.scrollHeight);
      return { gutter, x: box.right - right - gutter / 2, y: box.top + parseFloat(style.borderTopWidth) + height / 2, delta: Math.min(100, node.clientHeight / 3) };
    });
    expect(thumb.gutter).toBeGreaterThan(0);
    await page.mouse.move(thumb.x, thumb.y);
    await page.mouse.down();
    await page.mouse.move(thumb.x, thumb.y + thumb.delta, { steps: 12 });
    await page.mouse.up();
    await expect.poll(() => surface.evaluate(node => node.scrollTop), { message: `${selector} native thumb should scroll` }).toBeGreaterThan(0);
  }
});

for (const card of ['failure', 'error']) test('light and forced-color ' + card + ' cards stay readable', async ({ page }) => {
  if (card === 'failure') await openScrollableFailure(page);
  else {
    await page.route('**/src/preview.ts*', async route => {
      const response = await route.fetch();
      const source = (await response.text()).replace(/switch\s*\(command\)\s*\{/, "if (command === 'configure_session') throw new Error('Could not save model selection.'); switch (command) {");
      await route.fulfill({ response, body: source });
    });
    await page.goto('/?teams');
    await openOn(page, 'Codex');
    await picker(page).getByRole('tab', { name: 'Codex', exact: true }).click();
    await picker(page).getByRole('option', { name: 'Codex · GPT-6-Astra', exact: true }).click();
  }
  await page.evaluate(() => { document.documentElement.dataset.theme = 'light'; });
  const box = picker(page).locator('.model-menu-' + card);
  await expect(box).toBeVisible();
  expect(await box.evaluate(cardContrast)).toBeGreaterThanOrEqual(4.5);
  await page.emulateMedia({ forcedColors: 'active' });
  const style = await box.evaluate(node => { const s = getComputedStyle(node); return { width: s.borderTopWidth, style: s.borderTopStyle, background: s.backgroundColor }; });
  expect(style.width).toBe('1px');
  expect(style.style).toBe('solid');
  expect(style.background).toMatch(/^rgba\(.*?, 0\)$/);
});

test('failure tooltip stays inside a short viewport', async ({ page }) => {
  await page.setViewportSize({ width: 900, height: 260 });
  await openScrollableFailure(page);
  const tab = picker(page).getByRole('tab', { name: 'ZCode', exact: true });
  await tab.hover();
  const tip = page.getByRole('tooltip');
  await expect(tip).toBeVisible();
  const box = (await tip.boundingBox())!;
  expect(box.x).toBeGreaterThanOrEqual(0);
  expect(box.y).toBeGreaterThanOrEqual(0);
  expect(box.x + box.width).toBeLessThanOrEqual(900);
  expect(box.y + box.height).toBeLessThanOrEqual(260);
});

test('Space pages failure details and Shift+Tab returns to the rail', async ({ page }) => {
  await openScrollableFailure(page);
  const failure = picker(page).locator('.model-menu-failure');
  const list = picker(page).locator('.model-menu-list');
  await failure.focus();
  const initial = await list.evaluate(node => node.scrollTop);
  await page.keyboard.press('Space');
  await expect.poll(() => list.evaluate(node => node.scrollTop)).toBeGreaterThan(initial);
  await expect(failure).toBeFocused();
  await page.keyboard.press('Shift+Space');
  await expect.poll(() => list.evaluate(node => node.scrollTop)).toBe(initial);
  await page.keyboard.press('Shift+Tab');
  await expect(picker(page).getByRole('tab', { name: 'ZCode', exact: true })).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(failure).toBeFocused();
});

for (const kind of ['effort', 'speed']) test(kind + ' saves show a fallback for empty errors', async ({ page }) => {
  await open(page);
  await page.keyboard.press('Escape');
  await page.evaluate(async kind => {
    const { invoke } = await import((window as any).__pandacodePreviewUrl);
    const { openModelPicker } = await import('/src/' + 'model-picker.ts');
    const providers = await invoke('list_providers', {});
    providers.find((provider: any) => provider.id === 'codex').models = await invoke('list_provider_models', { provider: 'codex' });
    openModelPicker({
      anchor: document.querySelector('#model-picker-trigger')!, providers,
      current: { provider: 'codex', model: 'gpt-6-astra' }, canSwitchProvider: true,
      onSelect: async () => {},
      onEffortSelect: async () => { throw new Error(''); },
      onSpeedSelect: async () => { throw new Error('   '); },
    });
  }, kind);
  const group = picker(page).getByRole('radiogroup', { name: kind === 'effort' ? 'Effort' : 'Speed', exact: true });
  await group.getByRole('radio').nth(1).click();
  const error = picker(page).locator('.model-menu-error');
  await expect(error).toHaveText(kind === 'effort' ? 'Could not save reasoning effort.' : 'Could not save speed.');
  await expect(error).toBeVisible();
  expect((await error.boundingBox())!.height).toBeGreaterThan(0);
});
