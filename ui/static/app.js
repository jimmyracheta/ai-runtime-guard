const state = {
  catalog: null,
  policy: null,
  appliedPolicy: null,
  activeTab: null,
  allCommands: [],
  descriptions: {},
};

const TIER_ORDER = ['allowed', 'requires_simulation', 'requires_confirmation', 'blocked'];

function deepClone(v) {
  return JSON.parse(JSON.stringify(v));
}

async function loadAll() {
  const [catalogRes, policyRes] = await Promise.all([
    fetch('/api/catalog'),
    fetch('/api/policy')
  ]);
  state.catalog = await catalogRes.json();
  const payload = await policyRes.json();
  state.policy = deepClone(payload.policy);
  state.appliedPolicy = deepClone(payload.policy);
  state.activeTab = state.activeTab || state.catalog.tabs[0].id;
  state.allCommands = payload.all_commands || [];
  state.descriptions = payload.descriptions || {};
  document.getElementById('meta').textContent = `Policy hash: ${payload.hash}`;
  document.getElementById('json').value = JSON.stringify(state.policy, null, 2);
  renderLegend();
  renderTabs();
  renderCommands();
}

function tierFor(policy, cmd) {
  if ((policy.blocked?.commands || []).includes(cmd)) return 'blocked';
  if ((policy.requires_confirmation?.commands || []).includes(cmd)) return 'requires_confirmation';
  if ((policy.requires_simulation?.commands || []).includes(cmd)) return 'requires_simulation';
  return 'allowed';
}

function appliedOverrideFor(cmd) {
  return state.appliedPolicy?.ui_overrides?.commands?.[cmd] || {};
}

function setTier(cmd, tier) {
  const remove = (list) => (list || []).filter((x) => x !== cmd);
  state.policy.blocked.commands = remove(state.policy.blocked.commands);
  state.policy.requires_confirmation.commands = remove(state.policy.requires_confirmation.commands);
  state.policy.requires_simulation.commands = remove(state.policy.requires_simulation.commands);
  if (tier === 'blocked') state.policy.blocked.commands.push(cmd);
  if (tier === 'requires_confirmation') state.policy.requires_confirmation.commands.push(cmd);
  if (tier === 'requires_simulation') state.policy.requires_simulation.commands.push(cmd);
  document.getElementById('json').value = JSON.stringify(state.policy, null, 2);
}

function ensureOverridesRoot() {
  state.policy.ui_overrides = state.policy.ui_overrides || {};
  state.policy.ui_overrides.commands = state.policy.ui_overrides.commands || {};
}

function setOverride(cmd, patch) {
  ensureOverridesRoot();
  const current = state.policy.ui_overrides.commands[cmd] || {};
  const merged = { ...current, ...patch };
  const hasBudget = merged.budget && Object.keys(merged.budget).length > 0;
  const hasRetry = Number.isInteger(merged.retry_override);
  if (!hasBudget && !hasRetry) {
    delete state.policy.ui_overrides.commands[cmd];
  } else {
    state.policy.ui_overrides.commands[cmd] = merged;
  }
  document.getElementById('json').value = JSON.stringify(state.policy, null, 2);
}

function commandsForActiveTab() {
  const tab = state.catalog.tabs.find((x) => x.id === state.activeTab);
  if (!tab) return [];
  const fromTab = tab.id === 'all' ? state.allCommands : tab.commands;
  const filter = document.getElementById('search').value.trim().toLowerCase();
  return fromTab.filter((cmd) => !filter || cmd.toLowerCase().includes(filter));
}

function renderTabs() {
  const tabs = document.getElementById('tabs');
  tabs.innerHTML = '';
  state.catalog.tabs.forEach((tab) => {
    const btn = document.createElement('button');
    btn.textContent = tab.label;
    btn.style.display = 'block';
    btn.style.marginBottom = '8px';
    btn.style.width = '100%';
    if (state.activeTab === tab.id) btn.style.opacity = '1';
    else btn.style.opacity = '0.8';
    btn.onclick = () => { state.activeTab = tab.id; renderCommands(); };
    tabs.appendChild(btn);
  });
}

function statusBadgeFor(tier) {
  const span = document.createElement('span');
  if (tier === 'blocked') { span.className = 'status blocked'; span.textContent = 'Blocked'; }
  else if (tier === 'requires_confirmation') { span.className = 'status confirmation'; span.textContent = 'Requires Approval'; }
  else if (tier === 'requires_simulation') { span.className = 'status simulation'; span.textContent = 'Simulation'; }
  else { span.className = 'status allowed'; span.textContent = 'Allowed'; }
  return span;
}

function renderCommands() {
  const list = document.getElementById('commands');
  list.innerHTML = '';
  const commands = commandsForActiveTab();

  commands.forEach((cmd) => {
    const row = document.createElement('div');
    row.className = 'command';

    const label = document.createElement('div');
    const currentTier = tierFor(state.appliedPolicy, cmd);
    const desc = state.descriptions[cmd] || 'No catalog description yet.';
    const info = `<span class="info" title="${desc.replace(/"/g, '&quot;')}">ⓘ</span>`;
    label.innerHTML = `<strong>${cmd}</strong>${info}`;
    label.appendChild(statusBadgeFor(currentTier));

    const appliedOverride = appliedOverrideFor(cmd);
    if (Number.isInteger(appliedOverride.retry_override)) {
      const t = document.createElement('span');
      t.className = 'tag';
      t.textContent = `Retry: ${appliedOverride.retry_override}`;
      label.appendChild(t);
    }
    if (appliedOverride.budget) {
      const b = document.createElement('span');
      b.className = 'tag';
      const parts = [];
      if (Number.isInteger(appliedOverride.budget.max_ops_per_session)) parts.push(`ops ${appliedOverride.budget.max_ops_per_session}`);
      if (Number.isInteger(appliedOverride.budget.max_unique_paths_per_session)) parts.push(`paths ${appliedOverride.budget.max_unique_paths_per_session}`);
      if (Number.isInteger(appliedOverride.budget.max_bytes_per_session)) parts.push(`bytes ${appliedOverride.budget.max_bytes_per_session}`);
      b.textContent = `Budget: ${parts.join(', ') || 'on'}`;
      label.appendChild(b);
    }

    row.appendChild(label);

    TIER_ORDER.forEach((tier) => {
      const wrap = document.createElement('div');
      const radio = document.createElement('input');
      radio.type = 'radio';
      radio.name = `tier-${cmd}`;
      radio.checked = tierFor(state.policy, cmd) === tier;
      radio.onchange = () => setTier(cmd, tier);
      wrap.appendChild(radio);
      row.appendChild(wrap);
    });

    const currentOverride = state.policy?.ui_overrides?.commands?.[cmd] || {};

    const retry = document.createElement('input');
    retry.type = 'number';
    retry.min = '0';
    retry.placeholder = '-';
    retry.value = Number.isInteger(currentOverride.retry_override) ? String(currentOverride.retry_override) : '';
    retry.onchange = () => {
      const val = retry.value.trim();
      setOverride(cmd, { retry_override: val === '' ? undefined : parseInt(val, 10) });
      if (val === '') {
        const entry = state.policy?.ui_overrides?.commands?.[cmd] || {};
        delete entry.retry_override;
        setOverride(cmd, entry);
      }
    };
    row.appendChild(retry);

    const budgetOps = document.createElement('input');
    budgetOps.type = 'number';
    budgetOps.min = '0';
    budgetOps.placeholder = '-';
    budgetOps.value = currentOverride?.budget?.max_ops_per_session ? String(currentOverride.budget.max_ops_per_session) : '';

    const budgetPaths = document.createElement('input');
    budgetPaths.type = 'number';
    budgetPaths.min = '0';
    budgetPaths.placeholder = '-';
    budgetPaths.value = currentOverride?.budget?.max_unique_paths_per_session ? String(currentOverride.budget.max_unique_paths_per_session) : '';

    const budgetBytes = document.createElement('input');
    budgetBytes.type = 'number';
    budgetBytes.min = '0';
    budgetBytes.placeholder = '-';
    budgetBytes.value = currentOverride?.budget?.max_bytes_per_session ? String(currentOverride.budget.max_bytes_per_session) : '';

    const pushBudget = () => {
      const budget = {};
      if (budgetOps.value.trim() !== '') budget.max_ops_per_session = parseInt(budgetOps.value, 10);
      if (budgetPaths.value.trim() !== '') budget.max_unique_paths_per_session = parseInt(budgetPaths.value, 10);
      if (budgetBytes.value.trim() !== '') budget.max_bytes_per_session = parseInt(budgetBytes.value, 10);
      const patch = {};
      const retryVal = retry.value.trim();
      if (retryVal !== '') patch.retry_override = parseInt(retryVal, 10);
      patch.budget = Object.keys(budget).length ? budget : undefined;
      setOverride(cmd, patch);
      if (!patch.budget) {
        const entry = state.policy?.ui_overrides?.commands?.[cmd] || {};
        delete entry.budget;
        setOverride(cmd, entry);
      }
    };

    budgetOps.onchange = pushBudget;
    budgetPaths.onchange = pushBudget;
    budgetBytes.onchange = pushBudget;

    row.appendChild(budgetOps);
    row.appendChild(budgetPaths);
    row.appendChild(budgetBytes);

    list.appendChild(row);
  });
}

function renderLegend() {
  const legend = document.getElementById('legend');
  legend.innerHTML = '';
  const entries = [
    ['Allowed', 'allowed'],
    ['Simulation', 'simulation'],
    ['Requires Approval', 'confirmation'],
    ['Blocked', 'blocked'],
  ];
  entries.forEach(([label, cls]) => {
    const pill = document.createElement('span');
    pill.className = `status ${cls}`;
    pill.textContent = label;
    legend.appendChild(pill);
  });
  const note = document.createElement('span');
  note.className = 'tag';
  note.textContent = 'Status badges reflect applied policy (after Apply), not unsaved edits';
  legend.appendChild(note);
}

async function validatePolicy() {
  let policy;
  try { policy = JSON.parse(document.getElementById('json').value); }
  catch { document.getElementById('result').textContent = 'Invalid JSON in editor'; return; }
  const res = await fetch('/api/policy/validate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ policy }) });
  const payload = await res.json();
  document.getElementById('result').textContent = JSON.stringify(payload, null, 2);
}

async function applyPolicy() {
  let policy;
  try { policy = JSON.parse(document.getElementById('json').value); }
  catch { document.getElementById('result').textContent = 'Invalid JSON in editor'; return; }
  const res = await fetch('/api/policy/apply', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Actor': 'local-ui' }, body: JSON.stringify({ policy }) });
  const payload = await res.json();
  document.getElementById('result').textContent = JSON.stringify(payload, null, 2);
  if (res.ok) await loadAll();
}

document.getElementById('reload').onclick = loadAll;
document.getElementById('validate').onclick = validatePolicy;
document.getElementById('apply').onclick = applyPolicy;
document.getElementById('search').oninput = renderCommands;
loadAll();
