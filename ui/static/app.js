const state = { catalog: null, policy: null, activeTab: null };

async function loadAll() {
  const [catalogRes, policyRes] = await Promise.all([
    fetch('/api/catalog'),
    fetch('/api/policy')
  ]);
  state.catalog = await catalogRes.json();
  const payload = await policyRes.json();
  state.policy = payload.policy;
  state.activeTab = state.activeTab || state.catalog.tabs[0].id;
  document.getElementById('meta').textContent = `Policy hash: ${payload.hash}`;
  document.getElementById('json').value = JSON.stringify(state.policy, null, 2);
  renderTabs();
  renderCommands();
}

function tierFor(cmd) {
  if ((state.policy.blocked?.commands || []).includes(cmd)) return 'blocked';
  if ((state.policy.requires_confirmation?.commands || []).includes(cmd)) return 'requires_confirmation';
  if ((state.policy.requires_simulation?.commands || []).includes(cmd)) return 'requires_simulation';
  return 'allowed';
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

function renderTabs() {
  const tabs = document.getElementById('tabs');
  tabs.innerHTML = '';
  state.catalog.tabs.forEach((tab) => {
    const btn = document.createElement('button');
    btn.textContent = tab.label;
    btn.style.display = 'block';
    btn.style.marginBottom = '8px';
    btn.onclick = () => { state.activeTab = tab.id; renderCommands(); };
    tabs.appendChild(btn);
  });
}

function renderCommands() {
  const list = document.getElementById('commands');
  list.innerHTML = '';
  const tab = state.catalog.tabs.find((x) => x.id === state.activeTab);
  tab.commands.forEach((cmd) => {
    const row = document.createElement('div');
    row.className = 'command';
    const label = document.createElement('div');
    label.innerHTML = `<strong>${cmd}</strong><br/><small>${tab.label}</small>`;
    row.appendChild(label);
    ['allowed', 'requires_simulation', 'requires_confirmation', 'blocked'].forEach((tier) => {
      const radio = document.createElement('input');
      radio.type = 'radio';
      radio.name = `tier-${cmd}`;
      radio.checked = tierFor(cmd) === tier;
      radio.onchange = () => setTier(cmd, tier);
      row.appendChild(radio);
    });
    list.appendChild(row);
  });
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
loadAll();
