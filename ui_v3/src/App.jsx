import React, { useEffect, useMemo, useRef, useState } from 'react'

const API_BASE = 'http://127.0.0.1:5001'
const RAIL_ITEMS = [
  { id: 'approvals', label: 'Approvals', icon: '🔔' },
  { id: 'commands', label: 'Commands', icon: '🛡️' },
  { id: 'paths', label: 'Paths', icon: '🗂️' },
  { id: 'reports', label: 'Reports', icon: '📊' },
  { id: 'settings', label: 'Settings', icon: '⚙️' }
]
const DEFAULT_TABS = [{ id: 'all', label: 'All Commands' }]
const COLUMN_DEFS = [
  { key: 'allowed', label: 'Allowed', group: 'basic' },
  { key: 'blocked', label: 'Blocked', group: 'basic' },
  { key: 'requires_simulation', label: 'Simulation', group: 'advanced' },
  { key: 'requires_confirmation', label: 'Requires Approval', group: 'advanced' }
]

const BASIC_TIER_COLUMNS = COLUMN_DEFS.filter((c) => c.group === 'basic')
const ADVANCED_TIER_COLUMNS = COLUMN_DEFS.filter((c) => c.group === 'advanced')
const BASIC_GRID_COLS = 'minmax(320px,1fr)_90px_90px'
const ADVANCED_GRID_TAIL = '_90px_90px_80px_100px_110px_120px'
const ADVANCED_TOGGLE_KEY = 'airg.ui.showAdvancedSettings'

const STATUS_STYLE = {
  allowed: 'bg-green-100 text-green-700 border-green-200',
  requires_simulation: 'bg-blue-100 text-blue-700 border-blue-200',
  requires_confirmation: 'bg-amber-100 text-amber-700 border-amber-200',
  blocked: 'bg-red-100 text-red-700 border-red-200'
}

const STATUS_LABEL = {
  allowed: 'Allowed',
  requires_simulation: 'Simulation',
  requires_confirmation: 'Requires Approval',
  blocked: 'Blocked'
}

function deepClone(v) {
  return JSON.parse(JSON.stringify(v))
}

function slugifyCategoryId(label) {
  const slug = String(label || '').toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '')
  return slug || 'custom'
}

function normalizeCommandName(cmd) {
  return String(cmd || '').trim().replace(/\s+/g, ' ')
}

function tierFor(policy, cmd) {
  if ((policy?.blocked?.commands || []).includes(cmd)) return 'blocked'
  if ((policy?.requires_confirmation?.commands || []).includes(cmd)) return 'requires_confirmation'
  if ((policy?.requires_simulation?.commands || []).includes(cmd)) return 'requires_simulation'
  return 'allowed'
}

function setTier(policy, cmd, tier) {
  const next = deepClone(policy)
  const remove = (arr = []) => arr.filter((x) => x !== cmd)
  next.blocked.commands = remove(next.blocked?.commands)
  next.requires_confirmation.commands = remove(next.requires_confirmation?.commands)
  next.requires_simulation.commands = remove(next.requires_simulation?.commands)
  if (tier === 'blocked') next.blocked.commands.push(cmd)
  if (tier === 'requires_confirmation') next.requires_confirmation.commands.push(cmd)
  if (tier === 'requires_simulation') next.requires_simulation.commands.push(cmd)
  return next
}

function getOverride(policy, cmd) {
  return policy?.ui_overrides?.commands?.[cmd] || {}
}

function setOverride(policy, cmd, patch) {
  const next = deepClone(policy)
  next.ui_overrides = next.ui_overrides || {}
  next.ui_overrides.commands = next.ui_overrides.commands || {}
  const merged = { ...(next.ui_overrides.commands[cmd] || {}), ...patch }
  if (merged.retry_override === undefined) delete merged.retry_override
  if (!merged.budget || Object.keys(merged.budget).length === 0) delete merged.budget
  if (!merged.retry_override && !merged.budget) delete next.ui_overrides.commands[cmd]
  else next.ui_overrides.commands[cmd] = merged
  return next
}

function relativeTime(iso) {
  try {
    const d = new Date(iso)
    const sec = Math.max(0, Math.floor((Date.now() - d.getTime()) / 1000))
    if (sec < 60) return `${sec} seconds ago`
    const min = Math.floor(sec / 60)
    if (min < 60) return `${min} minute${min === 1 ? '' : 's'} ago`
    const hr = Math.floor(min / 60)
    return `${hr} hour${hr === 1 ? '' : 's'} ago`
  } catch {
    return iso
  }
}

export default function App() {
  const [activeRail, setActiveRail] = useState('approvals')
  const [activeTab, setActiveTab] = useState('all')
  const [policyHash, setPolicyHash] = useState('')
  const [appliedPolicy, setAppliedPolicy] = useState(null)
  const [draftPolicy, setDraftPolicy] = useState(null)
  const [search, setSearch] = useState('')
  const [jsonOpen, setJsonOpen] = useState(false)
  const [jsonText, setJsonText] = useState('')
  const [jsonError, setJsonError] = useState('')
  const [message, setMessage] = useState('')
  const [pendingApprovals, setPendingApprovals] = useState([])
  const [descriptions, setDescriptions] = useState({})
  const [contexts, setContexts] = useState({})
  const [runtimePaths, setRuntimePaths] = useState({})
  const [tabDefs, setTabDefs] = useState(DEFAULT_TABS)
  const [tabCommands, setTabCommands] = useState({ all: [] })
  const [allCommands, setAllCommands] = useState([])
  const [commandModal, setCommandModal] = useState({ open: false, command: '' })
  const [newCommand, setNewCommand] = useState('')
  const [newComment, setNewComment] = useState('')
  const [newCommandTabs, setNewCommandTabs] = useState([])
  const [newCategoryLabel, setNewCategoryLabel] = useState('')
  const [removing, setRemoving] = useState({})
  const [loaded, setLoaded] = useState(false)
  const [showAdvanced, setShowAdvanced] = useState(() => {
    if (typeof window === 'undefined') return false
    return window.localStorage.getItem(ADVANCED_TOGGLE_KEY) === '1'
  })
  const pollRef = useRef(null)

  const unsaved = useMemo(() => {
    if (!appliedPolicy || !draftPolicy) return false
    return JSON.stringify(appliedPolicy) !== JSON.stringify(draftPolicy)
  }, [appliedPolicy, draftPolicy])

  async function fetchPolicy() {
    const res = await fetch(`${API_BASE}/policy`)
    if (!res.ok) throw new Error(`Policy load failed (${res.status})`)
    const payload = await res.json()
    const payloadContexts = payload.contexts || {}
    const fallbackTabs = (() => {
      const labels = new Set()
      for (const list of Object.values(payloadContexts)) {
        for (const label of list || []) labels.add(String(label))
      }
      const extras = Array.from(labels)
        .sort((a, b) => a.localeCompare(b))
        .map((label) => ({ id: slugifyCategoryId(label), label }))
      return [{ id: 'all', label: 'All Commands' }, ...extras]
    })()
    setPolicyHash(payload.hash || '')
    setAppliedPolicy(payload.policy)
    setDraftPolicy(deepClone(payload.policy))
    setJsonText(JSON.stringify(payload.policy, null, 2))
    setDescriptions(payload.descriptions || {})
    setContexts(payloadContexts)
    setRuntimePaths(payload.runtime_paths || {})
    setTabDefs(payload.tabs?.length ? payload.tabs : fallbackTabs)
    setTabCommands(payload.tab_commands || { all: payload.all_commands || [] })
    setAllCommands(payload.all_commands || [])
    setJsonError('')
    setLoaded(true)
  }

  async function fetchApprovals() {
    const res = await fetch(`${API_BASE}/approvals/pending`)
    if (!res.ok) return
    const payload = await res.json()
    setPendingApprovals(payload.pending || [])
  }

  useEffect(() => {
    // Poll pending approvals every 3 seconds so operator actions/agent requests
    // from other processes appear without manual refresh.
    fetchPolicy().catch((err) => setMessage(err.message))
    fetchApprovals()
    pollRef.current = setInterval(fetchApprovals, 3000)
    return () => clearInterval(pollRef.current)
  }, [])

  useEffect(() => {
    if (typeof window !== 'undefined') {
      window.localStorage.setItem(ADVANCED_TOGGLE_KEY, showAdvanced ? '1' : '0')
    }
  }, [showAdvanced])

  useEffect(() => {
    // Table edits are source-of-truth while editing. Keep JSON textarea in sync
    // with the draft policy state to support dual editing surfaces.
    if (draftPolicy) {
      setJsonText(JSON.stringify(draftPolicy, null, 2))
    }
  }, [draftPolicy])

  useEffect(() => {
    if (!tabDefs.some((t) => t.id === activeTab)) {
      setActiveTab('all')
    }
  }, [activeTab, tabDefs])

  const commandRows = useMemo(() => {
    const base = activeTab === 'all' ? allCommands : (tabCommands[activeTab] || [])
    const q = search.trim().toLowerCase()
    return base.filter((cmd) => !q || cmd.toLowerCase().includes(q))
  }, [allCommands, activeTab, search, tabCommands])

  function onJsonChange(next) {
    setJsonText(next)
    try {
      // Bidirectional sync: valid JSON edits replace table-backed draft state.
      // Invalid JSON is tolerated in textarea without destroying current table state.
      const parsed = JSON.parse(next)
      setDraftPolicy(parsed)
      setJsonError('')
    } catch (e) {
      setJsonError('Invalid JSON. Table state remains unchanged until valid parse.')
    }
  }

  async function onValidate() {
    if (!draftPolicy) return
    const res = await fetch(`${API_BASE}/policy/validate`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ policy: draftPolicy })
    })
    const payload = await res.json()
    if (res.ok) setMessage('Validation passed')
    else setMessage(payload.error || 'Validation failed')
  }

  async function onApply() {
    if (!draftPolicy) return
    const res = await fetch(`${API_BASE}/policy/apply`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Actor': 'control-plane-v3' }, body: JSON.stringify({ policy: draftPolicy })
    })
    const payload = await res.json()
    if (!res.ok) {
      setMessage(payload.error || 'Apply failed')
      return
    }
    await fetchPolicy()
    setMessage('Policy applied')
  }

  async function onReload() {
    if (unsaved && !window.confirm('Discard unsaved edits and reload from backend?')) return
    await fetchPolicy()
    setMessage('Reloaded latest policy')
  }

  function ensureUiCatalogTab(policy, id, label) {
    const next = deepClone(policy)
    next.ui_catalog = next.ui_catalog || {}
    next.ui_catalog.tabs = Array.isArray(next.ui_catalog.tabs) ? next.ui_catalog.tabs : []
    let tab = next.ui_catalog.tabs.find((t) => t.id === id)
    if (!tab) {
      tab = { id, label, commands: [], descriptions: {} }
      next.ui_catalog.tabs.push(tab)
    } else {
      tab.label = label
      tab.commands = Array.isArray(tab.commands) ? tab.commands : []
      tab.descriptions = typeof tab.descriptions === 'object' && tab.descriptions ? tab.descriptions : {}
    }
    return next
  }

  function onCreateCategory() {
    const label = String(newCategoryLabel || '').trim()
    if (!label) {
      setMessage('Category name is required')
      return
    }
    const id = slugifyCategoryId(label)
    if (tabDefs.some((t) => t.id === id)) {
      setMessage(`Category "${label}" already exists`)
      return
    }
    setDraftPolicy((prev) => ensureUiCatalogTab(prev, id, label))
    setTabDefs((prev) => [...prev, { id, label }])
    setTabCommands((prev) => ({ ...prev, [id]: [] }))
    setNewCategoryLabel('')
    setMessage(`Category "${label}" added`)
  }

  function onAddCommand() {
    const command = normalizeCommandName(newCommand)
    if (!command) {
      setMessage('Command text is required')
      return
    }
    const selectedTabs = newCommandTabs.length ? newCommandTabs : (activeTab !== 'all' ? [activeTab] : [])
    if (!selectedTabs.length) {
      setMessage('Select at least one category')
      return
    }
    const validTabs = selectedTabs.filter((id) => id !== 'all' && tabDefs.some((t) => t.id === id))
    if (!validTabs.length) {
      setMessage('Select at least one valid non-All category')
      return
    }

    setDraftPolicy((prev) => {
      let next = deepClone(prev)
      for (const tabId of validTabs) {
        const tabLabel = tabDefs.find((t) => t.id === tabId)?.label || tabId
        next = ensureUiCatalogTab(next, tabId, tabLabel)
        const tab = next.ui_catalog.tabs.find((t) => t.id === tabId)
        if (!tab.commands.includes(command)) {
          tab.commands.push(command)
          tab.commands.sort()
        }
        if (String(newComment || '').trim()) {
          tab.descriptions[command] = String(newComment).trim()
        }
      }
      return next
    })

    setAllCommands((prev) => Array.from(new Set([...prev, command])).sort())
    if (String(newComment || '').trim()) {
      const comment = String(newComment).trim()
      setDescriptions((prev) => ({ ...prev, [command]: comment }))
    }
    setContexts((prev) => {
      const next = { ...prev }
      for (const tabId of validTabs) {
        const label = tabDefs.find((t) => t.id === tabId)?.label || tabId
        const cur = new Set(next[command] || [])
        cur.add(label)
        next[command] = Array.from(cur)
      }
      return next
    })
    setTabCommands((prev) => {
      const next = { ...prev }
      for (const tabId of validTabs) {
        const cur = new Set(next[tabId] || [])
        cur.add(command)
        next[tabId] = Array.from(cur).sort()
      }
      next.all = Array.from(new Set([...(next.all || []), command])).sort()
      return next
    })
    setNewCommand('')
    setNewComment('')
    setNewCommandTabs(activeTab !== 'all' ? [activeTab] : [])
    setMessage(`Command "${command}" added`)
  }

  async function approve(token, command) {
    const res = await fetch(`${API_BASE}/approvals/approve`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token, command })
    })
    if (!res.ok) {
      const payload = await res.json().catch(() => ({}))
      setMessage(payload.error || `Approve failed (${res.status})`)
      return
    }
    setRemoving((r) => ({ ...r, [token]: true }))
    setTimeout(() => setPendingApprovals((prev) => prev.filter((p) => p.token !== token)), 180)
  }

  async function deny(token) {
    const res = await fetch(`${API_BASE}/approvals/deny`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token })
    })
    if (!res.ok) {
      const payload = await res.json().catch(() => ({}))
      setMessage(payload.error || `Deny failed (${res.status})`)
      return
    }
    setRemoving((r) => ({ ...r, [token]: true }))
    setTimeout(() => setPendingApprovals((prev) => prev.filter((p) => p.token !== token)), 180)
  }

  function renderRailItem(item) {
    const isActive = activeRail === item.id
    const pending = item.id === 'approvals' ? pendingApprovals.length : 0
    return (
      <button
        key={item.id}
        onClick={() => setActiveRail(item.id)}
        className={`relative flex flex-col items-center justify-center gap-1 py-3 rounded-xl text-xs transition border ${
          isActive ? 'bg-brand text-white border-brand' : 'bg-white text-slate-700 border-slate-200 hover:border-brand/40'
        } ${pending > 0 && item.id === 'approvals' ? 'ring-1 ring-amber-300 bg-amber-50 text-amber-700' : ''}`}
      >
        <span className="text-base">{item.icon}</span>
        <span>{item.label}</span>
        {pending > 0 && (
          <span className="absolute -top-1 -right-1 text-[10px] px-1.5 py-0.5 rounded-full bg-amber-500 text-white">{pending}</span>
        )}
      </button>
    )
  }

  function CommandRow({ cmd }) {
    const currentTier = tierFor(draftPolicy, cmd)
    const appliedTier = tierFor(appliedPolicy, cmd)
    const applied = getOverride(appliedPolicy, cmd)
    const draftOverride = getOverride(draftPolicy, cmd)
    const contextList = (contexts[cmd] || []).join(', ') || 'Uncategorized'
    const allowAdvanced = currentTier !== 'allowed'
    const gridTemplateColumns = `${BASIC_GRID_COLS}${showAdvanced ? ADVANCED_GRID_TAIL : ''}`.replaceAll('_', ' ')

    const onRetry = (value) => {
      const next = value === '' ? undefined : Math.max(0, Math.min(10, parseInt(value, 10) || 0))
      setDraftPolicy((p) => setOverride(p, cmd, { retry_override: next }))
    }

    const onBudget = (field, value) => {
      const existing = { ...(draftOverride.budget || {}) }
      if (value === '') delete existing[field]
      else existing[field] = Math.max(0, parseInt(value, 10) || 0)
      setDraftPolicy((p) => setOverride(p, cmd, { budget: Object.keys(existing).length ? existing : undefined }))
    }

    return (
      <div className="grid gap-2 items-center border-b border-slate-200 py-2 text-sm" style={{ gridTemplateColumns }}>
        <div className="bg-white">
          <div className="font-semibold text-slate-800 flex items-center gap-2">
            <span className="font-mono">{cmd}</span>
            <button
              type="button"
              className="text-slate-400 hover:text-slate-600"
              onClick={() => setCommandModal({ open: true, command: cmd })}
              title="View command details"
            >
              ⓘ
            </button>
            <span className={`px-2 py-0.5 rounded-full border text-xs ${STATUS_STYLE[appliedTier]}`}>{STATUS_LABEL[appliedTier]}</span>
            {applied.retry_override !== undefined && <span className="text-xs px-2 py-0.5 border rounded-full text-slate-600">Retry {applied.retry_override}</span>}
            {applied.budget && <span className="text-xs px-2 py-0.5 border rounded-full text-slate-600">Budget set</span>}
          </div>
          <div className="text-xs text-slate-400">{contextList}</div>
        </div>
        {BASIC_TIER_COLUMNS.map((col) => (
          <label key={col.key} className="flex justify-center bg-white">
            <input
              type="radio"
              name={`tier-${cmd}`}
              checked={currentTier === col.key}
              onChange={() => setDraftPolicy((p) => setTier(p, cmd, col.key))}
            />
          </label>
        ))}
        {showAdvanced && ADVANCED_TIER_COLUMNS.map((col) => (
          <label
            key={col.key}
            className={`flex justify-center bg-blue-50 ${col.key === 'requires_simulation' ? 'border-l-2 border-slate-300 pl-4' : ''}`}
          >
            <input
              type="radio"
              name={`tier-${cmd}`}
              checked={currentTier === col.key}
              onChange={() => setDraftPolicy((p) => setTier(p, cmd, col.key))}
            />
          </label>
        ))}
        {showAdvanced && (
          <>
            <input
              type="number"
              min={0}
              max={10}
              placeholder="-"
              disabled={!allowAdvanced}
              title={!allowAdvanced ? 'Retry override is not relevant when command is Allowed' : 'Per-command metadata (runtime enforcement pending)'}
              className="border rounded px-2 py-1 disabled:bg-slate-100 disabled:text-slate-400 border-l-2 border-slate-300 pl-4 bg-white/80"
              value={draftOverride.retry_override ?? ''}
              onChange={(e) => onRetry(e.target.value)}
            />
            <input
              type="number"
              min={0}
              placeholder="-"
              disabled={!allowAdvanced}
              title={!allowAdvanced ? 'Budget metadata disabled when command is Allowed' : 'Per-command metadata (runtime enforcement pending)'}
              className="border rounded px-2 py-1 disabled:bg-slate-100 disabled:text-slate-400 bg-white/80"
              value={draftOverride?.budget?.max_ops_per_session ?? ''}
              onChange={(e) => onBudget('max_ops_per_session', e.target.value)}
            />
            <input
              type="number"
              min={0}
              placeholder="-"
              disabled={!allowAdvanced}
              className="border rounded px-2 py-1 disabled:bg-slate-100 disabled:text-slate-400 bg-white/80"
              value={draftOverride?.budget?.max_unique_paths_per_session ?? ''}
              onChange={(e) => onBudget('max_unique_paths_per_session', e.target.value)}
            />
            <input
              type="number"
              min={0}
              placeholder="-"
              disabled={!allowAdvanced}
              className="border rounded px-2 py-1 disabled:bg-slate-100 disabled:text-slate-400 bg-white/80"
              value={draftOverride?.budget?.max_bytes_per_session ?? ''}
              onChange={(e) => onBudget('max_bytes_per_session', e.target.value)}
            />
          </>
        )}
      </div>
    )
  }

  function ApprovalsPanel() {
    if (!pendingApprovals.length) {
      return (
        <div className="bg-white rounded-xl border border-slate-200 p-8 text-center shadow-sm">
          <div className="text-3xl mb-2">🔔</div>
          <div className="text-green-700 font-semibold">No pending approvals</div>
        </div>
      )
    }
    return (
      <div className="space-y-3">
        <div className="text-slate-700 font-medium">{pendingApprovals.length} command(s) awaiting approval</div>
        {pendingApprovals.map((item) => {
          const urgency = item.seconds_remaining < 60
          return (
            <div
              key={item.token}
              className={`bg-white border-l-4 ${urgency ? 'border-red-400' : 'border-amber-400'} rounded-xl border border-slate-200 p-4 shadow-sm transition-all duration-200 ${removing[item.token] ? 'opacity-0 -translate-y-1' : 'opacity-100 translate-y-0'}`}
            >
              <div className="font-mono text-base font-semibold text-slate-800">{item.command}</div>
              <div className="text-xs text-slate-500 mt-1">Requested {relativeTime(item.requested_at)} • session <span className="font-mono">{item.session_id || 'n/a'}</span></div>
              <div className={`text-xs mt-1 ${urgency ? 'text-red-600 font-semibold' : 'text-slate-500'}`}>Expires in {item.seconds_remaining}s</div>
              {item.affected_paths?.length > 0 && (
                <details className="mt-2 text-sm">
                  <summary className="cursor-pointer text-slate-600">Affected paths ({item.affected_paths.length})</summary>
                  <ul className="mt-2 text-xs font-mono bg-slate-50 rounded p-2 border border-slate-200 max-h-32 overflow-auto">
                    {item.affected_paths.map((p) => <li key={p}>{p}</li>)}
                  </ul>
                </details>
              )}
              <div className="mt-3 flex gap-2">
                <button onClick={() => approve(item.token, item.command)} className="px-3 py-1.5 rounded-lg bg-green-600 text-white text-sm font-medium">Approve</button>
                <button onClick={() => deny(item.token)} className="px-3 py-1.5 rounded-lg border border-red-300 text-red-700 text-sm">Deny</button>
              </div>
            </div>
          )
        })}
      </div>
    )
  }

  function CommandsPanel() {
    const gridTemplateColumns = `${BASIC_GRID_COLS}${showAdvanced ? ADVANCED_GRID_TAIL : ''}`.replaceAll('_', ' ')
    const nonAllTabs = tabDefs.filter((t) => t.id !== 'all')
    return (
      <>
        <div className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm mb-3 space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-[1fr_1fr] gap-3">
            <div className="space-y-2">
              <div className="text-xs font-semibold text-slate-600 uppercase tracking-wide">Add Command</div>
              <div className="grid grid-cols-1 md:grid-cols-[1fr_1fr] gap-2">
                <input
                  value={newCommand}
                  onChange={(e) => setNewCommand(e.target.value)}
                  className="border border-slate-300 rounded-lg px-3 py-2"
                  placeholder="Command (e.g. git cherry-pick)"
                />
                <input
                  value={newComment}
                  onChange={(e) => setNewComment(e.target.value)}
                  className="border border-slate-300 rounded-lg px-3 py-2"
                  placeholder="Description/comment shown in info modal"
                />
              </div>
              <div className="flex flex-wrap gap-2">
                {nonAllTabs.map((tab) => (
                  <label key={tab.id} className="text-xs border border-slate-300 rounded px-2 py-1 bg-slate-50 flex items-center gap-1">
                    <input
                      type="checkbox"
                      checked={newCommandTabs.includes(tab.id)}
                      onChange={(e) => {
                        if (e.target.checked) setNewCommandTabs((prev) => Array.from(new Set([...prev, tab.id])))
                        else setNewCommandTabs((prev) => prev.filter((x) => x !== tab.id))
                      }}
                    />
                    <span>{tab.label}</span>
                  </label>
                ))}
              </div>
              <button onClick={onAddCommand} className="px-3 py-1.5 rounded-lg bg-brand text-white text-sm">Add command</button>
            </div>
            <div className="space-y-2">
              <div className="text-xs font-semibold text-slate-600 uppercase tracking-wide">Add Category</div>
              <div className="flex gap-2">
                <input
                  value={newCategoryLabel}
                  onChange={(e) => setNewCategoryLabel(e.target.value)}
                  className="border border-slate-300 rounded-lg px-3 py-2 flex-1"
                  placeholder="Category name (e.g. Databases)"
                />
                <button onClick={onCreateCategory} className="px-3 py-1.5 rounded-lg border border-slate-300 bg-white text-slate-700 text-sm">Add category</button>
              </div>
            </div>
          </div>
        </div>
        <div className="flex items-center justify-between mb-3">
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full border border-slate-300 rounded-lg px-3 py-2 bg-white"
            placeholder="Filter commands..."
          />
        </div>
        <div className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm overflow-auto">
          <div className="grid gap-2 text-xs font-semibold text-slate-500 border-b border-slate-200 pb-2" style={{ gridTemplateColumns }}>
            <div />
            <div className="text-center col-span-2 rounded-md bg-white py-1 text-slate-700 border border-slate-200">Basic</div>
            {showAdvanced ? (
              <div className="col-span-6 rounded-md bg-blue-50 py-1 text-slate-700 border-l-2 border-slate-300 pl-4 pr-2 flex items-center justify-between">
                <span className="font-semibold">Advanced</span>
                <button
                  onClick={() => setShowAdvanced(false)}
                  className="text-xs text-slate-500 underline underline-offset-2 hover:text-slate-700"
                >
                  Hide advanced settings
                </button>
              </div>
            ) : (
              <div className="col-span-1 py-1 px-2 flex items-center justify-end">
                <button
                  onClick={() => setShowAdvanced(true)}
                  className="text-xs text-slate-500 underline underline-offset-2 hover:text-slate-700"
                >
                  Show advanced settings
                </button>
              </div>
            )}
          </div>
          <div className="grid gap-2 text-xs font-semibold text-slate-500 border-b border-slate-200 pb-2 pt-2" style={{ gridTemplateColumns }}>
            <div className="bg-white">Command</div>
            <div className="text-center bg-white">Allowed</div>
            <div className="text-center bg-white">Blocked</div>
            {showAdvanced && (
              <>
                <div className="text-center bg-blue-50 border-l-2 border-slate-300 pl-4">Simulation</div>
                <div className="text-center bg-blue-50">Requires Approval</div>
                <div className="text-center bg-blue-50 border-l-2 border-slate-300 pl-4">Retry</div>
                <div className="text-center bg-blue-50">Budget Ops</div>
                <div className="text-center bg-blue-50">Budget Paths</div>
                <div className="text-center bg-blue-50">Budget Bytes</div>
              </>
            )}
          </div>
          {commandRows.map((cmd) => <CommandRow key={cmd} cmd={cmd} />)}
        </div>
        <div className="mt-4 bg-white border border-slate-200 rounded-xl p-3 shadow-sm">
          <button onClick={() => setJsonOpen((x) => !x)} className="text-sm font-medium text-slate-700">
            {jsonOpen ? '▾' : '▸'} Advanced JSON
          </button>
          {jsonOpen && (
            <textarea
              value={jsonText}
              onChange={(e) => onJsonChange(e.target.value)}
              className="mt-3 w-full h-72 border border-slate-300 rounded-lg p-3 font-mono text-xs"
            />
          )}
          {jsonError && <div className="mt-2 text-sm text-red-600">{jsonError}</div>}
          {message && <div className="mt-2 text-sm text-slate-700">{message}</div>}
          <div className="mt-4 flex gap-2">
            <button onClick={onReload} className="px-4 py-2 rounded-lg border border-slate-300 bg-white text-slate-700">Reload</button>
            <button onClick={onValidate} className="px-4 py-2 rounded-lg bg-blue-600 text-white">Validate</button>
            <button onClick={onApply} className="px-4 py-2 rounded-lg bg-brand text-white">Apply</button>
          </div>
        </div>
      </>
    )
  }

  function PathsPanel() {
    return (
      <div className="space-y-3">
        <div className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm space-y-2">
          <div className="text-xs font-semibold text-slate-600 uppercase tracking-wide">Runtime Paths (Read Only)</div>
          <div className="grid grid-cols-1 gap-2">
            {Object.entries(runtimePaths).map(([key, value]) => (
              <div key={key} className="grid grid-cols-1 md:grid-cols-[260px_1fr] gap-2 items-center">
                <div className="text-xs font-mono text-slate-500">{key}</div>
                <input
                  value={String(value || '')}
                  readOnly
                  className="border border-slate-300 rounded-lg px-3 py-2 bg-slate-100 text-slate-700 font-mono text-xs"
                />
              </div>
            ))}
          </div>
          <div className="text-xs text-amber-700 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2">
            Runtime paths are managed by MCP client configuration/env. To change workspace paths, update your AI agent MCP config,
            then restart the MCP server and agent client.
          </div>
        </div>
      </div>
    )
  }

  function CommandInfoModal() {
    if (!commandModal.open) return null
    const cmd = commandModal.command
    const contextsForCmd = contexts[cmd] || []
    return (
      <div className="fixed inset-0 z-30 bg-slate-900/40 flex items-center justify-center p-4" onClick={() => setCommandModal({ open: false, command: '' })}>
        <div className="bg-white rounded-xl border border-slate-200 shadow-lg w-full max-w-lg" onClick={(e) => e.stopPropagation()}>
          <div className="px-4 py-3 border-b border-slate-200 flex items-center justify-between">
            <div className="font-semibold text-slate-800">Command Details</div>
            <button className="text-slate-500 hover:text-slate-700" onClick={() => setCommandModal({ open: false, command: '' })}>✕</button>
          </div>
          <div className="p-4 space-y-3 text-sm">
            <div>
              <div className="text-xs uppercase tracking-wide text-slate-500 mb-1">Command</div>
              <div className="font-mono text-slate-800">{cmd}</div>
            </div>
            <div>
              <div className="text-xs uppercase tracking-wide text-slate-500 mb-1">Description</div>
              <div className="text-slate-700">{descriptions[cmd] || 'No description available for this command.'}</div>
            </div>
            <div>
              <div className="text-xs uppercase tracking-wide text-slate-500 mb-1">Categories</div>
              <div className="text-slate-700">{contextsForCmd.length ? contextsForCmd.join(', ') : 'Uncategorized'}</div>
            </div>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-[#f0f1f3] text-slate-800 font-[system-ui]">
      <div className="border-b border-slate-200 bg-white/80 backdrop-blur px-5 py-4 sticky top-0 z-10">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold">Policy Control Plane</h1>
            <div className="text-xs text-slate-500 mt-1">Policy hash: <span className="font-mono">{policyHash || '-'}</span></div>
          </div>
          <div className="flex flex-col items-end gap-1">
            <div className="flex items-center gap-2">
              <div className="flex flex-col items-center gap-1">
                <span className="text-[10px] uppercase tracking-wide text-slate-500">Basic</span>
                <div className="flex items-center gap-2">
                  {['allowed', 'blocked'].map((k) => (
                    <span key={k} className={`px-2 py-0.5 rounded-full border text-xs ${STATUS_STYLE[k]}`}>{STATUS_LABEL[k]}</span>
                  ))}
                </div>
              </div>
              <span className="h-6 border-l border-slate-300 mx-2" />
              <div className="flex flex-col items-center gap-1">
                <span className="text-[10px] uppercase tracking-wide text-slate-500">Advanced</span>
                <div className="flex items-center gap-2">
                  {['requires_simulation', 'requires_confirmation'].map((k) => (
                    <span key={k} className={`px-2 py-0.5 rounded-full border text-xs ${STATUS_STYLE[k]}`}>{STATUS_LABEL[k]}</span>
                  ))}
                </div>
              </div>
              {unsaved && <span className="text-xs text-amber-700 font-medium flex items-center gap-1 ml-2"><span className="w-2 h-2 rounded-full bg-amber-500" /> Unsaved changes</span>}
            </div>
            <span className="text-xs italic text-slate-500">Status badges reflect applied policy (after Apply), not unsaved edits</span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-[74px_170px_1fr] gap-0 min-h-[calc(100vh-84px)]">
        <nav className="border-r border-slate-200 p-2 bg-white">
          <div className="space-y-2">
            {renderRailItem(RAIL_ITEMS[0])}
          </div>
          <div className="my-3 border-t border-slate-200" />
          <div className="space-y-2">
            {RAIL_ITEMS.slice(1).map(renderRailItem)}
          </div>
        </nav>

        {activeRail === 'commands' ? (
          <aside className="border-r border-slate-200 bg-white p-3 space-y-2">
            {tabDefs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`w-full text-left px-3 py-2 rounded-lg text-sm ${activeTab === tab.id ? 'bg-brand text-white' : 'text-slate-700 hover:bg-slate-100'}`}
              >
                {tab.label}
              </button>
            ))}
          </aside>
        ) : (
          <aside className="border-r border-slate-200 bg-white p-3" />
        )}

        <main className="p-4">
          {!loaded && <div className="text-slate-500">Loading...</div>}
          {loaded && activeRail === 'approvals' && ApprovalsPanel()}
          {loaded && activeRail === 'commands' && CommandsPanel()}
          {loaded && activeRail === 'paths' && PathsPanel()}
          {loaded && (activeRail === 'reports' || activeRail === 'settings') && (
            <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm text-slate-500">Coming soon</div>
          )}
        </main>
      </div>
      {CommandInfoModal()}
    </div>
  )
}
