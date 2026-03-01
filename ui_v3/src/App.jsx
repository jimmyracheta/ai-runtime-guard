import React, { useEffect, useMemo, useRef, useState } from 'react'

const API_BASE = 'http://127.0.0.1:5001'
const RAIL_ITEMS = [
  { id: 'approvals', label: 'Approvals', icon: '🔔' },
  { id: 'policy', label: 'Policy', icon: '🛡️' },
  { id: 'reports', label: 'Reports', icon: '📊' },
  { id: 'settings', label: 'Settings', icon: '⚙️' }
]
const POLICY_TABS = [
  { id: 'commands', label: 'Commands' },
  { id: 'paths', label: 'Paths' },
  { id: 'extensions', label: 'Extensions' },
  { id: 'network', label: 'Network' },
  { id: 'advanced', label: 'Advanced Policy' },
]
const REPORT_TABS = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'log', label: 'Log' },
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
const ADVANCED_TOGGLE_KEY = 'airg.ui.showAdvancedSettings'
const PATHS_ADVANCED_TOGGLE_KEY = 'airg.ui.showAdvancedPaths'
const RUNTIME_PATH_LABELS = {
  AIRG_WORKSPACE: 'Agent Workspace',
  AIRG_POLICY_PATH: 'Policy File',
  AIRG_APPROVAL_DB_PATH: 'Approval Database',
  AIRG_APPROVAL_HMAC_KEY_PATH: 'Approval Signing Key',
  AIRG_LOG_PATH: 'Log Path',
  AIRG_REPORTS_DB_PATH: 'Reports Database',
  AIRG_UI_DIST_PATH: 'UI Build Path',
}
const REPORT_FILTER_FIELDS = [
  { key: 'agent_id', label: 'Agent' },
  { key: 'source', label: 'Source' },
  { key: 'tool', label: 'Tool' },
  { key: 'decision_tier', label: 'Decision Tier' },
  { key: 'matched_rule', label: 'Matched Rule' },
  { key: 'command', label: 'Command' },
  { key: 'path', label: 'Path' },
]

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

function isAbsolutePath(path) {
  return String(path || '').startsWith('/')
}

function normalizeAbsolutePath(path) {
  const trimmed = String(path || '').trim()
  if (!trimmed) return ''
  if (!trimmed.startsWith('/')) return trimmed
  const collapsed = trimmed.replace(/\/{2,}/g, '/')
  if (collapsed.length > 1 && collapsed.endsWith('/')) return collapsed.replace(/\/+$/, '')
  return collapsed
}

function normalizeListToken(value) {
  return String(value || '').trim().replace(/\s+/g, ' ')
}

function normalizeDomain(value) {
  return String(value || '').trim().toLowerCase()
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
  const [activePolicyTab, setActivePolicyTab] = useState('commands')
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
  const [hasRevertSnapshot, setHasRevertSnapshot] = useState(false)
  const [hasDefaultSnapshot, setHasDefaultSnapshot] = useState(false)
  const [commandModal, setCommandModal] = useState({ open: false, command: '' })
  const [newCommand, setNewCommand] = useState('')
  const [newComment, setNewComment] = useState('')
  const [newCommandTabs, setNewCommandTabs] = useState([])
  const [newCategoryLabel, setNewCategoryLabel] = useState('')
  const [selectedCategories, setSelectedCategories] = useState([])
  const [newPathValue, setNewPathValue] = useState('')
  const [newPathTier, setNewPathTier] = useState('blocked')
  const [newExtensionValue, setNewExtensionValue] = useState('')
  const [newNetworkCommand, setNewNetworkCommand] = useState('')
  const [newWhitelistDomain, setNewWhitelistDomain] = useState('')
  const [newBlocklistDomain, setNewBlocklistDomain] = useState('')
  const [budgetBytesUnit, setBudgetBytesUnit] = useState('MB')
  const [removing, setRemoving] = useState({})
  const [loaded, setLoaded] = useState(false)
  const [reportsTab, setReportsTab] = useState('dashboard')
  const [reportsStatus, setReportsStatus] = useState(null)
  const [reportsOverview, setReportsOverview] = useState(null)
  const [reportsEvents, setReportsEvents] = useState([])
  const [reportsTotal, setReportsTotal] = useState(0)
  const [reportsConfirmations, setReportsConfirmations] = useState({ approved: 0, denied: 0 })
  const [reportsOffset, setReportsOffset] = useState(0)
  const [reportsLimit, setReportsLimit] = useState(50)
  const [reportsExpandedEventId, setReportsExpandedEventId] = useState(null)
  const [reportsLoading, setReportsLoading] = useState(false)
  const [reportsError, setReportsError] = useState('')
  const [reportsFilters, setReportsFilters] = useState({
    agent_id: '',
    source: '',
    tool: '',
    policy_decision: '',
    decision_tier: '',
    matched_rule: '',
    command: '',
    path: '',
    event: '',
  })
  const [reportsTimeFilter, setReportsTimeFilter] = useState('today')
  const [reportsCustomDay, setReportsCustomDay] = useState('')
  const [showAdvanced, setShowAdvanced] = useState(() => {
    if (typeof window === 'undefined') return false
    return window.localStorage.getItem(ADVANCED_TOGGLE_KEY) === '1'
  })
  const [showPathAdvanced, setShowPathAdvanced] = useState(() => {
    if (typeof window === 'undefined') return false
    return window.localStorage.getItem(PATHS_ADVANCED_TOGGLE_KEY) === '1'
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
    setHasRevertSnapshot(Boolean(payload.has_revert_snapshot))
    setHasDefaultSnapshot(Boolean(payload.has_default_snapshot))
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

  function buildReportQuery(extra = {}) {
    const params = new URLSearchParams()
    const merged = { ...reportsFilters, ...extra }
    for (const [k, v] of Object.entries(merged)) {
      const val = String(v || '').trim()
      if (val) params.set(k, val)
    }
    const now = new Date()
    const toIso = now.toISOString()
    if (reportsTimeFilter === 'all_time') {
      // no time bounds
    } else if (reportsTimeFilter === 'last_5_min') {
      const from = new Date(now.getTime() - 5 * 60 * 1000).toISOString()
      params.set('from', from)
      params.set('to', toIso)
    } else if (reportsTimeFilter === 'last_10_min') {
      const from = new Date(now.getTime() - 10 * 60 * 1000).toISOString()
      params.set('from', from)
      params.set('to', toIso)
    } else if (reportsTimeFilter === 'today') {
      const start = new Date(now)
      start.setHours(0, 0, 0, 0)
      params.set('from', start.toISOString())
      params.set('to', toIso)
    } else if (reportsTimeFilter === 'custom_day' && reportsCustomDay) {
      const start = new Date(`${reportsCustomDay}T00:00:00`)
      const end = new Date(`${reportsCustomDay}T23:59:59.999`)
      params.set('from', start.toISOString())
      params.set('to', end.toISOString())
    }
    return params.toString()
  }

  async function fetchReports({ sync } = { sync: false }) {
    setReportsLoading(true)
    setReportsError('')
    try {
      const q = buildReportQuery({ limit: reportsLimit, offset: reportsOffset, sync: sync ? '1' : '' })
      const [statusRes, overviewRes, eventsRes, confirmationsRes] = await Promise.all([
        fetch(`${API_BASE}/reports/status?${q}`),
        fetch(`${API_BASE}/reports/overview?${q}`),
        fetch(`${API_BASE}/reports/events?${q}`),
        fetch(`${API_BASE}/reports/confirmations?${q}`)
      ])
      if (!statusRes.ok || !overviewRes.ok || !eventsRes.ok || !confirmationsRes.ok) {
        throw new Error('Reports backend request failed')
      }
      const [statusPayload, overviewPayload, eventsPayload, confirmationsPayload] = await Promise.all([
        statusRes.json(),
        overviewRes.json(),
        eventsRes.json(),
        confirmationsRes.json(),
      ])
      setReportsStatus(statusPayload)
      setReportsOverview(overviewPayload)
      setReportsEvents(eventsPayload.events || [])
      setReportsTotal(eventsPayload.total || 0)
      setReportsConfirmations(confirmationsPayload.confirmations || { approved: 0, denied: 0 })
    } catch (err) {
      setReportsError(String(err.message || err))
    } finally {
      setReportsLoading(false)
    }
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
    if (activeRail !== 'reports') return
    fetchReports({ sync: true })
    const id = setInterval(() => fetchReports({ sync: true }), 300000)
    return () => clearInterval(id)
  }, [activeRail])

  useEffect(() => {
    if (activeRail !== 'reports') return
    fetchReports({ sync: false })
  }, [activeRail, reportsOffset, reportsLimit, reportsFilters, reportsTimeFilter, reportsCustomDay])

  useEffect(() => {
    if (typeof window !== 'undefined') {
      window.localStorage.setItem(ADVANCED_TOGGLE_KEY, showAdvanced ? '1' : '0')
    }
  }, [showAdvanced])

  useEffect(() => {
    if (typeof window !== 'undefined') {
      window.localStorage.setItem(PATHS_ADVANCED_TOGGLE_KEY, showPathAdvanced ? '1' : '0')
    }
  }, [showPathAdvanced])

  useEffect(() => {
    // Table edits are source-of-truth while editing. Keep JSON textarea in sync
    // with the draft policy state to support dual editing surfaces.
    if (draftPolicy) {
      setJsonText(JSON.stringify(draftPolicy, null, 2))
    }
  }, [draftPolicy])

  const commandRows = useMemo(() => {
    const base = allCommands
    const q = search.trim().toLowerCase()
    return base.filter((cmd) => {
      if (q && !cmd.toLowerCase().includes(q)) return false
      if (!selectedCategories.length) return true
      const cats = (contexts[cmd] || []).map((x) => String(x).toLowerCase())
      return selectedCategories.some((c) => cats.includes(c.toLowerCase()))
    })
  }, [allCommands, search, contexts, selectedCategories])

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

  async function onRevertLastApply() {
    if (!hasRevertSnapshot) {
      setMessage('No previous applied policy snapshot found')
      return
    }
    if (!window.confirm('Revert policy to the previous applied version?')) return
    const res = await fetch(`${API_BASE}/policy/revert-last`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Actor': 'control-plane-v3' }
    })
    const payload = await res.json().catch(() => ({}))
    if (!res.ok) {
      setMessage(payload.error || 'Revert failed')
      return
    }
    await fetchPolicy()
    setMessage('Reverted to previous applied policy')
  }

  async function onResetDefaults() {
    if (!hasDefaultSnapshot) {
      setMessage('No default snapshot found yet. Apply once to create one.')
      return
    }
    const confirmation = window.prompt('Type RESET to restore defaults')
    if (confirmation !== 'RESET') {
      setMessage('Reset canceled')
      return
    }
    const res = await fetch(`${API_BASE}/policy/reset-defaults`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Actor': 'control-plane-v3' }
    })
    const payload = await res.json().catch(() => ({}))
    if (!res.ok) {
      setMessage(payload.error || 'Reset failed')
      return
    }
    await fetchPolicy()
    setMessage('Policy reset to defaults')
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
    const selectedTabs = newCommandTabs
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
    setNewCommandTabs([])
    setMessage(`Command "${command}" added`)
  }

  function pathTierFor(policy, path) {
    if ((policy?.blocked?.paths || []).includes(path)) return 'blocked'
    if ((policy?.requires_confirmation?.paths || []).includes(path)) return 'requires_confirmation'
    if ((policy?.allowed?.paths_whitelist || []).includes(path)) return 'allowed'
    return 'allowed'
  }

  function setPathTier(policy, path, tier) {
    const next = deepClone(policy)
    const remove = (arr = []) => arr.filter((x) => x !== path)
    next.blocked.paths = remove(next.blocked?.paths)
    next.requires_confirmation.paths = remove(next.requires_confirmation?.paths)
    next.allowed.paths_whitelist = remove(next.allowed?.paths_whitelist)
    if (tier === 'blocked') next.blocked.paths.push(path)
    if (tier === 'requires_confirmation') next.requires_confirmation.paths.push(path)
    if (tier === 'allowed') next.allowed.paths_whitelist.push(path)
    next.blocked.paths = Array.from(new Set(next.blocked.paths)).sort()
    next.requires_confirmation.paths = Array.from(new Set(next.requires_confirmation.paths)).sort()
    next.allowed.paths_whitelist = Array.from(new Set(next.allowed.paths_whitelist)).sort()
    return next
  }

  function removePath(policy, path) {
    const next = deepClone(policy)
    next.blocked.paths = (next.blocked?.paths || []).filter((p) => p !== path)
    next.requires_confirmation.paths = (next.requires_confirmation?.paths || []).filter((p) => p !== path)
    next.allowed.paths_whitelist = (next.allowed?.paths_whitelist || []).filter((p) => p !== path)
    return next
  }

  function renamePath(policy, oldPath, newPath) {
    const normalized = String(newPath || '').trim()
    if (!normalized || !isAbsolutePath(normalized)) return policy
    const currentTier = pathTierFor(policy, oldPath)
    let next = removePath(policy, oldPath)
    next = setPathTier(next, normalized, currentTier)
    return next
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
        className={`relative w-full min-h-[102px] flex flex-col items-center justify-center gap-1 py-2 rounded-xl text-xs transition border ${
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
    const contextList = (contexts[cmd] || []).join(', ') || 'Uncategorized'
    const gridTemplateColumns = `${BASIC_GRID_COLS}${showAdvanced ? '_90px_90px' : ''}`.replaceAll('_', ' ')

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

  function ReportsPanel() {
    const totals = reportsOverview?.totals || {}
    const eventsPerDay = reportsOverview?.events_per_day_7d || []
    const blockedPerDay = reportsOverview?.blocked_per_day_7d || []
    const topCommands = reportsOverview?.top_commands || []
    const topPaths = reportsOverview?.top_paths || []
    const blockedByRule = reportsOverview?.blocked_by_rule || []
    const pageCount = Math.max(1, Math.ceil(reportsTotal / reportsLimit))
    const currentPage = Math.floor(reportsOffset / reportsLimit) + 1
    const pendingApprovalsCount = pendingApprovals.length

    const resetReportsFilters = () => {
      setReportsOffset(0)
      setReportsExpandedEventId(null)
      setReportsFilters({
        agent_id: '',
        source: '',
        tool: '',
        policy_decision: '',
        decision_tier: '',
        matched_rule: '',
        command: '',
        path: '',
        event: '',
      })
      setReportsTimeFilter('all_time')
      setReportsCustomDay('')
    }

    const openLogWithFilters = (patch = {}, options = {}) => {
      const clear = Boolean(options.clearAll)
      setReportsTab('log')
      setReportsOffset(0)
      if (clear) {
        resetReportsFilters()
      }
      setReportsFilters((prev) => ({ ...(clear ? {} : prev), ...patch }))
    }

    const TrendBars = ({ data, tone = 'blue' }) => {
      if (!data.length) return <div className="text-slate-500 text-xs">No data</div>
      const maxCount = Math.max(...data.map((x) => Number(x.count || 0)), 1)
      const barClass = tone === 'red' ? 'bg-red-400' : 'bg-blue-400'
      return (
        <div className="space-y-1">
          {data.slice(0, 7).map((row) => {
            const count = Number(row.count || 0)
            const width = Math.max(2, Math.round((count / maxCount) * 100))
            return (
              <div key={row.day} className="grid grid-cols-[92px_1fr_44px] items-center gap-2 text-xs font-mono">
                <div className="text-slate-600">{row.day}</div>
                <div className="h-2 bg-slate-100 rounded">
                  <div className={`h-2 rounded ${barClass}`} style={{ width: `${width}%` }} />
                </div>
                <div className="text-right text-slate-700">{count}</div>
              </div>
            )
          })}
        </div>
      )
    }

    return (
      <div className="space-y-3">
        <div className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm">
          <div className="flex items-center justify-between gap-3">
            <div>
              <div className="text-sm text-slate-700">
                Last indexed: <span className="font-mono text-xs">{reportsStatus?.last_ingested_at ? relativeTime(reportsStatus.last_ingested_at) : 'n/a'}</span>
              </div>
              <div className="text-[11px] text-slate-500 mt-1">Automatic refresh runs every 5 minutes.</div>
            </div>
            <button onClick={() => fetchReports({ sync: true })} className="px-3 py-1.5 rounded-lg border border-slate-300 text-slate-700 text-sm">Refresh</button>
          </div>
          {reportsError && <div className="mt-2 text-sm text-red-600">{reportsError}</div>}
          {reportsLoading && <div className="mt-2 text-xs text-slate-500">Refreshing reports...</div>}
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm space-y-2">
          <div className="flex items-center justify-between gap-2">
            <div className="text-xs font-semibold text-slate-600 uppercase tracking-wide">Filters</div>
            <button
              onClick={resetReportsFilters}
              className="px-2 py-1 rounded border border-slate-300 text-xs text-slate-700 hover:bg-slate-50"
            >
              Reset filters
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
            {REPORT_FILTER_FIELDS.map((field) => (
              <input
                key={field.key}
                value={reportsFilters[field.key] || ''}
                onChange={(e) => {
                  setReportsOffset(0)
                  setReportsFilters((prev) => ({ ...prev, [field.key]: e.target.value }))
                }}
                className="border border-slate-300 rounded-lg px-3 py-2 text-xs font-mono"
                placeholder={field.label}
                title={field.label}
              />
            ))}
            <select
              value={reportsTimeFilter}
              onChange={(e) => {
                setReportsOffset(0)
                setReportsTimeFilter(e.target.value)
              }}
              className="border border-slate-300 rounded-lg px-3 py-2 text-xs"
            >
              <option value="all_time">All Time</option>
              <option value="last_5_min">Last 5 min</option>
              <option value="last_10_min">Last 10 min</option>
              <option value="today">Today</option>
              <option value="custom_day">Custom day</option>
            </select>
            {reportsTimeFilter === 'custom_day' && (
              <input
                type="date"
                value={reportsCustomDay}
                onChange={(e) => {
                  setReportsOffset(0)
                  setReportsCustomDay(e.target.value)
                }}
                className="border border-slate-300 rounded-lg px-3 py-2 text-xs"
              />
            )}
          </div>
        </div>

        {reportsTab === 'dashboard' && (
          <>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
              <button
                onClick={() => openLogWithFilters({}, { clearAll: true })}
                className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm text-left hover:border-brand/60 cursor-pointer"
              >
                <div className="text-xs text-slate-500">Total events</div>
                <div className="text-2xl font-semibold">{totals.total_events || 0}</div>
              </button>
              <button
                onClick={() => openLogWithFilters({ policy_decision: 'blocked' }, { clearAll: true })}
                className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm text-left hover:border-brand/60 cursor-pointer"
              >
                <div className="text-xs text-slate-500">Blocked events</div>
                <div className="text-2xl font-semibold text-red-700">{totals.blocked_events || 0}</div>
                {(totals.blocked_events || 0) === 0 && <div className="text-[11px] text-slate-500 mt-1">No policy blocks recorded</div>}
              </button>
              <button
                onClick={() => openLogWithFilters({ event: 'backup_created' }, { clearAll: true })}
                className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm text-left hover:border-brand/60 cursor-pointer"
              >
                <div className="text-xs text-slate-500">Backups created</div>
                <div className="text-2xl font-semibold text-blue-700">{totals.backup_events || 0}</div>
                {(totals.backup_events || 0) === 0 && <div className="text-[11px] text-slate-500 mt-1">No destructive operations recorded</div>}
              </button>
              <button
                onClick={() => setActiveRail('approvals')}
                className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm text-left hover:border-brand/60 cursor-pointer"
              >
                <div className="text-xs text-slate-500">Confirmations</div>
                <div className="text-sm font-mono mt-1 text-slate-700">Pending: {pendingApprovalsCount}</div>
                <div className="text-sm font-mono text-green-700">Approved: {reportsConfirmations.approved || 0}</div>
                <div className="text-sm font-mono text-red-700">Denied: {reportsConfirmations.denied || 0}</div>
                {pendingApprovalsCount === 0 && <div className="text-[11px] text-slate-500 mt-1">No pending approvals</div>}
              </button>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm">
                <div className="text-sm font-semibold text-slate-700 mb-2">Events per day (7d)</div>
                <TrendBars data={eventsPerDay} tone="blue" />
              </div>
              <div className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm">
                <div className="text-sm font-semibold text-slate-700 mb-2">Blocked per day (7d)</div>
                <TrendBars data={blockedPerDay} tone="red" />
              </div>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm">
                <div className="text-sm font-semibold text-slate-700 mb-2">Top commands</div>
                <div className="space-y-1 text-xs font-mono">
                  {topCommands.length === 0 && <div className="text-slate-500">No data</div>}
                  {topCommands.map((row) => {
                    const total = Number(row.count || 0)
                    const allowed = Number(row.allowed_count || 0)
                    const blocked = Number(row.blocked_count || 0)
                    const allowedPct = total > 0 ? Math.round((allowed / total) * 100) : 0
                    const blockedPct = total > 0 ? Math.round((blocked / total) * 100) : 0
                    return (
                      <button
                        key={row.command}
                        onClick={() => openLogWithFilters({ command: row.command }, { clearAll: true })}
                        className="w-full text-left border border-transparent hover:border-slate-300 rounded px-1 py-1 cursor-pointer"
                      >
                        <div className="flex justify-between mb-1">
                          <span>{row.command}</span>
                          <span>{total}</span>
                        </div>
                        <div className="h-2 bg-slate-100 rounded overflow-hidden flex">
                          <div className="bg-green-400" style={{ width: `${allowedPct}%` }} />
                          <div className="bg-red-400" style={{ width: `${blockedPct}%` }} />
                        </div>
                      </button>
                    )
                  })}
                </div>
              </div>
              <div className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm">
                <div className="text-sm font-semibold text-slate-700 mb-2">Top paths</div>
                <div className="space-y-1 text-xs font-mono">
                  {topPaths.length === 0 && <div className="text-slate-500">No data</div>}
                  {topPaths.map((row) => (
                    <button
                      key={row.path}
                      onClick={() => openLogWithFilters({ path: row.path }, { clearAll: true })}
                      className="w-full text-left flex justify-between border border-transparent hover:border-slate-300 rounded px-1 py-1 cursor-pointer"
                    >
                      <span className="truncate pr-2">{row.path}</span>
                      <span>{row.count}</span>
                    </button>
                  ))}
                </div>
              </div>
              <div className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm">
                <div className="text-sm font-semibold text-slate-700 mb-2">Blocked by rule</div>
                <div className="space-y-1 text-xs font-mono">
                  {blockedByRule.length === 0 && <div className="text-slate-500">No data</div>}
                  {blockedByRule.map((row) => (
                    <button
                      key={row.matched_rule}
                      onClick={() => openLogWithFilters({ matched_rule: row.matched_rule }, { clearAll: true })}
                      className="w-full text-left flex justify-between border border-transparent hover:border-slate-300 rounded px-1 py-1 cursor-pointer"
                    >
                      <span>{row.matched_rule}</span>
                      <span>{row.count}</span>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </>
        )}

        {reportsTab === 'log' && (
          <div className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm">
            <div className="flex items-center justify-between text-sm mb-2">
              <div className="text-slate-700">Log events ({reportsTotal})</div>
              <div className="flex items-center gap-2">
                <button
                  disabled={currentPage <= 1}
                  onClick={() => setReportsOffset(Math.max(0, reportsOffset - reportsLimit))}
                  className="px-2 py-1 border border-slate-300 rounded text-xs disabled:opacity-50"
                >
                  Prev
                </button>
                <span className="text-xs text-slate-500">Page {currentPage}/{pageCount}</span>
                <button
                  disabled={currentPage >= pageCount}
                  onClick={() => setReportsOffset(reportsOffset + reportsLimit)}
                  className="px-2 py-1 border border-slate-300 rounded text-xs disabled:opacity-50"
                >
                  Next
                </button>
              </div>
            </div>
            <div className="overflow-auto border border-slate-200 rounded-lg">
              <table className="min-w-full text-xs">
                <thead className="bg-slate-50 text-slate-600">
                  <tr>
                    <th className="text-left px-2 py-1"> </th>
                    <th className="text-left px-2 py-1">Time</th>
                    <th className="text-left px-2 py-1">Agent</th>
                    <th className="text-left px-2 py-1">Source</th>
                    <th className="text-left px-2 py-1">Tool</th>
                    <th className="text-left px-2 py-1">Decision</th>
                    <th className="text-left px-2 py-1">Matched Rule</th>
                    <th className="text-left px-2 py-1">Command / Path</th>
                  </tr>
                </thead>
                <tbody>
                  {reportsEvents.length === 0 && (
                    <tr><td colSpan={8} className="px-2 py-4 text-center text-slate-500">No events</td></tr>
                  )}
                  {reportsEvents.map((e) => {
                    const expanded = reportsExpandedEventId === e.id
                    let prettyJson = ''
                    try {
                      prettyJson = JSON.stringify(JSON.parse(e.raw_json || '{}'), null, 2)
                    } catch {
                      prettyJson = e.raw_json || '{}'
                    }
                    return (
                      <React.Fragment key={e.id}>
                        <tr className="border-t border-slate-100">
                          <td className="px-2 py-1">
                            <button
                              onClick={() => setReportsExpandedEventId(expanded ? null : e.id)}
                              className="text-slate-500 hover:text-slate-700"
                              title="Expand event"
                            >
                              {expanded ? '▾' : '▸'}
                            </button>
                          </td>
                          <td className="px-2 py-1 font-mono">{e.timestamp}</td>
                          <td className="px-2 py-1">{e.agent_id || 'Unknown'}</td>
                          <td className="px-2 py-1">{e.source || '-'}</td>
                          <td className="px-2 py-1">{e.tool || '-'}</td>
                          <td className="px-2 py-1">{e.policy_decision || '-'}</td>
                          <td className="px-2 py-1 font-mono">{e.matched_rule || '-'}</td>
                          <td className="px-2 py-1 font-mono">{e.command || e.path || '-'}</td>
                        </tr>
                        {expanded && (
                          <tr className="bg-slate-50 border-t border-slate-100">
                            <td colSpan={8} className="px-2 py-2">
                              <pre className="text-xs font-mono whitespace-pre-wrap break-all">{prettyJson}</pre>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    )
  }

  function CommandsPanel() {
    const gridTemplateColumns = `${BASIC_GRID_COLS}${showAdvanced ? '_90px_90px' : ''}`.replaceAll('_', ' ')
    const nonAllTabs = tabDefs.filter((t) => t.id !== 'all')
    return (
      <>
        <div className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm mb-3 space-y-2">
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
        <div className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm mb-3 space-y-2">
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
        <div className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm mb-3 space-y-2">
          <div className="text-xs font-semibold text-slate-600 uppercase tracking-wide">Filters</div>
          <div className="grid grid-cols-1 md:grid-cols-[1fr_1fr] gap-2">
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full border border-slate-300 rounded-lg px-3 py-2 bg-white"
              placeholder="Filter commands by text..."
            />
            <div className="border border-slate-300 rounded-lg px-3 py-2 bg-white">
              <div className="text-xs text-slate-500 mb-1">Categories (multi-select, default: All)</div>
              <div className="flex flex-wrap gap-2">
                {nonAllTabs.map((tab) => (
                  <label key={tab.id} className="text-xs border border-slate-300 rounded px-2 py-1 bg-slate-50 flex items-center gap-1">
                    <input
                      type="checkbox"
                      checked={selectedCategories.includes(tab.label)}
                      onChange={(e) => {
                        if (e.target.checked) setSelectedCategories((prev) => Array.from(new Set([...prev, tab.label])))
                        else setSelectedCategories((prev) => prev.filter((x) => x !== tab.label))
                      }}
                    />
                    <span>{tab.label}</span>
                  </label>
                ))}
              </div>
            </div>
          </div>
        </div>
        <div className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm overflow-auto">
          <div className="grid gap-2 text-xs font-semibold text-slate-500 border-b border-slate-200 pb-2" style={{ gridTemplateColumns }}>
            <div />
            <div className="text-center col-span-2 rounded-md bg-white py-1 text-slate-700 border border-slate-200">Basic</div>
            {showAdvanced ? (
              <div className="col-span-2 rounded-md bg-blue-50 py-1 text-slate-700 border-l-2 border-slate-300 pl-4 pr-2 flex items-center justify-between">
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
              </>
            )}
          </div>
          {showAdvanced && (
            <div className="text-xs text-slate-500 bg-blue-50 border border-blue-100 rounded-md px-2 py-1 mt-2 mb-1">
              Additional simulation and budget settings are configured on the Advanced Policy page.
            </div>
          )}
          {commandRows.map((cmd) => <CommandRow key={cmd} cmd={cmd} />)}
        </div>
      </>
    )
  }

  function PathsPanel() {
    const allPaths = Array.from(new Set([
      ...((draftPolicy?.allowed?.paths_whitelist) || []),
      ...((draftPolicy?.blocked?.paths) || []),
      ...((draftPolicy?.requires_confirmation?.paths) || []),
    ])).sort()

    const visiblePaths = allPaths.filter((p) => showPathAdvanced || pathTierFor(draftPolicy, p) !== 'requires_confirmation')
    const pathGridColumns = `minmax(420px,1fr)_90px_90px${showPathAdvanced ? '_120px' : ''}_90px`.replaceAll('_', ' ')

    const onAddPath = () => {
      const p = normalizeAbsolutePath(newPathValue)
      if (!p) {
        setMessage('Path is required')
        return
      }
      if (!isAbsolutePath(p)) {
        setMessage('Only absolute paths are allowed (must start with /)')
        return
      }
      setDraftPolicy((prev) => setPathTier(prev, p, newPathTier))
      setNewPathValue('')
      setMessage(`Path "${p}" added`)
    }

    const onEditPath = (oldPath) => {
      const next = window.prompt('Edit absolute path', oldPath)
      if (next === null) return
      const normalized = normalizeAbsolutePath(next)
      if (!normalized || !isAbsolutePath(normalized)) {
        setMessage('Only absolute paths are allowed (must start with /)')
        return
      }
      setDraftPolicy((prev) => renamePath(prev, oldPath, normalized))
    }

    return (
      <div className="space-y-3">
        <div className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm space-y-2">
          <div className="text-xs font-semibold text-slate-600 uppercase tracking-wide">Runtime Paths (Read Only)</div>
          <div className="grid grid-cols-1 gap-2">
            {Object.entries(runtimePaths).map(([key, value]) => (
              key === 'AIRG_AGENT_ID' ? null : (
              <div key={key} className="grid grid-cols-1 md:grid-cols-[260px_1fr] gap-2 items-center">
                <div className="text-xs text-slate-600">{RUNTIME_PATH_LABELS[key] || key}</div>
                <input
                  value={String(value || '')}
                  readOnly
                  className="border border-slate-300 rounded-lg px-3 py-2 bg-slate-100 text-slate-700 font-mono text-xs"
                />
              </div>
              )
            ))}
          </div>
          <div className="text-xs text-amber-700 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2">
            Runtime paths are managed by MCP client configuration/env. To change workspace paths, update your AI agent MCP config,
            then restart the MCP server and agent client.
          </div>
        </div>
        <div className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm space-y-2">
          <div className="text-xs font-semibold text-slate-600 uppercase tracking-wide">Add Path</div>
          <div className="grid grid-cols-1 md:grid-cols-[1fr_320px_auto] gap-2 items-center">
            <input
              value={newPathValue}
              onChange={(e) => setNewPathValue(e.target.value)}
              className="border border-slate-300 rounded-lg px-3 py-2 font-mono text-xs"
              placeholder="/absolute/path"
              title="Use absolute paths only. Example: /Users/your_username/Documents/Folder"
            />
            <div className="flex items-center gap-3 text-xs">
              <label className="flex items-center gap-1"><input type="radio" checked={newPathTier === 'allowed'} onChange={() => setNewPathTier('allowed')} /> Allowed</label>
              <label className="flex items-center gap-1"><input type="radio" checked={newPathTier === 'blocked'} onChange={() => setNewPathTier('blocked')} /> Blocked</label>
              {showPathAdvanced && (
                <label className="flex items-center gap-1"><input type="radio" checked={newPathTier === 'requires_confirmation'} onChange={() => setNewPathTier('requires_confirmation')} /> Requires Approval</label>
              )}
            </div>
            <button onClick={onAddPath} className="px-3 py-1.5 rounded-lg bg-brand text-white text-sm">Add path</button>
          </div>
          <div className="text-xs text-slate-500">Example: <span className="font-mono">/Users/your_username/Documents/Folder</span></div>
        </div>
        <div className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm overflow-auto">
          <div className="grid gap-2 text-xs font-semibold text-slate-500 border-b border-slate-200 pb-2" style={{ gridTemplateColumns: pathGridColumns }}>
            <div />
            <div className="text-center col-span-2 rounded-md bg-white py-1 text-slate-700 border border-slate-200">Basic</div>
            {showPathAdvanced ? (
              <div className="col-span-2 rounded-md bg-blue-50 py-1 text-slate-700 border-l-2 border-slate-300 pl-4 pr-2 flex items-center justify-between">
                <span className="font-semibold">Advanced</span>
                <button
                  onClick={() => setShowPathAdvanced(false)}
                  className="text-xs text-slate-500 underline underline-offset-2 hover:text-slate-700"
                >
                  Hide advanced settings
                </button>
              </div>
            ) : (
              <div className="col-span-1 py-1 px-2 flex items-center justify-end">
                <button
                  onClick={() => setShowPathAdvanced(true)}
                  className="text-xs text-slate-500 underline underline-offset-2 hover:text-slate-700"
                >
                  Show advanced settings
                </button>
              </div>
            )}
          </div>
          <div className="grid gap-2 text-xs font-semibold text-slate-500 border-b border-slate-200 pb-2 pt-2" style={{ gridTemplateColumns: pathGridColumns }}>
            <div>Path</div>
            <div className="text-center">Allowed</div>
            <div className="text-center">Blocked</div>
            {showPathAdvanced && <div className="text-center bg-blue-50 border-l-2 border-slate-300 pl-4">Requires Approval</div>}
            <div className="text-center">Actions</div>
          </div>
          {visiblePaths.map((p) => {
            const tier = pathTierFor(draftPolicy, p)
            return (
              <div key={p} className="grid gap-2 items-center border-b border-slate-200 py-2 text-sm" style={{ gridTemplateColumns: pathGridColumns }}>
                <div className="border border-slate-300 rounded px-2 py-1 font-mono text-xs bg-white">{p}</div>
                <label className="flex justify-center"><input type="radio" checked={tier === 'allowed'} onChange={() => setDraftPolicy((prev) => setPathTier(prev, p, 'allowed'))} /></label>
                <label className="flex justify-center"><input type="radio" checked={tier === 'blocked'} onChange={() => setDraftPolicy((prev) => setPathTier(prev, p, 'blocked'))} /></label>
                {showPathAdvanced && (
                  <label className="flex justify-center bg-blue-50 border-l-2 border-slate-300 pl-4">
                    <input type="radio" checked={tier === 'requires_confirmation'} onChange={() => setDraftPolicy((prev) => setPathTier(prev, p, 'requires_confirmation'))} />
                  </label>
                )}
                <div className="flex justify-center gap-2">
                  <button onClick={() => onEditPath(p)} className="px-2 py-1 rounded border border-slate-300 text-slate-700 text-xs">Edit</button>
                  <button onClick={() => setDraftPolicy((prev) => removePath(prev, p))} className="px-2 py-1 rounded border border-red-300 text-red-700 text-xs">Remove</button>
                </div>
              </div>
            )
          })}
        </div>
      </div>
    )
  }

  function ExtensionsPanel() {
    const blockedExt = (draftPolicy?.blocked?.extensions || []).slice().sort()
    const onAdd = () => {
      const val = String(newExtensionValue || '').trim()
      if (!val) {
        setMessage('Extension value is required')
        return
      }
      setDraftPolicy((prev) => {
        const next = deepClone(prev)
        next.blocked = next.blocked || {}
        next.blocked.extensions = Array.from(new Set([...(next.blocked.extensions || []), val])).sort()
        return next
      })
      setNewExtensionValue('')
      setMessage(`Extension "${val}" added to blocked list`)
    }
    return (
      <div className="space-y-3">
        <div className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm space-y-2">
          <div className="text-xs font-semibold text-slate-600 uppercase tracking-wide">Blocked Extensions</div>
          <div className="grid grid-cols-1 md:grid-cols-[1fr_auto] gap-2 items-center">
            <input
              value={newExtensionValue}
              onChange={(e) => setNewExtensionValue(e.target.value)}
              className="border border-slate-300 rounded-lg px-3 py-2 font-mono text-xs"
              placeholder="*.ext"
              title="Enter extension pattern such as *.pem, *.key, *.env"
            />
            <button onClick={onAdd} className="px-3 py-1.5 rounded-lg bg-brand text-white text-sm">Add extension</button>
          </div>
          <div className="text-xs text-slate-500">Example: <span className="font-mono">*.pem</span></div>
        </div>
        <div className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm overflow-auto">
          <div className="grid grid-cols-[minmax(320px,1fr)_100px] gap-2 text-xs font-semibold text-slate-500 border-b border-slate-200 pb-2">
            <div>Extension</div>
            <div className="text-center">Actions</div>
          </div>
          {blockedExt.map((ext) => (
            <div key={ext} className="grid grid-cols-[minmax(320px,1fr)_100px] gap-2 items-center border-b border-slate-200 py-2 text-sm">
              <div className="border border-slate-300 rounded px-2 py-1 font-mono text-xs bg-white">{ext}</div>
              <div className="flex justify-center">
                <button
                  onClick={() => setDraftPolicy((prev) => {
                    const next = deepClone(prev)
                    next.blocked.extensions = (next.blocked?.extensions || []).filter((e) => e !== ext)
                    return next
                  })}
                  className="px-2 py-1 rounded border border-red-300 text-red-700 text-xs"
                >
                  Remove
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    )
  }

  function NetworkPanel() {
    const network = draftPolicy?.network || {}
    const commands = (network.commands || []).slice().sort()
    const allowedDomains = (network.allowed_domains || []).slice().sort()
    const blockedDomains = (network.blocked_domains || []).slice().sort()
    const hasWhitelist = allowedDomains.length > 0
    const hasBlocklist = blockedDomains.length > 0

    const updateNetwork = (patch) => {
      setDraftPolicy((prev) => {
        const next = deepClone(prev)
        next.network = { ...(next.network || {}), ...patch }
        return next
      })
    }

    const addNetworkCommand = () => {
      const cmd = normalizeListToken(newNetworkCommand)
      if (!cmd) {
        setMessage('Network command is required')
        return
      }
      updateNetwork({ commands: Array.from(new Set([...(network.commands || []), cmd])).sort() })
      setNewNetworkCommand('')
      setMessage(`Network command "${cmd}" added`)
    }

    const addDomain = (type) => {
      const raw = type === 'allow' ? newWhitelistDomain : newBlocklistDomain
      const domain = normalizeDomain(raw)
      if (!domain) {
        setMessage('Domain value is required')
        return
      }
      if (type === 'allow') {
        updateNetwork({ allowed_domains: Array.from(new Set([...(network.allowed_domains || []), domain])).sort() })
        setNewWhitelistDomain('')
        setMessage(`Domain "${domain}" added to whitelist`)
      } else {
        updateNetwork({ blocked_domains: Array.from(new Set([...(network.blocked_domains || []), domain])).sort() })
        setNewBlocklistDomain('')
        setMessage(`Domain "${domain}" added to blocklist`)
      }
    }

    return (
      <div className="space-y-3">
        <div className="bg-white border border-red-200 rounded-xl p-3 shadow-sm">
          <div className="text-sm text-red-700">
            Network policy applies to commands listed under <span className="font-mono">network.commands</span>. In <span className="font-mono">off</span> mode no checks are enforced.
            In <span className="font-mono">monitor</span> mode checks are logged but commands are allowed. In <span className="font-mono">enforce</span> mode domain allow/block rules are enforced.
          </div>
        </div>

        <div className="bg-blue-50 border border-blue-200 rounded-xl p-3 shadow-sm">
          <div className="text-xs font-semibold text-blue-900 uppercase tracking-wide mb-1">Runtime Domain Matching Notes</div>
          <div className="text-xs text-blue-900 space-y-1">
            <div>Subdomains are matched: a rule for <span className="font-mono">example.com</span> also applies to <span className="font-mono">api.example.com</span>.</div>
            <div>Policy checks the hostnames found in command arguments/URLs only.</div>
            <div>Redirect chains and short-link expansion are not followed; checks apply to the visible domain in the command.</div>
            <div>Referral/tracking query params do not affect domain matching.</div>
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm space-y-2">
          <div className="text-xs font-semibold text-slate-600 uppercase tracking-wide">Enforcement Mode</div>
          <div className="flex flex-wrap gap-3 text-sm">
            {['off', 'monitor', 'enforce'].map((mode) => (
              <label key={mode} className="flex items-center gap-2 border border-slate-300 rounded px-3 py-1.5 bg-slate-50">
                <input
                  type="radio"
                  checked={(network.enforcement_mode || 'off') === mode}
                  onChange={() => updateNetwork({ enforcement_mode: mode })}
                />
                <span className="font-mono">{mode}</span>
              </label>
            ))}
          </div>
          {(network.enforcement_mode || 'off') === 'enforce' && (
            <label className="mt-1 inline-flex items-center gap-2 text-xs text-slate-700">
              <input
                type="checkbox"
                checked={Boolean(network.block_unknown_domains)}
                onChange={(e) => updateNetwork({ block_unknown_domains: e.target.checked })}
              />
              Block domains not present in whitelist or blocklist
            </label>
          )}
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm space-y-2">
          <div className="text-xs font-semibold text-slate-600 uppercase tracking-wide">Network Commands</div>
          <div className="text-xs text-slate-500">These commands are used to trigger network policy evaluation. Listing a command here does not block it by itself.</div>
          <div className="grid grid-cols-1 md:grid-cols-[1fr_auto] gap-2 items-center">
            <input
              value={newNetworkCommand}
              onChange={(e) => setNewNetworkCommand(e.target.value)}
              className="border border-slate-300 rounded-lg px-3 py-2 font-mono text-xs"
              placeholder="curl"
            />
            <button onClick={addNetworkCommand} className="px-3 py-1.5 rounded-lg bg-brand text-white text-sm">Add command</button>
          </div>
          <div className="bg-slate-50 border border-slate-200 rounded-lg p-2">
            <div className="flex flex-wrap gap-2">
              {commands.map((cmd) => (
                <span key={cmd} className="inline-flex items-center gap-1 px-2 py-1 rounded border border-slate-300 bg-white text-xs font-mono">
                  {cmd}
                  <button
                    className="text-red-600"
                    onClick={() => updateNetwork({ commands: (network.commands || []).filter((c) => c !== cmd) })}
                    title="Remove"
                  >
                    ×
                  </button>
                </span>
              ))}
              {!commands.length && <span className="text-xs text-slate-400">No network commands configured</span>}
            </div>
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm">
          <div className="text-xs font-semibold text-slate-600 uppercase tracking-wide mb-2">Domain Rules</div>
          <div className="text-xs text-slate-600 mb-3">
            {(network.enforcement_mode || 'off') !== 'enforce' && 'Network policy is not blocking in current mode; switch to enforce for hard blocking.'}
            {(network.enforcement_mode || 'off') === 'enforce' && hasWhitelist && !hasBlocklist && !network.block_unknown_domains && 'Whitelist is advisory only: listed domains are explicitly allowed, and other domains are also allowed unless blocked.'}
            {(network.enforcement_mode || 'off') === 'enforce' && !hasWhitelist && hasBlocklist && 'Blocklist is active: listed domains are denied; all others are allowed.'}
            {(network.enforcement_mode || 'off') === 'enforce' && hasWhitelist && hasBlocklist && !network.block_unknown_domains && 'Blocklist takes precedence on overlap. Whitelisted domains are allowed unless also blocked. Domains in neither list are allowed.'}
            {(network.enforcement_mode || 'off') === 'enforce' && network.block_unknown_domains && 'Default-deny is active: domains in blocklist are denied, and domains not present in whitelist are denied.'}
            {(network.enforcement_mode || 'off') === 'enforce' && !hasWhitelist && !hasBlocklist && !network.block_unknown_domains && 'No domain rules configured: domains are unrestricted unless enforcement is handled elsewhere.'}
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="border-r-0 lg:border-r lg:pr-4 border-slate-200 space-y-2">
              <div className="text-sm font-semibold text-slate-700">Domain Whitelist</div>
              <div className="grid grid-cols-[1fr_auto] gap-2">
                <input
                  value={newWhitelistDomain}
                  onChange={(e) => setNewWhitelistDomain(e.target.value)}
                  className="border border-slate-300 rounded-lg px-3 py-2 text-xs font-mono"
                  placeholder="api.github.com"
                />
                <button onClick={() => addDomain('allow')} className="px-3 py-1.5 rounded-lg bg-brand text-white text-sm">Add</button>
              </div>
              <div className="bg-slate-50 border border-slate-200 rounded-lg p-2 flex flex-wrap gap-2 min-h-[52px]">
                {allowedDomains.map((d) => (
                  <span key={d} className="inline-flex items-center gap-1 px-2 py-1 rounded border border-green-300 bg-green-50 text-xs font-mono">
                    {d}
                    <button className="text-red-600" onClick={() => updateNetwork({ allowed_domains: (network.allowed_domains || []).filter((x) => x !== d) })}>×</button>
                  </span>
                ))}
                {!allowedDomains.length && <span className="text-xs text-slate-400">No whitelisted domains</span>}
              </div>
            </div>
            <div className="space-y-2">
              <div className="text-sm font-semibold text-slate-700">Domain Blocklist</div>
              <div className="grid grid-cols-[1fr_auto] gap-2">
                <input
                  value={newBlocklistDomain}
                  onChange={(e) => setNewBlocklistDomain(e.target.value)}
                  className="border border-slate-300 rounded-lg px-3 py-2 text-xs font-mono"
                  placeholder="malicious.example"
                />
                <button onClick={() => addDomain('block')} className="px-3 py-1.5 rounded-lg border border-red-300 text-red-700 text-sm bg-white">Add</button>
              </div>
              <div className="bg-slate-50 border border-slate-200 rounded-lg p-2 flex flex-wrap gap-2 min-h-[52px]">
                {blockedDomains.map((d) => (
                  <span key={d} className="inline-flex items-center gap-1 px-2 py-1 rounded border border-red-300 bg-red-50 text-xs font-mono">
                    {d}
                    <button className="text-red-600" onClick={() => updateNetwork({ blocked_domains: (network.blocked_domains || []).filter((x) => x !== d) })}>×</button>
                  </span>
                ))}
                {!blockedDomains.length && <span className="text-xs text-slate-400">No blocked domains</span>}
              </div>
            </div>
          </div>
        </div>
      </div>
    )
  }

  function AdvancedPolicyPanel() {
    const simulation = draftPolicy?.requires_simulation || {}
    const cumulative = simulation?.cumulative_budget || {}
    const limits = cumulative?.limits || {}
    const counting = cumulative?.counting || {}
    const reset = cumulative?.reset || {}
    const confirmation = draftPolicy?.requires_confirmation || {}
    const approvalSecurity = confirmation?.approval_security || {}
    const execution = draftPolicy?.execution || {}
    const shellContainment = execution?.shell_workspace_containment || {}
    const allowed = draftPolicy?.allowed || {}
    const backupAccess = draftPolicy?.backup_access || {}
    const restore = draftPolicy?.restore || {}
    const audit = draftPolicy?.audit || {}
    const reportsCfg = draftPolicy?.reports || {}
    const bytesMultiplier = {
      KB: 1024,
      MB: 1024 * 1024,
      GB: 1024 * 1024 * 1024,
    }

    const setSimulation = (patch) => {
      setDraftPolicy((prev) => {
        const next = deepClone(prev)
        next.requires_simulation = { ...(next.requires_simulation || {}), ...patch }
        return next
      })
    }

    const setConfirmationSecurity = (patch) => {
      setDraftPolicy((prev) => {
        const next = deepClone(prev)
        next.requires_confirmation = { ...(next.requires_confirmation || {}) }
        next.requires_confirmation.approval_security = {
          ...(next.requires_confirmation.approval_security || {}),
          ...patch,
        }
        return next
      })
    }

    const setExecution = (patch) => {
      setDraftPolicy((prev) => {
        const next = deepClone(prev)
        next.execution = { ...(next.execution || {}), ...patch }
        return next
      })
    }

    const setShellContainment = (patch) => {
      setDraftPolicy((prev) => {
        const next = deepClone(prev)
        next.execution = { ...(next.execution || {}) }
        next.execution.shell_workspace_containment = {
          ...(next.execution.shell_workspace_containment || {}),
          ...patch,
        }
        return next
      })
    }

    const setAllowed = (patch) => {
      setDraftPolicy((prev) => {
        const next = deepClone(prev)
        next.allowed = { ...(next.allowed || {}), ...patch }
        return next
      })
    }

    const setBackupAccess = (patch) => {
      setDraftPolicy((prev) => {
        const next = deepClone(prev)
        next.backup_access = { ...(next.backup_access || {}), ...patch }
        return next
      })
    }

    const setRestore = (patch) => {
      setDraftPolicy((prev) => {
        const next = deepClone(prev)
        next.restore = { ...(next.restore || {}), ...patch }
        return next
      })
    }

    const setAudit = (patch) => {
      setDraftPolicy((prev) => {
        const next = deepClone(prev)
        next.audit = { ...(next.audit || {}), ...patch }
        return next
      })
    }

    const setReportsConfig = (patch) => {
      setDraftPolicy((prev) => {
        const next = deepClone(prev)
        next.reports = { ...(next.reports || {}), ...patch }
        return next
      })
    }

    const setCumulative = (patch) => {
      setDraftPolicy((prev) => {
        const next = deepClone(prev)
        const rs = { ...(next.requires_simulation || {}) }
        rs.cumulative_budget = { ...(rs.cumulative_budget || {}), ...patch }
        next.requires_simulation = rs
        return next
      })
    }

    const setLimits = (key, value) => {
      const parsed = value === '' ? undefined : Math.max(0, parseInt(value, 10) || 0)
      const nextLimits = { ...(limits || {}) }
      if (parsed === undefined) delete nextLimits[key]
      else nextLimits[key] = parsed
      setCumulative({ limits: nextLimits })
    }

    const bytesRaw = Number(limits.max_total_bytes_estimate || 0)
    const bytesDisplay = bytesRaw
      ? String(Math.round((bytesRaw / bytesMultiplier[budgetBytesUnit]) * 100) / 100)
      : ''

    const onBytesDisplayChange = (value) => {
      const normalized = String(value || '').trim()
      const nextLimits = { ...(limits || {}) }
      if (!normalized) {
        delete nextLimits.max_total_bytes_estimate
      } else {
        const parsed = Number(normalized)
        if (!Number.isFinite(parsed) || parsed < 0) return
        nextLimits.max_total_bytes_estimate = Math.round(parsed * bytesMultiplier[budgetBytesUnit])
      }
      setCumulative({ limits: nextLimits })
    }

    const setCounting = (patch) => {
      setCumulative({ counting: { ...(counting || {}), ...patch } })
    }
    const setReset = (patch) => {
      setCumulative({ reset: { ...(reset || {}), ...patch } })
    }

    const commandsIncluded = Array.isArray(counting.commands_included) ? counting.commands_included.join(', ') : ''
    const allowedToolsText = Array.isArray(backupAccess.allowed_tools) ? backupAccess.allowed_tools.join(', ') : ''
    const redactPatternsText = Array.isArray(audit.redact_patterns) ? audit.redact_patterns.join('\n') : ''

    return (
      <div className="space-y-3">
        <div className="bg-blue-50 border border-blue-200 rounded-xl p-3 text-xs text-blue-800">
          These settings are global/session-level controls for simulation and cumulative budget, not per-command controls.
          Check the manual for exact enforcement semantics and examples.
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm space-y-3">
          <div className="text-xs font-semibold text-slate-600 uppercase tracking-wide">Cumulative Budget</div>
          <div className="flex items-center gap-3 text-sm">
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={Boolean(cumulative.enabled)}
                onChange={(e) => setCumulative({ enabled: e.target.checked })}
              />
              Enabled
            </label>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <label className="text-xs text-slate-600">
              Max total operations
              <input
                type="number"
                min={0}
                className="mt-1 w-full border border-slate-300 rounded-lg px-3 py-2 text-sm"
                value={limits.max_total_operations ?? ''}
                onChange={(e) => setLimits('max_total_operations', e.target.value)}
              />
            </label>
            <label className="text-xs text-slate-600">
              Max unique paths
              <input
                type="number"
                min={0}
                className="mt-1 w-full border border-slate-300 rounded-lg px-3 py-2 text-sm"
                value={limits.max_unique_paths ?? ''}
                onChange={(e) => setLimits('max_unique_paths', e.target.value)}
              />
            </label>
            <label className="text-xs text-slate-600">
              Max total bytes estimate
              <div className="mt-1 grid grid-cols-[1fr_auto] gap-2">
                <input
                  type="number"
                  min={0}
                  step="0.01"
                  className="w-full border border-slate-300 rounded-lg px-3 py-2 text-sm"
                  value={bytesDisplay}
                  onChange={(e) => onBytesDisplayChange(e.target.value)}
                />
                <select
                  className="border border-slate-300 rounded-lg px-2 py-2 text-sm"
                  value={budgetBytesUnit}
                  onChange={(e) => setBudgetBytesUnit(e.target.value)}
                >
                  <option value="KB">KB</option>
                  <option value="MB">MB</option>
                  <option value="GB">GB</option>
                </select>
              </div>
              <div className="mt-1 text-[11px] text-slate-500">
                Stored in policy as raw bytes (auto-converted from selected unit).
              </div>
            </label>
          </div>

          <div className="grid grid-cols-1 gap-3">
            <label className="text-xs text-slate-600">
              Commands included (comma-separated)
              <input
                type="text"
                className="mt-1 w-full border border-slate-300 rounded-lg px-3 py-2 text-sm font-mono"
                value={commandsIncluded}
                onChange={(e) => {
                  const values = e.target.value
                    .split(',')
                    .map((v) => normalizeListToken(v))
                    .filter(Boolean)
                  setCounting({ commands_included: values })
                }}
              />
            </label>
          </div>

          <div className="flex flex-wrap gap-4 text-sm">
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={Boolean(counting.dedupe_paths)}
                onChange={(e) => setCounting({ dedupe_paths: e.target.checked })}
              />
              Dedupe paths
            </label>
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={Boolean(counting.include_noop_attempts)}
                onChange={(e) => setCounting({ include_noop_attempts: e.target.checked })}
              />
              Include noop attempts
            </label>
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm space-y-3">
          <div className="text-xs font-semibold text-slate-600 uppercase tracking-wide">Cumulative Budget Reset</div>
          <div className="text-[11px] text-slate-500">
            Operations older than the configured window are removed from budget calculation.
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <label className="text-xs text-slate-600">
              Sliding window (seconds)
              <input
                type="number"
                min={0}
                className="mt-1 w-full border border-slate-300 rounded-lg px-3 py-2 text-sm"
                value={reset.window_seconds ?? 3600}
                onChange={(e) => setReset({ window_seconds: Math.max(0, parseInt(e.target.value, 10) || 0) })}
              />
            </label>
            <label className="text-xs text-slate-600">
              Idle reset (seconds)
              <input
                type="number"
                min={0}
                className="mt-1 w-full border border-slate-300 rounded-lg px-3 py-2 text-sm"
                value={reset.idle_reset_seconds ?? 900}
                onChange={(e) => setReset({ idle_reset_seconds: Math.max(0, parseInt(e.target.value, 10) || 0) })}
              />
            </label>
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm space-y-3">
          <div className="text-xs font-semibold text-slate-600 uppercase tracking-wide">Command Simulation Controls</div>
          <div className="text-[11px] text-slate-500">
            Configures retry and blast-radius thresholds for commands under simulation policy.
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <label className="text-xs text-slate-600">
              Max retries
              <input
                type="number"
                min={0}
                className="mt-1 w-full border border-slate-300 rounded-lg px-3 py-2 text-sm"
                value={simulation.max_retries ?? 0}
                onChange={(e) => setSimulation({ max_retries: Math.max(0, parseInt(e.target.value, 10) || 0) })}
              />
            </label>
            <label className="text-xs text-slate-600">
              Bulk file threshold
              <input
                type="number"
                min={0}
                className="mt-1 w-full border border-slate-300 rounded-lg px-3 py-2 text-sm"
                value={simulation.bulk_file_threshold ?? 0}
                onChange={(e) => setSimulation({ bulk_file_threshold: Math.max(0, parseInt(e.target.value, 10) || 0) })}
              />
            </label>
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm space-y-3">
          <div className="text-xs font-semibold text-slate-600 uppercase tracking-wide">Backup & Restore</div>
          <div className="flex flex-wrap gap-4 text-sm">
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={Boolean(backupAccess.block_agent_tools)}
                onChange={(e) => setBackupAccess({ block_agent_tools: e.target.checked })}
              />
              Protect backup storage from agent tools
            </label>
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={Boolean(restore.require_dry_run_before_apply)}
                onChange={(e) => setRestore({ require_dry_run_before_apply: e.target.checked })}
              />
              Require dry run before restore apply
            </label>
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={Boolean(audit.backup_enabled)}
                onChange={(e) => setAudit({ backup_enabled: e.target.checked })}
              />
              Backup enabled
            </label>
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={Boolean(audit.backup_on_content_change_only)}
                onChange={(e) => setAudit({ backup_on_content_change_only: e.target.checked })}
              />
              Backup on content change only
            </label>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <label className="text-xs text-slate-600">
              Backup allowed tools (comma-separated)
              <input
                type="text"
                className="mt-1 w-full border border-slate-300 rounded-lg px-3 py-2 text-sm font-mono"
                value={allowedToolsText}
                onChange={(e) => {
                  const values = e.target.value
                    .split(',')
                    .map((v) => normalizeListToken(v))
                    .filter(Boolean)
                  setBackupAccess({ allowed_tools: values })
                }}
              />
            </label>
            <label className="text-xs text-slate-600">
              Restore confirmation TTL (seconds)
              <input
                type="number"
                min={30}
                className="mt-1 w-full border border-slate-300 rounded-lg px-3 py-2 text-sm"
                value={restore.confirmation_ttl_seconds ?? 300}
                onChange={(e) => setRestore({ confirmation_ttl_seconds: Math.max(30, parseInt(e.target.value, 10) || 30) })}
              />
            </label>
            <label className="text-xs text-slate-600">
              Backup root
              <input
                type="text"
                className="mt-1 w-full border border-slate-300 rounded-lg px-3 py-2 text-sm font-mono"
                value={audit.backup_root ?? ''}
                onChange={(e) => setAudit({ backup_root: e.target.value })}
              />
            </label>
            <label className="text-xs text-slate-600">
              Max versions per file
              <input
                type="number"
                min={1}
                className="mt-1 w-full border border-slate-300 rounded-lg px-3 py-2 text-sm"
                value={audit.max_versions_per_file ?? 5}
                onChange={(e) => setAudit({ max_versions_per_file: Math.max(1, parseInt(e.target.value, 10) || 1) })}
              />
            </label>
            <label className="text-xs text-slate-600">
              Backup retention days
              <input
                type="number"
                min={0}
                className="mt-1 w-full border border-slate-300 rounded-lg px-3 py-2 text-sm"
                value={audit.backup_retention_days ?? 30}
                onChange={(e) => setAudit({ backup_retention_days: Math.max(0, parseInt(e.target.value, 10) || 0) })}
              />
            </label>
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm space-y-3">
          <div className="text-xs font-semibold text-slate-600 uppercase tracking-wide">Command Execution Limits</div>
          <div className="text-[11px] text-slate-500">
            Sets safety limits for command runtime duration and output size.
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <label className="text-xs text-slate-600">
              Max command timeout (seconds)
              <input
                type="number"
                min={1}
                className="mt-1 w-full border border-slate-300 rounded-lg px-3 py-2 text-sm"
                value={execution.max_command_timeout_seconds ?? 30}
                onChange={(e) => setExecution({ max_command_timeout_seconds: Math.max(1, parseInt(e.target.value, 10) || 1) })}
              />
            </label>
            <label className="text-xs text-slate-600">
              Max output chars
              <input
                type="number"
                min={1024}
                className="mt-1 w-full border border-slate-300 rounded-lg px-3 py-2 text-sm"
                value={execution.max_output_chars ?? 200000}
                onChange={(e) => setExecution({ max_output_chars: Math.max(1024, parseInt(e.target.value, 10) || 1024) })}
              />
            </label>
          </div>
          <div className="border-t border-slate-200 pt-3 space-y-2">
            <div className="text-xs font-semibold text-slate-600">Attempt workspace shell command containment</div>
            <div className="text-[11px] text-slate-500">
              Best-effort path containment for `execute_command`. In monitor mode, commands are allowed and logged; in enforce mode, commands referencing outside paths are blocked.
            </div>
            <div className="flex flex-wrap gap-3 text-sm">
              {['off', 'monitor', 'enforce'].map((mode) => (
                <label key={mode} className="flex items-center gap-2 capitalize">
                  <input
                    type="radio"
                    name="shell-containment-mode"
                    checked={(shellContainment.mode || 'off') === mode}
                    onChange={() => setShellContainment({ mode })}
                  />
                  {mode}
                </label>
              ))}
            </div>
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm space-y-3">
          <div className="text-xs font-semibold text-slate-600 uppercase tracking-wide">Whitelisted Commands Limits</div>
          <div className="text-[11px] text-amber-800 bg-amber-50 border border-amber-200 rounded-lg p-2">
            Applies to commands not explicitly configured as blocked, simulation-gated, or approval-gated.
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <label className="text-xs text-slate-600">
              Max file size (MB)
              <input
                type="number"
                min={0}
                className="mt-1 w-full border border-slate-300 rounded-lg px-3 py-2 text-sm"
                value={allowed.max_file_size_mb ?? 10}
                onChange={(e) => setAllowed({ max_file_size_mb: Math.max(0, parseInt(e.target.value, 10) || 0) })}
              />
            </label>
            <label className="text-xs text-slate-600">
              Max files per operation
              <input
                type="number"
                min={0}
                className="mt-1 w-full border border-slate-300 rounded-lg px-3 py-2 text-sm"
                value={allowed.max_files_per_operation ?? 10}
                onChange={(e) => setAllowed({ max_files_per_operation: Math.max(0, parseInt(e.target.value, 10) || 0) })}
              />
            </label>
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm space-y-3">
          <div className="text-xs font-semibold text-slate-600 uppercase tracking-wide">Command Approval Security Settings</div>
          <div className="text-[11px] text-slate-500">
            Controls token security and failed-approval throttling for commands requiring human approval.
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <label className="text-xs text-slate-600">
              Max failed attempts per token
              <input
                type="number"
                min={0}
                className="mt-1 w-full border border-slate-300 rounded-lg px-3 py-2 text-sm"
                value={approvalSecurity.max_failed_attempts_per_token ?? 5}
                onChange={(e) => setConfirmationSecurity({ max_failed_attempts_per_token: Math.max(0, parseInt(e.target.value, 10) || 0) })}
              />
            </label>
            <label className="text-xs text-slate-600">
              Failed-attempt window (seconds)
              <input
                type="number"
                min={0}
                className="mt-1 w-full border border-slate-300 rounded-lg px-3 py-2 text-sm"
                value={approvalSecurity.failed_attempt_window_seconds ?? 600}
                onChange={(e) => setConfirmationSecurity({ failed_attempt_window_seconds: Math.max(0, parseInt(e.target.value, 10) || 0) })}
              />
            </label>
            <label className="text-xs text-slate-600">
              Approval token TTL (seconds)
              <input
                type="number"
                min={0}
                className="mt-1 w-full border border-slate-300 rounded-lg px-3 py-2 text-sm"
                value={approvalSecurity.token_ttl_seconds ?? 600}
                onChange={(e) => setConfirmationSecurity({ token_ttl_seconds: Math.max(0, parseInt(e.target.value, 10) || 0) })}
              />
            </label>
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm space-y-3">
          <div className="text-xs font-semibold text-slate-600 uppercase tracking-wide">Reports Settings</div>
          <div className="text-[11px] text-slate-500">
            Controls reports ingestion cadence and retention for reports.db.
          </div>
          <div className="flex items-center gap-3 text-sm">
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={Boolean(reportsCfg.enabled)}
                onChange={(e) => setReportsConfig({ enabled: e.target.checked })}
              />
              Reports enabled
            </label>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <label className="text-xs text-slate-600">
              Ingest poll interval (seconds)
              <input
                type="number"
                min={1}
                className="mt-1 w-full border border-slate-300 rounded-lg px-3 py-2 text-sm"
                value={reportsCfg.ingest_poll_interval_seconds ?? 5}
                onChange={(e) => setReportsConfig({ ingest_poll_interval_seconds: Math.max(1, parseInt(e.target.value, 10) || 1) })}
              />
            </label>
            <label className="text-xs text-slate-600">
              Reconcile interval (seconds)
              <input
                type="number"
                min={60}
                className="mt-1 w-full border border-slate-300 rounded-lg px-3 py-2 text-sm"
                value={reportsCfg.reconcile_interval_seconds ?? 3600}
                onChange={(e) => setReportsConfig({ reconcile_interval_seconds: Math.max(60, parseInt(e.target.value, 10) || 60) })}
              />
            </label>
            <label className="text-xs text-slate-600">
              Prune interval (seconds)
              <input
                type="number"
                min={300}
                className="mt-1 w-full border border-slate-300 rounded-lg px-3 py-2 text-sm"
                value={reportsCfg.prune_interval_seconds ?? 86400}
                onChange={(e) => setReportsConfig({ prune_interval_seconds: Math.max(300, parseInt(e.target.value, 10) || 300) })}
              />
            </label>
            <label className="text-xs text-slate-600">
              Retention days
              <input
                type="number"
                min={1}
                className="mt-1 w-full border border-slate-300 rounded-lg px-3 py-2 text-sm"
                value={reportsCfg.retention_days ?? 30}
                onChange={(e) => setReportsConfig({ retention_days: Math.max(1, parseInt(e.target.value, 10) || 1) })}
              />
            </label>
            <label className="text-xs text-slate-600">
              Max reports DB size (MB)
              <input
                type="number"
                min={10}
                className="mt-1 w-full border border-slate-300 rounded-lg px-3 py-2 text-sm"
                value={reportsCfg.max_db_size_mb ?? 200}
                onChange={(e) => setReportsConfig({ max_db_size_mb: Math.max(10, parseInt(e.target.value, 10) || 10) })}
              />
            </label>
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm space-y-3">
          <div className="text-xs font-semibold text-slate-600 uppercase tracking-wide">Log Redaction</div>
          <label className="text-xs text-slate-600 block">
            Redact patterns (one regex per line)
            <textarea
              className="mt-1 w-full border border-slate-300 rounded-lg px-3 py-2 text-xs font-mono h-28"
              value={redactPatternsText}
              onChange={(e) => {
                const values = e.target.value
                  .split('\n')
                  .map((v) => v.trim())
                  .filter(Boolean)
                setAudit({ redact_patterns: values })
              }}
            />
          </label>
        </div>
      </div>
    )
  }

  function PolicyPanel() {
    return (
      <>
        <div className="bg-white border border-slate-200 rounded-xl p-3 shadow-sm mb-3 flex flex-wrap items-center justify-end gap-2">
          <button onClick={onReload} className="px-4 py-2 rounded-lg border border-slate-300 bg-white text-slate-700">Reload</button>
          <button onClick={onValidate} className="px-4 py-2 rounded-lg bg-blue-600 text-white">Validate</button>
          <button onClick={onApply} className="px-4 py-2 rounded-lg bg-brand text-white">Apply</button>
          <button
            onClick={onRevertLastApply}
            disabled={!hasRevertSnapshot}
            className="px-4 py-2 rounded-lg border border-amber-300 bg-amber-50 text-amber-800 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Revert Last Apply
          </button>
          <button
            onClick={onResetDefaults}
            disabled={!hasDefaultSnapshot}
            className="px-4 py-2 rounded-lg border border-red-300 bg-red-50 text-red-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Reset to Defaults
          </button>
        </div>
        {activePolicyTab === 'commands' && CommandsPanel()}
        {activePolicyTab === 'paths' && PathsPanel()}
        {activePolicyTab === 'extensions' && ExtensionsPanel()}
        {activePolicyTab === 'network' && NetworkPanel()}
        {activePolicyTab === 'advanced' && AdvancedPolicyPanel()}
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
        </div>
      </>
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
          <div className="flex items-center gap-2">
            {unsaved && <span className="text-xs text-amber-700 font-medium flex items-center gap-1 ml-2"><span className="w-2 h-2 rounded-full bg-amber-500" /> Unsaved changes</span>}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-[96px_170px_1fr] gap-0 min-h-[calc(100vh-84px)]">
        <nav className="border-r border-slate-200 p-2 bg-white">
          <div className="space-y-2">
            {renderRailItem(RAIL_ITEMS[0])}
          </div>
          <div className="my-3 border-t border-slate-200" />
          <div className="space-y-2">
            {RAIL_ITEMS.slice(1).map(renderRailItem)}
          </div>
        </nav>

        {activeRail === 'policy' ? (
          <aside className="border-r border-slate-200 bg-white p-3 space-y-2">
            {POLICY_TABS.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActivePolicyTab(tab.id)}
                className={`w-full text-left px-3 py-2 rounded-lg text-sm transition ${activePolicyTab === tab.id ? 'bg-brand text-white' : 'text-slate-700 hover:bg-slate-100'}`}
              >
                {tab.label}
              </button>
            ))}
          </aside>
        ) : activeRail === 'reports' ? (
          <aside className="border-r border-slate-200 bg-white p-3 space-y-2">
            {REPORT_TABS.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setReportsTab(tab.id)}
                className={`w-full text-left px-3 py-2 rounded-lg text-sm transition ${reportsTab === tab.id ? 'bg-brand text-white' : 'text-slate-700 hover:bg-slate-100'}`}
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
          {loaded && activeRail === 'policy' && PolicyPanel()}
          {loaded && activeRail === 'reports' && ReportsPanel()}
          {loaded && activeRail === 'settings' && (
            <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm text-slate-500">Coming soon</div>
          )}
        </main>
      </div>
      {CommandInfoModal()}
    </div>
  )
}
