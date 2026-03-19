import React, { useEffect, useMemo, useRef, useState } from 'react'
import runtimeGuardLogo64 from './assets/logo_v4_64px.png'
import runtimeGuardLogo128 from './assets/logo_v4_128px.png'

const API_BASE = 'http://127.0.0.1:5001'
const RAIL_ITEMS = [
  { id: 'approvals', label: 'Approvals' },
  { id: 'policy', label: 'Policy' },
  { id: 'reports', label: 'Reports' },
  { id: 'settings', label: 'Settings' }
]
const POLICY_TABS = [
  { id: 'commands', label: 'Commands' },
  { id: 'paths', label: 'Paths' },
  { id: 'extensions', label: 'Extensions' },
  { id: 'network', label: 'Network' },
  { id: 'agent_overrides', label: 'Agent Overrides' },
  { id: 'advanced', label: 'Advanced Policy' },
]
const REPORT_TABS = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'log', label: 'Log' },
]
const SETTINGS_TABS = [
  { id: 'agents', label: 'Agents' },
  { id: 'advanced', label: 'Advanced' },
]
const NAV_CHILDREN = {
  approvals: [
    { id: 'pending', label: 'Pending' },
    { id: 'history', label: 'History' },
  ],
  policy: POLICY_TABS.map((tab) => ({ id: tab.id, label: tab.label })),
  reports: REPORT_TABS.map((tab) => ({ id: tab.id, label: tab.label })),
  settings: SETTINGS_TABS.map((tab) => ({ id: tab.id, label: tab.label })),
}
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
  { key: 'agent_session_id', label: 'Agent Session' },
  { key: 'source', label: 'Source' },
  { key: 'tool', label: 'Tool' },
  { key: 'decision_tier', label: 'Decision Tier' },
  { key: 'matched_rule', label: 'Matched Rule' },
  { key: 'command', label: 'Command' },
  { key: 'path', label: 'Path' },
]

const STATUS_STYLE = {
  allowed: 'badge badge-allowed',
  requires_simulation: 'badge badge-info',
  requires_confirmation: 'badge badge-pending',
  blocked: 'badge badge-blocked'
}

const STATUS_LABEL = {
  allowed: 'Allowed',
  requires_simulation: 'Simulation',
  requires_confirmation: 'Requires Approval',
  blocked: 'Blocked'
}

const AGENT_OVERRIDE_SECTIONS = [
  'blocked',
  'requires_confirmation',
  'requires_simulation',
  'allowed',
  'network',
  'execution',
]
const AGENT_OVERRIDE_SECTION_LABELS = {
  blocked: 'Blocked',
  requires_confirmation: 'Require Confirmation',
  requires_simulation: 'Require Simulation',
  allowed: 'Allowed',
  network: 'Network',
  execution: 'Execution',
}

function deepClone(v) {
  return JSON.parse(JSON.stringify(v))
}

function isPlainObject(v) {
  return !!v && typeof v === 'object' && !Array.isArray(v)
}

function deepMerge(base, overlay) {
  if (!isPlainObject(base)) return deepClone(overlay)
  if (!isPlainObject(overlay)) return deepClone(overlay)
  const out = deepClone(base)
  for (const [k, v] of Object.entries(overlay)) {
    if (isPlainObject(v) && isPlainObject(out[k])) out[k] = deepMerge(out[k], v)
    else out[k] = deepClone(v)
  }
  return out
}

function deepDiff(base, value) {
  if (Array.isArray(value) || Array.isArray(base)) {
    return JSON.stringify(base) === JSON.stringify(value) ? undefined : deepClone(value)
  }
  if (isPlainObject(value) && isPlainObject(base)) {
    const out = {}
    for (const key of Object.keys(value)) {
      const diff = deepDiff(base[key], value[key])
      if (diff !== undefined) out[key] = diff
    }
    return Object.keys(out).length ? out : undefined
  }
  return JSON.stringify(base) === JSON.stringify(value) ? undefined : deepClone(value)
}

function formatHuman(value, indent = 0) {
  const pad = '  '.repeat(indent)
  if (Array.isArray(value)) {
    if (!value.length) return `${pad}(empty list)`
    return value.map((item) => `${pad}- ${typeof item === 'object' ? '\n' + formatHuman(item, indent + 1) : String(item)}`).join('\n')
  }
  if (isPlainObject(value)) {
    const keys = Object.keys(value)
    if (!keys.length) return `${pad}(empty object)`
    return keys.map((k) => {
      const v = value[k]
      if (isPlainObject(v) || Array.isArray(v)) return `${pad}${k}:\n${formatHuman(v, indent + 1)}`
      return `${pad}${k}: ${String(v)}`
    }).join('\n')
  }
  return `${pad}${String(value)}`
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

function NavIcon({ id }) {
  if (id === 'approvals') {
    return (
      <svg className="w-4 h-4 text-slate-300" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4">
        <rect x="2" y="3" width="12" height="10" rx="2" />
        <path d="M5 8l2 2 4-4" />
      </svg>
    )
  }
  if (id === 'policy') {
    return (
      <svg className="w-4 h-4 text-slate-300" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4">
        <path d="M8 2l5 2v4c0 3.1-2.6 5-5 6-2.4-1-5-2.9-5-6V4l5-2z" />
      </svg>
    )
  }
  if (id === 'reports') {
    return (
      <svg className="w-4 h-4 text-slate-300" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4">
        <rect x="2" y="9" width="2.5" height="5" />
        <rect x="6.75" y="6" width="2.5" height="8" />
        <rect x="11.5" y="3" width="2.5" height="11" />
      </svg>
    )
  }
  return (
    <svg className="w-4 h-4 text-slate-300" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4">
      <circle cx="8" cy="8" r="2" />
      <path d="M8 2.2v1.6M8 12.2v1.6M2.2 8h1.6M12.2 8h1.6M3.8 3.8l1.1 1.1M11.1 11.1l1.1 1.1M3.8 12.2l1.1-1.1M11.1 4.9l1.1-1.1" />
    </svg>
  )
}

function UiIcon({ kind, className = 'w-4 h-4 text-slate-700' }) {
  if (kind === 'save') return <svg className={className} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4"><path d="M3 2h8l2 2v10H3z" /><path d="M5 2v4h6V2" /><path d="M5 10h6" /></svg>
  if (kind === 'folder') return <svg className={className} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4"><path d="M2 5h4l1 1h7v7H2z" /><path d="M2 5V3h4l1 1" /></svg>
  if (kind === 'copy') return <svg className={className} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4"><rect x="5" y="5" width="8" height="9" /><rect x="3" y="2" width="8" height="9" /></svg>
  if (kind === 'terminal') return <svg className={className} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4"><rect x="2" y="3" width="12" height="10" rx="1" /><path d="M5 7l2 1.5L5 10" /><path d="M8.5 10h2.5" /></svg>
  if (kind === 'info') return <svg className={className} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4"><circle cx="8" cy="8" r="6" /><path d="M8 7v4" /><circle cx="8" cy="5" r="0.7" fill="currentColor" stroke="none" /></svg>
  if (kind === 'trash') return <svg className={className} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4"><path d="M3 4h10" /><path d="M6 4V2h4v2" /><path d="M5 4l.5 9h5L11 4" /></svg>
  return <svg className={className} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4"><rect x="3" y="3" width="10" height="10" /></svg>
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

function ensureScriptSentinelPolicy(policy) {
  const next = deepClone(policy || {})
  const current = isPlainObject(next.script_sentinel) ? next.script_sentinel : {}
  next.script_sentinel = {
    enabled: Boolean(current.enabled),
    mode: ['match_original', 'block', 'requires_confirmation'].includes(String(current.mode || '').trim())
      ? String(current.mode).trim()
      : 'match_original',
    max_scan_bytes: Math.max(1024, Number.parseInt(String(current.max_scan_bytes ?? '1048576'), 10) || 1048576),
    include_wrappers: current.include_wrappers === undefined ? true : Boolean(current.include_wrappers),
  }
  return next
}

export default function App() {
  const [activeRail, setActiveRail] = useState('approvals')
  const [activeApprovalsTab, setActiveApprovalsTab] = useState('pending')
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
  const [commandEditModal, setCommandEditModal] = useState({
    open: false,
    original: '',
    command: '',
    description: '',
    tabIds: [],
  })
  const [newCommand, setNewCommand] = useState('')
  const [newComment, setNewComment] = useState('')
  const [newCommandTabs, setNewCommandTabs] = useState([])
  const [newCategoryLabel, setNewCategoryLabel] = useState('')
  const [selectedCategories, setSelectedCategories] = useState([])
  const [showAddCommandForm, setShowAddCommandForm] = useState(false)
  const [showAddCategoryForm, setShowAddCategoryForm] = useState(false)
  const [newPathValue, setNewPathValue] = useState('')
  const [newPathTier, setNewPathTier] = useState('blocked')
  const [showRuntimePaths, setShowRuntimePaths] = useState(false)
  const [showAddPathForm, setShowAddPathForm] = useState(false)
  const [newExtensionValue, setNewExtensionValue] = useState('')
  const [showAddExtensionForm, setShowAddExtensionForm] = useState(false)
  const [newNetworkCommand, setNewNetworkCommand] = useState('')
  const [newWhitelistDomain, setNewWhitelistDomain] = useState('')
  const [newBlocklistDomain, setNewBlocklistDomain] = useState('')
  const [showNetworkEditors, setShowNetworkEditors] = useState(false)
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
  const [showReportFilters, setShowReportFilters] = useState(false)
  const [reportsExpandedEventId, setReportsExpandedEventId] = useState(null)
  const [reportsLoading, setReportsLoading] = useState(false)
  const [reportsError, setReportsError] = useState('')
  const [activeSettingsTab, setActiveSettingsTab] = useState('agents')
  const [agentProfiles, setAgentProfiles] = useState([])
  const [agentTypes, setAgentTypes] = useState([])
  const [settingsConfigsDir, setSettingsConfigsDir] = useState('')
  const [settingsLoading, setSettingsLoading] = useState(false)
  const [settingsError, setSettingsError] = useState('')
  const [settingsSavedProfiles, setSettingsSavedProfiles] = useState({})
  const [settingsNeedsReconfigure, setSettingsNeedsReconfigure] = useState({})
  const [agentPosture, setAgentPosture] = useState({ profiles: [], discovered_unregistered: [], totals: { green: 0, yellow: 0, red: 0 } })
  const [agentPostureLoading, setAgentPostureLoading] = useState(false)
  const [agentPostureError, setAgentPostureError] = useState('')
  const [scriptSentinelData, setScriptSentinelData] = useState({ artifacts: { total: 0, items: [] }, summary: null })
  const [scriptSentinelLoading, setScriptSentinelLoading] = useState(false)
  const [scriptSentinelError, setScriptSentinelError] = useState('')
  const [scriptSentinelActionLoading, setScriptSentinelActionLoading] = useState({})
  const [agentConfigActionLoading, setAgentConfigActionLoading] = useState({})
  const [reportsFilters, setReportsFilters] = useState({
    agent_id: '',
    agent_session_id: '',
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
  const [validateButtonState, setValidateButtonState] = useState('idle')
  const [applyButtonState, setApplyButtonState] = useState('idle')
  const [validationErrorModal, setValidationErrorModal] = useState({
    open: false,
    title: '',
    details: '',
  })
  const [copyAssistModal, setCopyAssistModal] = useState({
    open: false,
    title: '',
    content: '',
  })
  const [showAdvanced, setShowAdvanced] = useState(() => {
    if (typeof window === 'undefined') return false
    return window.localStorage.getItem(ADVANCED_TOGGLE_KEY) === '1'
  })
  const [showPathAdvanced, setShowPathAdvanced] = useState(() => {
    if (typeof window === 'undefined') return false
    return window.localStorage.getItem(PATHS_ADVANCED_TOGGLE_KEY) === '1'
  })
  const pollRef = useRef(null)
  const [overrideAgentId, setOverrideAgentId] = useState('')
  const [overrideExpanded, setOverrideExpanded] = useState({})
  const [overrideListInputs, setOverrideListInputs] = useState({})
  const [navOpen, setNavOpen] = useState({
    approvals: true,
    policy: true,
    reports: false,
    settings: false,
  })
  const validateTimerRef = useRef(null)
  const applyTimerRef = useRef(null)
  const copyAssistRef = useRef(null)

  const unsaved = useMemo(() => {
    if (!appliedPolicy || !draftPolicy) return false
    return JSON.stringify(appliedPolicy) !== JSON.stringify(draftPolicy)
  }, [appliedPolicy, draftPolicy])

  const knownAgentIds = useMemo(() => {
    const ids = new Set()
    const fromPolicy = Object.keys((draftPolicy?.agent_overrides || {}))
      .filter((x) => x && x !== '_comment')
      .map((x) => String(x).trim())
      .filter(Boolean)
    fromPolicy.forEach((id) => ids.add(id))
    ;(agentProfiles || []).forEach((p) => {
      const id = String(p?.agent_id || '').trim()
      if (id) ids.add(id)
    })
    return Array.from(ids).sort()
  }, [draftPolicy, agentProfiles])

  const currentChildByRail = useMemo(
    () => ({
      approvals: activeApprovalsTab,
      policy: activePolicyTab,
      reports: reportsTab,
      settings: activeSettingsTab,
    }),
    [activeApprovalsTab, activePolicyTab, reportsTab, activeSettingsTab]
  )

  const pageTitle = useMemo(() => {
    if (activeRail === 'policy') {
      const tab = POLICY_TABS.find((t) => t.id === activePolicyTab)
      return `Policy · ${tab?.label || 'Commands'}`
    }
    if (activeRail === 'reports') {
      const tab = REPORT_TABS.find((t) => t.id === reportsTab)
      return `Reports · ${tab?.label || 'Dashboard'}`
    }
    if (activeRail === 'settings') {
      const tab = SETTINGS_TABS.find((t) => t.id === activeSettingsTab)
      return `Settings · ${tab?.label || 'Agents'}`
    }
    return 'Approvals · Pending'
  }, [activeRail, activePolicyTab, reportsTab, activeSettingsTab])

  useEffect(() => {
    if (!overrideAgentId && knownAgentIds.length) {
      setOverrideAgentId(knownAgentIds[0])
    } else if (overrideAgentId && !knownAgentIds.includes(overrideAgentId)) {
      setOverrideAgentId(knownAgentIds[0] || '')
    }
  }, [knownAgentIds, overrideAgentId])

  useEffect(() => {
    return () => {
      if (validateTimerRef.current) clearTimeout(validateTimerRef.current)
      if (applyTimerRef.current) clearTimeout(applyTimerRef.current)
    }
  }, [])

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
    const normalizedPolicy = ensureScriptSentinelPolicy(payload.policy || {})
    setAppliedPolicy(normalizedPolicy)
    setDraftPolicy(deepClone(normalizedPolicy))
    setJsonText(JSON.stringify(normalizedPolicy, null, 2))
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

  function emptyProfile() {
    return {
      profile_id: `profile-${Date.now()}`,
      name: '',
      agent_type: 'claude_code',
      workspace: '',
      agent_id: '',
      last_generated_at: '',
      last_saved_path: '',
      last_saved_instructions_path: '',
    }
  }

  function profileSnapshotMap(profiles = []) {
    const out = {}
    for (const p of profiles || []) {
      const id = String(p?.profile_id || '').trim()
      if (!id) continue
      out[id] = {
        name: String(p?.name || '').trim(),
        agent_type: String(p?.agent_type || '').trim(),
        agent_id: String(p?.agent_id || '').trim(),
        workspace: String(p?.workspace || '').trim(),
      }
    }
    return out
  }

  async function fetchSettingsAgents() {
    setSettingsLoading(true)
    setSettingsError('')
    try {
      const res = await fetch(`${API_BASE}/settings/agents`)
      if (!res.ok) throw new Error(`Settings load failed (${res.status})`)
      const payload = await res.json()
      setAgentProfiles(payload.profiles || [])
      setSettingsSavedProfiles(profileSnapshotMap(payload.profiles || []))
      setAgentTypes(payload.agent_types || [])
      setSettingsConfigsDir(payload.configs_dir || '')
    } catch (err) {
      setSettingsError(String(err.message || err))
    } finally {
      setSettingsLoading(false)
    }
  }

  async function upsertSettingsProfile(profile, { createWorkspace = false } = {}) {
    const res = await fetch(`${API_BASE}/settings/agents/upsert`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ profile, create_workspace: createWorkspace }),
    })
    const payload = await res.json()
    if (!res.ok || !payload.ok) {
      const err = new Error((payload.errors || ['Save failed']).join('; '))
      err.payload = payload
      throw err
    }
    setAgentProfiles(payload.profiles || [])
    setSettingsSavedProfiles(profileSnapshotMap(payload.profiles || []))
    return payload
  }

  async function generateAgentConfig(profileId, saveToFile = false) {
    const res = await fetch(`${API_BASE}/settings/agents/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ profile_id: profileId, save_to_file: saveToFile }),
    })
    const payload = await res.json()
    if (!res.ok || !payload.ok) {
      throw new Error((payload.errors || ['Generate failed']).join('; '))
    }
    setAgentProfiles(payload.profiles || [])
    setSettingsSavedProfiles(profileSnapshotMap(payload.profiles || []))
    return payload
  }

  async function openSavedConfigFile(profileId) {
    const params = new URLSearchParams({ profile_id: profileId })
    const res = await fetch(`${API_BASE}/settings/agents/open-file?${params.toString()}`)
    const payload = await res.json()
    if (!res.ok || !payload.ok) {
      throw new Error((payload.errors || ['Open file failed']).join('; '))
    }
    return payload
  }

  async function deleteSettingsProfile(profileId) {
    const res = await fetch(`${API_BASE}/settings/agents/delete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ profile_id: profileId }),
    })
    const payload = await res.json()
    if (!res.ok || !payload.ok) {
      throw new Error((payload.errors || ['Delete failed']).join('; '))
    }
    setAgentProfiles(payload.profiles || [])
    setSettingsSavedProfiles(profileSnapshotMap(payload.profiles || []))
    return payload
  }

  async function reconfigureRuntimeProfile(profileId) {
    const res = await fetch(`${API_BASE}/settings/agents/reconfigure-runtime`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ profile_id: profileId }),
    })
    const payload = await res.json()
    if (!res.ok || !payload.ok) {
      throw new Error((payload.errors || ['Runtime reconfigure failed']).join('; '))
    }
    return payload
  }

  async function fetchAgentPosture() {
    setAgentPostureLoading(true)
    setAgentPostureError('')
    const url = `${API_BASE}/settings/agents/posture`
    try {
      const res = await fetch(url, { headers: { Accept: 'application/json' } })
      const raw = await res.text()
      let payload = {}
      try {
        payload = raw ? JSON.parse(raw) : {}
      } catch {
        throw new Error(`Agent posture returned invalid JSON (${res.status}).`)
      }
      if (!res.ok || payload?.ok === false) {
        const detail = payload?.error
          ? String(payload.error)
          : Array.isArray(payload?.errors) && payload.errors.length
            ? payload.errors.join('; ')
            : `HTTP ${res.status}`
        throw new Error(`Agent posture load failed: ${detail}`)
      }
      setAgentPosture({
        profiles: payload.profiles || [],
        discovered_unregistered: payload.discovered_unregistered || [],
        totals: payload.totals || { green: 0, yellow: 0, red: 0 },
      })
    } catch (err) {
      const name = err?.name ? `${err.name}: ` : ''
      setAgentPostureError(`${name}${String(err.message || err)} [${url}]`)
    } finally {
      setAgentPostureLoading(false)
    }
  }

  async function fetchScriptSentinel() {
    setScriptSentinelLoading(true)
    setScriptSentinelError('')
    try {
      const res = await fetch(`${API_BASE}/settings/agents/script-sentinel?limit=200&offset=0&hours=24`)
      const payload = await res.json().catch(() => ({}))
      if (!res.ok || !payload?.ok) {
        throw new Error((payload?.errors || ['Script Sentinel load failed']).join('; '))
      }
      setScriptSentinelData({
        artifacts: payload.artifacts || { total: 0, items: [] },
        summary: payload.summary || null,
      })
    } catch (err) {
      setScriptSentinelError(String(err.message || err))
    } finally {
      setScriptSentinelLoading(false)
    }
  }

  async function scriptSentinelAllowance(contentHash, allowanceType) {
    const actionKey = `${allowanceType}:${contentHash}`
    setScriptSentinelActionLoading((prev) => ({ ...prev, [actionKey]: true }))
    setScriptSentinelError('')
    try {
      const promptText = allowanceType === 'once'
        ? 'Reason for one-time dismiss:'
        : 'Reason to trust this artifact for this agent:'
      const reason = window.prompt(promptText, '')
      if (!reason || !String(reason).trim()) return
      const endpoint = allowanceType === 'once'
        ? `${API_BASE}/settings/agents/script-sentinel/dismiss-once`
        : `${API_BASE}/settings/agents/script-sentinel/trust`
      const body = allowanceType === 'once'
        ? { content_hash: contentHash, reason: String(reason).trim(), ttl_seconds: 600 }
        : { content_hash: contentHash, reason: String(reason).trim() }
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      const payload = await res.json().catch(() => ({}))
      if (!res.ok || !payload?.ok) {
        throw new Error((payload?.errors || ['Script Sentinel allowance failed']).join('; '))
      }
      setMessage(allowanceType === 'once' ? 'One-time dismiss created.' : 'Persistent trust created.')
      await fetchScriptSentinel()
    } catch (err) {
      setScriptSentinelError(String(err.message || err))
    } finally {
      setScriptSentinelActionLoading((prev) => {
        const next = { ...prev }
        delete next[actionKey]
        return next
      })
    }
  }

  async function applyAgentConfigHardening(profileId, { autoAddMcp = false } = {}) {
    const res = await fetch(`${API_BASE}/settings/agents/config-apply`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ profile_id: profileId, auto_add_mcp: autoAddMcp }),
    })
    const payload = await res.json().catch(() => ({}))
    if (!res.ok || !payload.ok) {
      const err = new Error((payload.errors || ['Agent hardening apply failed']).join('; '))
      err.payload = payload
      throw err
    }
    if (payload.posture) {
      setAgentPosture({
        profiles: payload.posture.profiles || [],
        discovered_unregistered: payload.posture.discovered_unregistered || [],
        totals: payload.posture.totals || { green: 0, yellow: 0, red: 0 },
      })
    }
    return payload
  }

  async function undoAgentConfigHardening(profileId) {
    const res = await fetch(`${API_BASE}/settings/agents/config-undo`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ profile_id: profileId }),
    })
    const payload = await res.json().catch(() => ({}))
    if (!res.ok || !payload.ok) {
      const err = new Error((payload.errors || ['Agent hardening undo failed']).join('; '))
      err.payload = payload
      throw err
    }
    if (payload.posture) {
      setAgentPosture({
        profiles: payload.posture.profiles || [],
        discovered_unregistered: payload.posture.discovered_unregistered || [],
        totals: payload.posture.totals || { green: 0, yellow: 0, red: 0 },
      })
    }
    return payload
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
    if (activeRail !== 'settings') return
    fetchSettingsAgents()
  }, [activeRail])

  useEffect(() => {
    if (activeRail !== 'settings' || activeSettingsTab !== 'agents') return
    fetchAgentPosture()
    fetchScriptSentinel()
  }, [activeRail, activeSettingsTab])

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
      setDraftPolicy(ensureScriptSentinelPolicy(parsed))
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
    const payload = await res.json().catch(() => ({}))
    if (res.ok) {
      setMessage('Validation passed')
      setValidateButtonState('success')
      if (validateTimerRef.current) clearTimeout(validateTimerRef.current)
      validateTimerRef.current = setTimeout(() => setValidateButtonState('idle'), 2000)
    } else {
      const details = payload?.error
        ? String(payload.error)
        : `Validation failed (${res.status})`
      const payloadDump = (() => {
        try {
          return JSON.stringify(payload, null, 2)
        } catch {
          return String(payload || '')
        }
      })()
      setValidationErrorModal({
        open: true,
        title: 'Validation Failed',
        details: payloadDump && payloadDump !== '{}' ? `${details}\n\n${payloadDump}` : details,
      })
    }
  }

  async function onApply() {
    if (!draftPolicy) return
    const res = await fetch(`${API_BASE}/policy/apply`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Actor': 'control-plane-v3' }, body: JSON.stringify({ policy: draftPolicy })
    })
    const payload = await res.json().catch(() => ({}))
    if (!res.ok) {
      setMessage(payload.error || 'Apply failed')
      return
    }
    await fetchPolicy()
    setMessage('Policy applied')
    setApplyButtonState('success')
    if (applyTimerRef.current) clearTimeout(applyTimerRef.current)
    applyTimerRef.current = setTimeout(() => setApplyButtonState('idle'), 2000)
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
    const validTabs = selectedTabs.filter((id) => id !== 'all' && tabDefs.some((t) => t.id === id))

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

  function openCommandEditModal(cmd) {
    const contextLabels = contexts[cmd] || []
    const categoryTabIds = tabDefs
      .filter((tab) => tab.id !== 'all' && contextLabels.includes(tab.label))
      .map((tab) => tab.id)
    setCommandEditModal({
      open: true,
      original: cmd,
      command: cmd,
      description: descriptions[cmd] || '',
      tabIds: categoryTabIds,
    })
  }

  function saveCommandEdit() {
    const original = String(commandEditModal.original || '').trim()
    const updated = normalizeCommandName(commandEditModal.command)
    const updatedDescription = String(commandEditModal.description || '').trim()
    const selectedTabIds = (commandEditModal.tabIds || []).filter((id) => id !== 'all' && tabDefs.some((t) => t.id === id))

    if (!original) {
      setMessage('Original command is missing')
      return
    }
    if (!updated) {
      setMessage('Command text is required')
      return
    }
    if (updated !== original && allCommands.includes(updated)) {
      setMessage(`Command "${updated}" already exists`)
      return
    }

    setDraftPolicy((prev) => {
      const next = deepClone(prev)
      const priorTier = tierFor(next, original)
      const remove = (arr = []) => arr.filter((x) => x !== original)
      next.blocked.commands = remove(next.blocked?.commands)
      next.requires_confirmation.commands = remove(next.requires_confirmation?.commands)
      next.requires_simulation.commands = remove(next.requires_simulation?.commands)
      if (priorTier === 'blocked') next.blocked.commands = Array.from(new Set([...(next.blocked.commands || []), updated])).sort()
      if (priorTier === 'requires_confirmation') next.requires_confirmation.commands = Array.from(new Set([...(next.requires_confirmation.commands || []), updated])).sort()
      if (priorTier === 'requires_simulation') next.requires_simulation.commands = Array.from(new Set([...(next.requires_simulation.commands || []), updated])).sort()

      next.ui_catalog = next.ui_catalog || {}
      next.ui_catalog.tabs = Array.isArray(next.ui_catalog.tabs) ? next.ui_catalog.tabs : []
      for (const tab of next.ui_catalog.tabs) {
        tab.commands = Array.isArray(tab.commands) ? tab.commands.filter((c) => c !== original) : []
        tab.descriptions = typeof tab.descriptions === 'object' && tab.descriptions ? tab.descriptions : {}
        delete tab.descriptions[original]
      }
      for (const tabId of selectedTabIds) {
        const tabLabel = tabDefs.find((t) => t.id === tabId)?.label || tabId
        ensureUiCatalogTab(next, tabId, tabLabel)
        const tab = next.ui_catalog.tabs.find((t) => t.id === tabId)
        if (!tab.commands.includes(updated)) {
          tab.commands.push(updated)
          tab.commands.sort()
        }
        if (updatedDescription) tab.descriptions[updated] = updatedDescription
      }
      return next
    })

    setAllCommands((prev) => {
      const next = prev.filter((c) => c !== original)
      next.push(updated)
      return Array.from(new Set(next)).sort()
    })
    setDescriptions((prev) => {
      const next = { ...prev }
      delete next[original]
      if (updatedDescription) next[updated] = updatedDescription
      return next
    })
    setContexts((prev) => {
      const next = { ...prev }
      delete next[original]
      next[updated] = selectedTabIds.map((id) => tabDefs.find((t) => t.id === id)?.label || id)
      return next
    })
    setTabCommands((prev) => {
      const next = { ...prev }
      Object.keys(next).forEach((tabId) => {
        next[tabId] = (next[tabId] || []).filter((c) => c !== original)
      })
      for (const tabId of selectedTabIds) {
        const cur = new Set(next[tabId] || [])
        cur.add(updated)
        next[tabId] = Array.from(cur).sort()
      }
      next.all = Array.from(new Set([...(next.all || []).filter((c) => c !== original), updated])).sort()
      return next
    })

    setCommandEditModal({ open: false, original: '', command: '', description: '', tabIds: [] })
    setMessage(`Command "${original}" updated`)
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

  function toggleNavSection(sectionId) {
    setNavOpen((prev) => ({ ...prev, [sectionId]: !prev[sectionId] }))
  }

  function activateNav(sectionId, childId = '') {
    setActiveRail(sectionId)
    if (sectionId === 'approvals' && childId) setActiveApprovalsTab(childId)
    if (sectionId === 'policy' && childId) setActivePolicyTab(childId)
    if (sectionId === 'reports' && childId) setReportsTab(childId)
    if (sectionId === 'settings' && childId) setActiveSettingsTab(childId)
  }

  function renderSidebarSection(item) {
    const isActiveRail = activeRail === item.id
    const isOpen = Boolean(navOpen[item.id])
    const children = NAV_CHILDREN[item.id] || []
    const activeChild = currentChildByRail[item.id]
    const pending = item.id === 'approvals' ? pendingApprovals.length : 0
    return (
      <div key={item.id} className="mb-2">
        <button
          type="button"
          onClick={() => {
            activateNav(item.id, activeChild || children[0]?.id || '')
            if (children.length) toggleNavSection(item.id)
          }}
          className={`w-full flex items-center gap-2 px-3 py-2 text-left text-sm transition border sidebar-section-header ${
            isActiveRail
              ? 'bg-[var(--bg-sidebar-active)] text-[var(--text-sidebar-active)] border-transparent'
              : 'text-[var(--text-sidebar)] border-transparent hover:bg-[var(--bg-sidebar-hover)] hover:text-[var(--text-sidebar-active)]'
          }`}
        >
          <NavIcon id={item.id} />
          <span className="flex-1 font-medium">{item.label}</span>
          {pending > 0 && <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-red-500 text-white">{pending}</span>}
          {children.length > 0 && <span className={`text-xs text-slate-400 transition ${isOpen ? 'rotate-90' : ''}`}>▸</span>}
        </button>
        {children.length > 0 && isOpen && (
          <div className="mt-1 space-y-1">
            {children.map((child) => {
              const isActiveChild = isActiveRail && activeChild === child.id
              return (
                <button
                  key={`${item.id}-${child.id}`}
                  type="button"
                  onClick={() => activateNav(item.id, child.id)}
                  className={`w-full flex items-center gap-2 pl-8 pr-3 py-1.5 text-left text-xs transition border sidebar-nav-item ${
                    isActiveChild
                      ? 'active bg-[var(--bg-sidebar-active)] text-[var(--text-sidebar-active)] border-transparent font-medium'
                      : 'text-[var(--text-sidebar)] border-transparent hover:bg-[var(--bg-sidebar-hover)] hover:text-[var(--text-sidebar-active)]'
                  }`}
                >
                  <span className={`w-1.5 h-1.5 rounded-full ${isActiveChild ? 'bg-[var(--status-blue)]' : 'bg-slate-500'}`} />
                  <span>{child.label}</span>
                </button>
              )
            })}
          </div>
        )}
      </div>
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
            <button
              type="button"
              className="text-slate-400 hover:text-slate-600"
              onClick={() => openCommandEditModal(cmd)}
              title="Edit command metadata"
            >
              ✎
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
    const truncateCommand = (command, max = 110) => {
      if (!command) return ''
      if (command.length <= max) return command
      return `${command.slice(0, max - 1)}…`
    }

    if (!pendingApprovals.length) {
      return (
        <div className="bg-white rounded-[10px] border border-slate-200 p-8 text-center shadow-sm">
          <div className="mb-2 inline-flex items-center justify-center">
            <UiIcon kind="info" className="w-8 h-8 text-slate-500" />
          </div>
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
              className={`bg-white border-l-4 ${urgency ? 'border-red-400' : 'border-amber-400'} rounded-[10px] border border-slate-200 p-4 shadow-sm transition-all duration-200 ${removing[item.token] ? 'opacity-0 -translate-y-1' : 'opacity-100 translate-y-0'}`}
            >
              <div className="text-sm font-semibold text-slate-800">
                Agent <span className="font-mono">{item.agent_id || 'Unknown'}</span> needs approval for the following command:
              </div>
              <div className="font-mono text-sm text-slate-700 mt-1 break-all">{truncateCommand(item.command)}</div>
              <div className="text-xs text-slate-500 mt-1">Requested {relativeTime(item.requested_at)} • session <span className="font-mono">{item.session_id || 'n/a'}</span></div>
              <div className={`text-xs mt-1 ${urgency ? 'text-red-600 font-semibold' : 'text-slate-500'}`}>Expires in {item.seconds_remaining}s</div>
              <details className="mt-2 text-sm">
                <summary className="cursor-pointer text-slate-600">Full command details</summary>
                <pre className="mt-2 text-xs font-mono bg-slate-50 rounded p-2 border border-slate-200 overflow-auto whitespace-pre-wrap break-all">{item.command}</pre>
              </details>
              {item.affected_paths?.length > 0 && (
                <details className="mt-2 text-sm">
                  <summary className="cursor-pointer text-slate-600">Affected paths ({item.affected_paths.length})</summary>
                  <ul className="mt-2 text-xs font-mono bg-slate-50 rounded p-2 border border-slate-200 max-h-32 overflow-auto">
                    {item.affected_paths.map((p) => <li key={p}>{p}</li>)}
                  </ul>
                </details>
              )}
              <div className="mt-3 flex gap-2">
                <button onClick={() => approve(item.token, item.command)} className="px-3 py-1.5 rounded-[10px] bg-green-600 text-white text-sm font-medium">Approve</button>
                <button onClick={() => deny(item.token)} className="px-3 py-1.5 rounded-[10px] border border-red-300 text-red-700 text-sm">Deny</button>
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
    const todayKey = new Date().toISOString().slice(0, 10)

    const mapCountByDay = (rows) => {
      const out = new Map()
      ;(rows || []).forEach((row) => {
        const day = String(row?.day || '')
        const count = Number(row?.count || 0)
        if (day) out.set(day, count)
      })
      return out
    }

    const dayKeys = Array.from({ length: 7 }, (_, i) => {
      const d = new Date()
      d.setDate(d.getDate() - (6 - i))
      return d.toISOString().slice(0, 10)
    })
    const eventMap = mapCountByDay(eventsPerDay)
    const blockedMap = mapCountByDay(blockedPerDay)
    const chartRows = dayKeys.map((day) => ({
      day,
      total: Number(eventMap.get(day) || 0),
      blocked: Number(blockedMap.get(day) || 0),
    }))
    const chartMax = Math.max(1, ...chartRows.map((row) => Number(row.total || 0)))
    const hasChartData = chartRows.some((row) => Number(row.total || 0) > 0 || Number(row.blocked || 0) > 0)
    const eventsToday = Number(eventMap.get(todayKey) || 0)
    const blockedToday = Number(blockedMap.get(todayKey) || 0)
    const yesterdayKey = dayKeys[dayKeys.length - 2] || ''
    const eventsYesterday = Number(eventMap.get(yesterdayKey) || 0)
    const blockedYesterday = Number(blockedMap.get(yesterdayKey) || 0)
    const backupToday = reportsEvents.filter((event) => (
      String(event?.event || '') === 'backup_created' && String(event?.timestamp || '').startsWith(todayKey)
    )).length

    const formatDayLabel = (isoDay) => {
      const dt = new Date(`${isoDay}T00:00:00`)
      if (Number.isNaN(dt.getTime())) return isoDay
      return dt.toLocaleDateString(undefined, { weekday: 'short' })
    }

    const formatDelta = (todayValue, yesterdayValue) => {
      const delta = Number(todayValue || 0) - Number(yesterdayValue || 0)
      if (delta > 0) return { text: `+${delta} vs yesterday`, tone: 'positive' }
      if (delta < 0) return { text: `${delta} vs yesterday`, tone: 'negative' }
      return { text: 'No change vs yesterday', tone: 'neutral' }
    }

    const totalDelta = formatDelta(eventsToday, eventsYesterday)
    const blockedDelta = formatDelta(blockedToday, blockedYesterday)

    const filteredLabels = REPORT_FILTER_FIELDS.reduce((acc, field) => {
      const value = String(reportsFilters[field.key] || '').trim()
      if (value) acc.push(`${field.label} = ${value}`)
      return acc
    }, [])
    if (reportsTimeFilter !== 'all_time') {
      if (reportsTimeFilter === 'custom_day' && reportsCustomDay) {
        filteredLabels.push(`Date = ${reportsCustomDay}`)
      } else if (reportsTimeFilter === 'today') {
        filteredLabels.push('Date = Today')
      } else if (reportsTimeFilter === 'last_10_min') {
        filteredLabels.push('Date = Last 10 min')
      } else if (reportsTimeFilter === 'last_5_min') {
        filteredLabels.push('Date = Last 5 min')
      }
    }
    const activeFilterCount = filteredLabels.length
    const activeFilterSummary = filteredLabels.slice(0, 3).join(', ')
    const agentsMonitored = Math.max(
      Number(knownAgentIds?.length || 0),
      new Set(
        (reportsEvents || [])
          .map((event) => String(event?.agent_id || '').trim())
          .filter(Boolean)
      ).size
    )
    const lastEventTimestamp = String(reportsEvents[0]?.timestamp || reportsStatus?.last_ingested_at || '').trim()
    const timeSinceLastEvent = lastEventTimestamp ? relativeTime(lastEventTimestamp) : 'n/a'
    const nextIndexIn = (() => {
      const src = String(reportsStatus?.last_ingested_at || '').trim()
      if (!src) return 'n/a'
      const base = new Date(src).getTime()
      if (Number.isNaN(base)) return 'n/a'
      const next = base + (5 * 60 * 1000)
      const diff = next - Date.now()
      if (diff <= 0) return 'due'
      const mins = Math.floor(diff / 60000)
      const secs = Math.floor((diff % 60000) / 1000)
      return `${mins}m ${String(secs).padStart(2, '0')}s`
    })()
    const systemActive = !reportsError

    const resetReportsFilters = () => {
      setReportsOffset(0)
      setReportsExpandedEventId(null)
      setReportsFilters({
        agent_id: '',
        agent_session_id: '',
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
      setShowReportFilters(false)
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

    return (
      <div className="space-y-3">
        <div className="card">
          <div className="flex items-center justify-between gap-3 mb-3">
            <div className="text-xs text-slate-500">
              {reportsStatus?.last_ingested_at ? `Last indexed ${relativeTime(reportsStatus.last_ingested_at)}` : 'No ingest data yet'}
            </div>
            <button onClick={() => fetchReports({ sync: true })} className="btn btn-ghost">Refresh</button>
          </div>
          <div className="status-banner">
            <div className="status-item">
              <span className={`dot ${systemActive ? 'active' : 'inactive'}`} />
              <span>{systemActive ? 'System active' : 'System degraded'}</span>
            </div>
            <div className="status-item">
              <span className="value">{agentsMonitored}</span>
              <span>agents monitored</span>
            </div>
            <div className="status-item">
              <span className="value">{pendingApprovalsCount}</span>
              <span>pending approvals</span>
            </div>
            <div className="status-item">
              <span className="value">{timeSinceLastEvent}</span>
              <span>since last event</span>
            </div>
            <div className="status-item">
              <span className="value">{nextIndexIn}</span>
              <span>next index</span>
            </div>
          </div>
          {reportsError && <div className="mt-2 text-sm text-red-600">{reportsError}</div>}
          {reportsLoading && <div className="mt-2 text-xs text-slate-500">Refreshing reports...</div>}
        </div>

        <div className="card">
          <div className="flex items-center justify-between gap-2">
            <button onClick={() => setShowReportFilters((v) => !v)} className="btn btn-ghost">
              {showReportFilters ? 'Hide filters' : 'Show filters'} ({activeFilterCount})
            </button>
            {showReportFilters && (
              <button onClick={resetReportsFilters} className="btn btn-ghost">Reset filters</button>
            )}
          </div>
          {activeFilterCount > 0 && (
            <div className="text-xs text-slate-600 mt-2">
              Filtered: <span className="font-mono">{activeFilterSummary}{activeFilterCount > 3 ? ', ...' : ''}</span>
            </div>
          )}
          {showReportFilters && (
            <div className="filter-panel mt-3">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                {REPORT_FILTER_FIELDS.map((field) => (
                  <input
                    key={field.key}
                    value={reportsFilters[field.key] || ''}
                    onChange={(e) => {
                      setReportsOffset(0)
                      setReportsFilters((prev) => ({ ...prev, [field.key]: e.target.value }))
                    }}
                    className="mono-input"
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
                  />
                )}
              </div>
            </div>
          )}
        </div>

        {reportsTab === 'dashboard' && (
          <>
            <div className="stat-grid">
              <button
                onClick={() => openLogWithFilters({}, { clearAll: true })}
                className="stat-card text-left hover:border-[#bfd4ff] cursor-pointer"
              >
                <div className="stat-label">Total events</div>
                <div className={`stat-value ${Number(totals.total_events || 0) === 0 ? 'zero' : ''}`}>{totals.total_events || 0}</div>
                <div className={`stat-delta ${totalDelta.tone}`}>{totalDelta.text}</div>
              </button>
              <button
                onClick={() => openLogWithFilters({ policy_decision: 'blocked' }, { clearAll: true })}
                className={`stat-card text-left hover:border-[#bfd4ff] cursor-pointer ${Number(totals.blocked_events || 0) > 0 ? 'has-alert' : ''}`}
              >
                <div className="stat-label">Blocked events</div>
                <div className={`stat-value blocked ${Number(totals.blocked_events || 0) === 0 ? 'zero' : ''}`}>{totals.blocked_events || 0}</div>
                <div className={`stat-delta ${blockedDelta.tone}`}>{blockedDelta.text}</div>
              </button>
              <button
                onClick={() => openLogWithFilters({ event: 'backup_created' }, { clearAll: true })}
                className="stat-card text-left hover:border-[#bfd4ff] cursor-pointer"
              >
                <div className="stat-label">Backups created</div>
                <div className={`stat-value ${Number(totals.backup_events || 0) === 0 ? 'zero' : ''}`}>{totals.backup_events || 0}</div>
                <div className="stat-delta">Today (visible log): {backupToday}</div>
              </button>
              <button
                onClick={() => setActiveRail('approvals')}
                className={`stat-card text-left hover:border-[#bfd4ff] cursor-pointer ${pendingApprovalsCount > 0 ? 'has-pending' : ''}`}
              >
                <div className="stat-label">Approvals</div>
                <div className={`stat-value ${pendingApprovalsCount === 0 ? 'zero' : ''}`}>{reportsConfirmations.approved || 0} / {reportsConfirmations.denied || 0}</div>
                <div className="stat-delta">Pending: {pendingApprovalsCount}</div>
              </button>
            </div>

            <div className="card">
              <div className="text-sm font-semibold text-slate-700 mb-2">Activity (7 days)</div>
              {hasChartData ? (
                <>
                  <div className="activity-chart">
                    <div className="activity-y-axis">
                      <span>{chartMax}</span>
                      <span>{Math.max(1, Math.round(chartMax / 2))}</span>
                      <span>0</span>
                    </div>
                    <div className="activity-bars">
                      {chartRows.map((row) => {
                        const totalPct = row.total > 0 ? Math.max(4, Math.round((row.total / chartMax) * 100)) : 0
                        const blockedPct = row.blocked > 0 ? Math.max(4, Math.round((row.blocked / chartMax) * 100)) : 0
                        return (
                          <div key={row.day} className="chart-bar-group" title={`${row.day}: total ${row.total}, blocked ${row.blocked}`}>
                            <div className="chart-bar-stack">
                              <div className="chart-bar total" style={{ height: `${totalPct}%` }} />
                              <div className="chart-bar blocked" style={{ height: `${blockedPct}%` }} />
                            </div>
                            <div className="chart-bar-label">{formatDayLabel(row.day)}</div>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                  <div className="chart-legend">
                    <span><i className="legend-swatch total" /> Total events</span>
                    <span><i className="legend-swatch blocked" /> Blocked</span>
                  </div>
                </>
              ) : (
                <div className="chart-empty">
                  <div className="chart-empty-icon">▤</div>
                  <p>No events recorded yet</p>
                  <p className="text-tertiary">Events will appear here once an agent makes its first tool call through AIRG.</p>
                </div>
              )}
            </div>

            <div className="card">
              <div className="top-lists-grid">
                <div className="top-list">
                  <h4>Top commands</h4>
                  {!topCommands.length && <div className="text-xs text-slate-500">No data</div>}
                  {topCommands.map((row) => (
                    <button
                      key={row.command}
                      onClick={() => openLogWithFilters({ command: row.command }, { clearAll: true })}
                      className="top-list-item"
                    >
                      <span className="name">{row.command}</span>
                      <span className="count">{row.count}</span>
                    </button>
                  ))}
                </div>
                <div className="top-list">
                  <h4>Top paths</h4>
                  {!topPaths.length && <div className="text-xs text-slate-500">No data</div>}
                  {topPaths.map((row) => (
                    <button
                      key={row.path}
                      onClick={() => openLogWithFilters({ path: row.path }, { clearAll: true })}
                      className="top-list-item"
                    >
                      <span className="name truncate pr-2">{row.path}</span>
                      <span className="count">{row.count}</span>
                    </button>
                  ))}
                </div>
                <div className="top-list">
                  <h4>Blocked by rule</h4>
                  {!blockedByRule.length && <div className="text-xs text-slate-500">No data</div>}
                  {blockedByRule.map((row) => (
                    <button
                      key={row.matched_rule}
                      onClick={() => openLogWithFilters({ matched_rule: row.matched_rule }, { clearAll: true })}
                      className="top-list-item"
                    >
                      <span className="name">{row.matched_rule}</span>
                      <span className="count">{row.count}</span>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </>
        )}

        {reportsTab === 'log' && (
          <div className="bg-white border border-slate-200 rounded-[10px] p-3 shadow-sm">
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
            <div className="overflow-auto border border-slate-200 rounded-[10px]">
              <table className="min-w-full text-xs">
                <thead className="bg-slate-50 text-slate-600">
                  <tr>
                    <th className="text-left px-2 py-1"> </th>
                    <th className="text-left px-2 py-1">Time</th>
                    <th className="text-left px-2 py-1">Agent</th>
                    <th className="text-left px-2 py-1">Session</th>
                    <th className="text-left px-2 py-1">Source</th>
                    <th className="text-left px-2 py-1">Tool</th>
                    <th className="text-left px-2 py-1">Decision</th>
                    <th className="text-left px-2 py-1">Matched Rule</th>
                    <th className="text-left px-2 py-1">Command / Path</th>
                  </tr>
                </thead>
                <tbody>
                  {reportsEvents.length === 0 && (
                    <tr><td colSpan={9} className="px-2 py-4 text-center text-slate-500">No events</td></tr>
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
                          <td className="px-2 py-1 font-mono">{e.agent_session_id || e.session_id || '-'}</td>
                          <td className="px-2 py-1">{e.source || '-'}</td>
                          <td className="px-2 py-1">{e.tool || '-'}</td>
                          <td className="px-2 py-1">{e.policy_decision || '-'}</td>
                          <td className="px-2 py-1 font-mono">{e.matched_rule || '-'}</td>
                          <td className="px-2 py-1 font-mono">{e.command || e.path || '-'}</td>
                        </tr>
                        {expanded && (
                          <tr className="bg-slate-50 border-t border-slate-100">
                            <td colSpan={9} className="px-2 py-2">
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
        <div className="card mb-3">
          <div className="flex items-center justify-between mb-2">
            <div className="section-title m-0">Command Authoring</div>
            <div className="flex items-center gap-2">
              <button onClick={() => setShowAddCommandForm((v) => !v)} className="btn btn-ghost">{showAddCommandForm ? 'Hide Add Command' : '+ Add Command'}</button>
              <button onClick={() => setShowAddCategoryForm((v) => !v)} className="btn btn-ghost">{showAddCategoryForm ? 'Hide Add Category' : '+ Add Category'}</button>
            </div>
          </div>
          {showAddCommandForm && (
            <div className="space-y-2 mb-3">
              <div className="form-label">Add Command</div>
              <div className="grid grid-cols-1 md:grid-cols-[1fr_1fr] gap-2">
                <input
                  value={newCommand}
                  onChange={(e) => setNewCommand(e.target.value)}
                  className="mono-input"
                  placeholder="Command (e.g. git cherry-pick)"
                />
                <input
                  value={newComment}
                  onChange={(e) => setNewComment(e.target.value)}
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
              <div className="text-xs text-slate-500">Category selection is optional. If none is selected, the command is added as uncategorized.</div>
              <button onClick={onAddCommand} className="btn btn-primary">Add command</button>
            </div>
          )}
          {showAddCategoryForm && (
            <div className="space-y-2">
              <div className="form-label">Add Category</div>
              <div className="flex gap-2">
                <input
                  value={newCategoryLabel}
                  onChange={(e) => setNewCategoryLabel(e.target.value)}
                  className="flex-1"
                  placeholder="Category name (e.g. Databases)"
                />
                <button onClick={onCreateCategory} className="btn btn-ghost">Add category</button>
              </div>
            </div>
          )}
        </div>

        <div className="card mb-3 space-y-2">
          <div className="section-title">Filters</div>
          <div className="grid grid-cols-1 md:grid-cols-[1fr_1fr] gap-2">
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full"
              placeholder="Filter commands by text..."
            />
            <div className="border border-[var(--border-input)] rounded-[var(--radius-md)] px-3 py-2 bg-[var(--bg-input)]">
              <div className="text-xs text-[var(--text-secondary)] mb-1">Categories (multi-select, default: All)</div>
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

        <div className="card overflow-auto">
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
        <div className="card">
          <button type="button" className="section-toggle" onClick={() => setShowRuntimePaths((v) => !v)}>
            <span>Runtime Paths</span>
            <span className="text-[var(--text-tertiary)]">(read only)</span>
            <span className={`ml-auto text-xs text-[var(--text-tertiary)] transition ${showRuntimePaths ? 'rotate-180' : ''}`}>▾</span>
          </button>
          {showRuntimePaths && (
            <>
              <dl className="runtime-paths-list mt-3">
                {Object.entries(runtimePaths).map(([key, value]) => (
                  key === 'AIRG_AGENT_ID' ? null : (
                    <div key={key}>
                      <dt>{RUNTIME_PATH_LABELS[key] || key}</dt>
                      <dd className="path-display">{String(value || '')}</dd>
                    </div>
                  )
                ))}
              </dl>
              <div className="text-xs text-amber-700 bg-amber-50 border border-amber-200 rounded-[10px] px-3 py-2 mt-3">
                Runtime paths are managed by MCP client configuration/env. To change workspace paths, update your AI agent MCP config,
                then restart the MCP server and agent client.
              </div>
            </>
          )}
        </div>
        <div className="card">
          <div className="flex items-center justify-between">
            <div className="section-title m-0">Path Rules</div>
            <button onClick={() => setShowAddPathForm((v) => !v)} className="btn btn-ghost">{showAddPathForm ? 'Hide Add Path' : '+ Add Path'}</button>
          </div>
          {showAddPathForm && (
            <div className="space-y-2 mt-3">
              <div className="grid grid-cols-1 md:grid-cols-[1fr_320px_auto] gap-2 items-center">
                <input
                  value={newPathValue}
                  onChange={(e) => setNewPathValue(e.target.value)}
                  className="mono-input"
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
                <button onClick={onAddPath} className="btn btn-primary">Add path</button>
              </div>
              <div className="text-xs text-slate-500">Example: <span className="font-mono">/Users/your_username/Documents/Folder</span></div>
            </div>
          )}
        </div>
        <div className="card overflow-auto">
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
                <div className="border border-slate-300 rounded px-2 py-1 font-mono text-xs bg-[var(--bg-input)]">{p}</div>
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
    const onEdit = (oldExt) => {
      const nextVal = window.prompt('Edit extension value', oldExt)
      if (nextVal === null) return
      const val = String(nextVal || '').trim()
      if (!val) {
        setMessage('Extension value is required')
        return
      }
      setDraftPolicy((prev) => {
        const next = deepClone(prev)
        const list = (next.blocked?.extensions || []).filter((e) => e !== oldExt)
        list.push(val)
        next.blocked.extensions = Array.from(new Set(list)).sort()
        return next
      })
      setMessage(`Extension "${oldExt}" updated`)
    }
    return (
      <div className="space-y-3">
        <div className="card">
          <div className="flex items-center justify-between">
            <div className="section-title m-0">Blocked Extensions</div>
            <button onClick={() => setShowAddExtensionForm((v) => !v)} className="btn btn-ghost">{showAddExtensionForm ? 'Hide Add Extension' : '+ Add Extension'}</button>
          </div>
          {showAddExtensionForm && (
            <div className="space-y-2 mt-3">
              <div className="grid grid-cols-1 md:grid-cols-[1fr_auto] gap-2 items-center">
                <input
                  value={newExtensionValue}
                  onChange={(e) => setNewExtensionValue(e.target.value)}
                  className="mono-input"
                  placeholder="*.ext"
                  title="Enter extension pattern such as *.pem, *.key, *.env"
                />
                <button onClick={onAdd} className="btn btn-primary">Add extension</button>
              </div>
              <div className="text-xs text-slate-500">Example: <span className="font-mono">*.pem</span></div>
            </div>
          )}
        </div>
        <div className="card overflow-auto">
          <div className="grid grid-cols-[minmax(320px,1fr)_140px] gap-2 text-xs font-semibold text-slate-500 border-b border-slate-200 pb-2">
            <div>Extension</div>
            <div className="text-center">Actions</div>
          </div>
          {blockedExt.map((ext) => (
            <div key={ext} className="grid grid-cols-[minmax(320px,1fr)_140px] gap-2 items-center border-b border-slate-200 py-2 text-sm">
              <div className="border border-slate-300 rounded px-2 py-1 font-mono text-xs bg-[var(--bg-input)]">{ext}</div>
              <div className="flex justify-center gap-2">
                <button
                  onClick={() => onEdit(ext)}
                  className="px-2 py-1 rounded border border-slate-300 text-slate-700 text-xs"
                >
                  Edit
                </button>
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
        <div className="bg-white border border-red-200 rounded-[10px] p-3 shadow-sm">
          <div className="text-sm text-red-700">
            Network policy applies to commands listed under <span className="font-mono">network.commands</span>. In <span className="font-mono">off</span> mode no checks are enforced.
            In <span className="font-mono">monitor</span> mode checks are logged but commands are allowed. In <span className="font-mono">enforce</span> mode domain allow/block rules are enforced.
          </div>
        </div>

        <div className="bg-blue-50 border border-blue-200 rounded-[10px] p-3 shadow-sm">
          <div className="text-xs font-semibold text-blue-900 uppercase tracking-wide mb-1">Runtime Domain Matching Notes</div>
          <div className="text-xs text-blue-900 space-y-1">
            <div>Subdomains are matched: a rule for <span className="font-mono">example.com</span> also applies to <span className="font-mono">api.example.com</span>.</div>
            <div>Policy checks the hostnames found in command arguments/URLs only.</div>
            <div>Redirect chains and short-link expansion are not followed; checks apply to the visible domain in the command.</div>
            <div>Referral/tracking query params do not affect domain matching.</div>
          </div>
        </div>

        <div className="card space-y-2">
          <div className="text-xs font-semibold text-slate-600 uppercase tracking-wide">Enforcement Mode</div>
          <div className="flex items-center justify-end">
            <button onClick={() => setShowNetworkEditors((v) => !v)} className="btn btn-ghost">{showNetworkEditors ? 'Hide Network Editors' : '+ Show Network Editors'}</button>
          </div>
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

        {showNetworkEditors && (
        <div className="card space-y-2">
          <div className="text-xs font-semibold text-slate-600 uppercase tracking-wide">Network Commands</div>
          <div className="text-xs text-slate-500">These commands are used to trigger network policy evaluation. Listing a command here does not block it by itself.</div>
          <div className="grid grid-cols-1 md:grid-cols-[1fr_auto] gap-2 items-center">
            <input
              value={newNetworkCommand}
              onChange={(e) => setNewNetworkCommand(e.target.value)}
              className="mono-input"
              placeholder="curl"
            />
            <button onClick={addNetworkCommand} className="btn btn-primary">Add command</button>
          </div>
          <div className="bg-slate-50 border border-slate-200 rounded-[10px] p-2">
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
        )}

        {showNetworkEditors && (
        <div className="card">
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
                  className="mono-input"
                  placeholder="api.github.com"
                />
                <button onClick={() => addDomain('allow')} className="btn btn-primary">Add</button>
              </div>
              <div className="bg-slate-50 border border-slate-200 rounded-[10px] p-2 flex flex-wrap gap-2 min-h-[52px]">
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
                  className="mono-input"
                  placeholder="malicious.example"
                />
                <button onClick={() => addDomain('block')} className="btn btn-danger">Add</button>
              </div>
              <div className="bg-slate-50 border border-slate-200 rounded-[10px] p-2 flex flex-wrap gap-2 min-h-[52px]">
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
        )}
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
    const scriptSentinel = draftPolicy?.script_sentinel || {}
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

    const setScriptSentinel = (patch) => {
      setDraftPolicy((prev) => {
        const next = deepClone(prev)
        next.script_sentinel = { ...(next.script_sentinel || {}), ...patch }
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
        <div className="bg-blue-50 border border-blue-200 rounded-[10px] p-3 text-xs text-blue-800">
          These settings are global/session-level controls for simulation and cumulative budget, not per-command controls.
          Check the manual for exact enforcement semantics and examples.
        </div>

        <div className="bg-white border border-slate-200 rounded-[10px] p-3 shadow-sm space-y-3">
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
                className="mt-1 w-full border border-slate-300 rounded-[10px] px-3 py-2 text-sm"
                value={limits.max_total_operations ?? ''}
                onChange={(e) => setLimits('max_total_operations', e.target.value)}
              />
            </label>
            <label className="text-xs text-slate-600">
              Max unique paths
              <input
                type="number"
                min={0}
                className="mt-1 w-full border border-slate-300 rounded-[10px] px-3 py-2 text-sm"
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
                  className="w-full border border-slate-300 rounded-[10px] px-3 py-2 text-sm"
                  value={bytesDisplay}
                  onChange={(e) => onBytesDisplayChange(e.target.value)}
                />
                <select
                  className="border border-slate-300 rounded-[10px] px-2 py-2 text-sm"
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
                className="mt-1 w-full border border-slate-300 rounded-[10px] px-3 py-2 text-sm font-mono"
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

        <div className="bg-white border border-slate-200 rounded-[10px] p-3 shadow-sm space-y-3">
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
                className="mt-1 w-full border border-slate-300 rounded-[10px] px-3 py-2 text-sm"
                value={reset.window_seconds ?? 3600}
                onChange={(e) => setReset({ window_seconds: Math.max(0, parseInt(e.target.value, 10) || 0) })}
              />
            </label>
            <label className="text-xs text-slate-600">
              Idle reset (seconds)
              <input
                type="number"
                min={0}
                className="mt-1 w-full border border-slate-300 rounded-[10px] px-3 py-2 text-sm"
                value={reset.idle_reset_seconds ?? 900}
                onChange={(e) => setReset({ idle_reset_seconds: Math.max(0, parseInt(e.target.value, 10) || 0) })}
              />
            </label>
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-[10px] p-3 shadow-sm space-y-3">
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
                className="mt-1 w-full border border-slate-300 rounded-[10px] px-3 py-2 text-sm"
                value={simulation.max_retries ?? 0}
                onChange={(e) => setSimulation({ max_retries: Math.max(0, parseInt(e.target.value, 10) || 0) })}
              />
            </label>
            <label className="text-xs text-slate-600">
              Bulk file threshold
              <input
                type="number"
                min={0}
                className="mt-1 w-full border border-slate-300 rounded-[10px] px-3 py-2 text-sm"
                value={simulation.bulk_file_threshold ?? 0}
                onChange={(e) => setSimulation({ bulk_file_threshold: Math.max(0, parseInt(e.target.value, 10) || 0) })}
              />
            </label>
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-[10px] p-3 shadow-sm space-y-3">
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
                className="mt-1 w-full border border-slate-300 rounded-[10px] px-3 py-2 text-sm font-mono"
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
                className="mt-1 w-full border border-slate-300 rounded-[10px] px-3 py-2 text-sm"
                value={restore.confirmation_ttl_seconds ?? 300}
                onChange={(e) => setRestore({ confirmation_ttl_seconds: Math.max(30, parseInt(e.target.value, 10) || 30) })}
              />
            </label>
            <label className="text-xs text-slate-600">
              Backup root
              <input
                type="text"
                className="mt-1 w-full border border-slate-300 rounded-[10px] px-3 py-2 text-sm font-mono"
                value={audit.backup_root ?? ''}
                onChange={(e) => setAudit({ backup_root: e.target.value })}
              />
            </label>
            <label className="text-xs text-slate-600">
              Max versions per file
              <input
                type="number"
                min={1}
                className="mt-1 w-full border border-slate-300 rounded-[10px] px-3 py-2 text-sm"
                value={audit.max_versions_per_file ?? 5}
                onChange={(e) => setAudit({ max_versions_per_file: Math.max(1, parseInt(e.target.value, 10) || 1) })}
              />
            </label>
            <label className="text-xs text-slate-600">
              Backup retention days
              <input
                type="number"
                min={0}
                className="mt-1 w-full border border-slate-300 rounded-[10px] px-3 py-2 text-sm"
                value={audit.backup_retention_days ?? 30}
                onChange={(e) => setAudit({ backup_retention_days: Math.max(0, parseInt(e.target.value, 10) || 0) })}
              />
            </label>
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-[10px] p-3 shadow-sm space-y-3">
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
                className="mt-1 w-full border border-slate-300 rounded-[10px] px-3 py-2 text-sm"
                value={execution.max_command_timeout_seconds ?? 30}
                onChange={(e) => setExecution({ max_command_timeout_seconds: Math.max(1, parseInt(e.target.value, 10) || 1) })}
              />
            </label>
            <label className="text-xs text-slate-600">
              Max output chars
              <input
                type="number"
                min={1024}
                className="mt-1 w-full border border-slate-300 rounded-[10px] px-3 py-2 text-sm"
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

        <div className="bg-white border border-slate-200 rounded-[10px] p-3 shadow-sm space-y-3">
          <div className="text-xs font-semibold text-slate-600 uppercase tracking-wide">Whitelisted Commands Limits</div>
          <div className="text-[11px] text-amber-800 bg-amber-50 border border-amber-200 rounded-[10px] p-2">
            Applies to commands not explicitly configured as blocked, simulation-gated, or approval-gated.
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <label className="text-xs text-slate-600">
              Max file size (MB)
              <input
                type="number"
                min={0}
                className="mt-1 w-full border border-slate-300 rounded-[10px] px-3 py-2 text-sm"
                value={allowed.max_file_size_mb ?? 10}
                onChange={(e) => setAllowed({ max_file_size_mb: Math.max(0, parseInt(e.target.value, 10) || 0) })}
              />
            </label>
            <label className="text-xs text-slate-600">
              Max files per operation
              <input
                type="number"
                min={0}
                className="mt-1 w-full border border-slate-300 rounded-[10px] px-3 py-2 text-sm"
                value={allowed.max_files_per_operation ?? 10}
                onChange={(e) => setAllowed({ max_files_per_operation: Math.max(0, parseInt(e.target.value, 10) || 0) })}
              />
            </label>
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-[10px] p-3 shadow-sm space-y-3">
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
                className="mt-1 w-full border border-slate-300 rounded-[10px] px-3 py-2 text-sm"
                value={approvalSecurity.max_failed_attempts_per_token ?? 5}
                onChange={(e) => setConfirmationSecurity({ max_failed_attempts_per_token: Math.max(0, parseInt(e.target.value, 10) || 0) })}
              />
            </label>
            <label className="text-xs text-slate-600">
              Failed-attempt window (seconds)
              <input
                type="number"
                min={0}
                className="mt-1 w-full border border-slate-300 rounded-[10px] px-3 py-2 text-sm"
                value={approvalSecurity.failed_attempt_window_seconds ?? 600}
                onChange={(e) => setConfirmationSecurity({ failed_attempt_window_seconds: Math.max(0, parseInt(e.target.value, 10) || 0) })}
              />
            </label>
            <label className="text-xs text-slate-600">
              Approval token TTL (seconds)
              <input
                type="number"
                min={0}
                className="mt-1 w-full border border-slate-300 rounded-[10px] px-3 py-2 text-sm"
                value={approvalSecurity.token_ttl_seconds ?? 600}
                onChange={(e) => setConfirmationSecurity({ token_ttl_seconds: Math.max(0, parseInt(e.target.value, 10) || 0) })}
              />
            </label>
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-[10px] p-3 shadow-sm space-y-3">
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
                className="mt-1 w-full border border-slate-300 rounded-[10px] px-3 py-2 text-sm"
                value={reportsCfg.ingest_poll_interval_seconds ?? 5}
                onChange={(e) => setReportsConfig({ ingest_poll_interval_seconds: Math.max(1, parseInt(e.target.value, 10) || 1) })}
              />
            </label>
            <label className="text-xs text-slate-600">
              Reconcile interval (seconds)
              <input
                type="number"
                min={60}
                className="mt-1 w-full border border-slate-300 rounded-[10px] px-3 py-2 text-sm"
                value={reportsCfg.reconcile_interval_seconds ?? 3600}
                onChange={(e) => setReportsConfig({ reconcile_interval_seconds: Math.max(60, parseInt(e.target.value, 10) || 60) })}
              />
            </label>
            <label className="text-xs text-slate-600">
              Prune interval (seconds)
              <input
                type="number"
                min={300}
                className="mt-1 w-full border border-slate-300 rounded-[10px] px-3 py-2 text-sm"
                value={reportsCfg.prune_interval_seconds ?? 86400}
                onChange={(e) => setReportsConfig({ prune_interval_seconds: Math.max(300, parseInt(e.target.value, 10) || 300) })}
              />
            </label>
            <label className="text-xs text-slate-600">
              Retention days
              <input
                type="number"
                min={1}
                className="mt-1 w-full border border-slate-300 rounded-[10px] px-3 py-2 text-sm"
                value={reportsCfg.retention_days ?? 30}
                onChange={(e) => setReportsConfig({ retention_days: Math.max(1, parseInt(e.target.value, 10) || 1) })}
              />
            </label>
            <label className="text-xs text-slate-600">
              Max reports DB size (MB)
              <input
                type="number"
                min={10}
                className="mt-1 w-full border border-slate-300 rounded-[10px] px-3 py-2 text-sm"
                value={reportsCfg.max_db_size_mb ?? 200}
                onChange={(e) => setReportsConfig({ max_db_size_mb: Math.max(10, parseInt(e.target.value, 10) || 10) })}
              />
            </label>
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-[10px] p-3 shadow-sm space-y-3">
          <div className="text-xs font-semibold text-slate-600 uppercase tracking-wide">Script Sentinel</div>
          <div className="text-[11px] text-slate-500">
            Policy-intent continuity for script-mediated execution. Content written via <span className="font-mono">write_file</span> is scanned for blocked/approval-gated patterns.
          </div>
          <div className="flex flex-wrap gap-4 text-sm">
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={Boolean(scriptSentinel.enabled)}
                onChange={(e) => setScriptSentinel({ enabled: e.target.checked })}
              />
              Enabled
            </label>
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={Boolean(scriptSentinel.include_wrappers)}
                onChange={(e) => setScriptSentinel({ include_wrappers: e.target.checked })}
              />
              Include common wrapper signatures
            </label>
          </div>
          <div className="space-y-2">
            <div className="text-xs text-slate-600">Mode</div>
            <div className="flex flex-wrap gap-3 text-sm">
              {['match_original', 'block', 'requires_confirmation'].map((mode) => (
                <label key={mode} className="flex items-center gap-2">
                  <input
                    type="radio"
                    name="script-sentinel-mode"
                    checked={(scriptSentinel.mode || 'match_original') === mode}
                    onChange={() => setScriptSentinel({ mode })}
                  />
                  <span className="font-mono">{mode}</span>
                </label>
              ))}
            </div>
          </div>
          <label className="text-xs text-slate-600 block">
            Max scan bytes per write
            <input
              type="number"
              min={1024}
              className="mt-1 w-full border border-slate-300 rounded-[10px] px-3 py-2 text-sm"
              value={scriptSentinel.max_scan_bytes ?? 1048576}
              onChange={(e) => setScriptSentinel({ max_scan_bytes: Math.max(1024, parseInt(e.target.value, 10) || 1024) })}
            />
            <div className="mt-1 text-[11px] text-slate-500">
              Files larger than this limit are skipped for write-time scanning.
            </div>
          </label>
        </div>

        <div className="bg-white border border-slate-200 rounded-[10px] p-3 shadow-sm space-y-3">
          <div className="text-xs font-semibold text-slate-600 uppercase tracking-wide">Log Redaction</div>
          <label className="text-xs text-slate-600 block">
            Redact patterns (one regex per line)
            <textarea
              className="mt-1 w-full border border-slate-300 rounded-[10px] px-3 py-2 text-xs font-mono h-28"
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

  function AgentOverridesPanel() {
    const overrides = draftPolicy?.agent_overrides || {}
    const selectedPolicy = overrideAgentId ? (overrides?.[overrideAgentId]?.policy || {}) : {}

    const setAgentOverridePolicy = (agentId, updater) => {
      setDraftPolicy((prev) => {
        const next = deepClone(prev)
        next.agent_overrides = { ...(next.agent_overrides || {}) }
        const current = next.agent_overrides?.[agentId] || {}
        const currentPolicy = current.policy && typeof current.policy === 'object' ? current.policy : {}
        const updatedPolicy = updater(currentPolicy)
        next.agent_overrides[agentId] = { policy: updatedPolicy }
        return next
      })
    }

    const setSectionValue = (section, value) => {
      if (!overrideAgentId) return
      const baseline = draftPolicy?.[section] || {}
      const diff = deepDiff(baseline, value)
      setAgentOverridePolicy(overrideAgentId, (policy) => {
        const out = { ...(policy || {}) }
        if (diff === undefined) delete out[section]
        else out[section] = diff
        return out
      })
    }

    const sectionValue = (section) => deepMerge(draftPolicy?.[section] || {}, selectedPolicy[section] || {})
    const isSectionOverridden = (section) => Object.prototype.hasOwnProperty.call(selectedPolicy || {}, section)

    const updateListField = (section, field, transform = (v) => v) => {
      const raw = String(overrideListInputs?.[`${section}.${field}`] || '').trim()
      const normalized = transform(raw)
      if (!normalized) {
        setMessage('Value is required')
        return
      }
      const current = sectionValue(section)
      const list = Array.isArray(current?.[field]) ? current[field] : []
      const next = { ...(current || {}), [field]: Array.from(new Set([...list, normalized])) }
      setSectionValue(section, next)
      setOverrideListInputs((prev) => ({ ...prev, [`${section}.${field}`]: '' }))
    }

    const removeListField = (section, field, item) => {
      const current = sectionValue(section)
      const list = Array.isArray(current?.[field]) ? current[field] : []
      const next = { ...(current || {}), [field]: list.filter((x) => x !== item) }
      setSectionValue(section, next)
    }

    const toggleExpanded = (section) => {
      setOverrideExpanded((prev) => ({ ...prev, [section]: !prev[section] }))
    }

    const setInherit = (section) => {
      if (!overrideAgentId) return
      setAgentOverridePolicy(overrideAgentId, (policy) => {
        const out = { ...(policy || {}) }
        delete out[section]
        return out
      })
    }

    const setOverride = (section) => {
      if (!overrideAgentId) return
      setOverrideExpanded((prev) => ({ ...prev, [section]: true }))
    }

    const resetAgentOverrides = () => {
      if (!overrideAgentId) return
      if (!window.confirm(`Reset all override sections to inherited for "${overrideAgentId}"?`)) return
      setAgentOverridePolicy(overrideAgentId, () => ({}))
      setMessage(`All sections reset to inherited for ${overrideAgentId}`)
    }

    const showBaselineInfo = (section) => {
      const baseline = draftPolicy?.[section] || {}
      window.alert(`${AGENT_OVERRIDE_SECTION_LABELS[section]} baseline\n\n${formatHuman(baseline)}`)
    }

    const listDelta = (baseList, effectiveList) => {
      const b = Array.isArray(baseList) ? baseList : []
      const e = Array.isArray(effectiveList) ? effectiveList : []
      return {
        added: e.filter((x) => !b.includes(x)),
        removed: b.filter((x) => !e.includes(x)),
      }
    }

    const summarizeQuickDiff = () => {
      if (!overrideAgentId) return
      const lines = [`Agent policy diff for ${overrideAgentId}`]

      const addListLine = (label, delta) => {
        if (delta.added.length) lines.push(`${label}: added ${delta.added.length} (${delta.added.join(', ')})`)
        if (delta.removed.length) lines.push(`${label}: removed ${delta.removed.length} (${delta.removed.join(', ')})`)
      }
      const addScalarLine = (label, baseValue, effectiveValue) => {
        if (JSON.stringify(baseValue) !== JSON.stringify(effectiveValue)) {
          lines.push(`${label}: ${String(baseValue)} -> ${String(effectiveValue)}`)
        }
      }

      const blockedBase = draftPolicy?.blocked || {}
      const blockedEff = sectionValue('blocked')
      addListLine('Blocked commands', listDelta(blockedBase.commands, blockedEff.commands))
      addListLine('Blocked paths', listDelta(blockedBase.paths, blockedEff.paths))
      addListLine('Blocked extensions', listDelta(blockedBase.extensions, blockedEff.extensions))

      const confirmBase = draftPolicy?.requires_confirmation || {}
      const confirmEff = sectionValue('requires_confirmation')
      addListLine('Requires confirmation commands', listDelta(confirmBase.commands, confirmEff.commands))
      addListLine('Requires confirmation paths', listDelta(confirmBase.paths, confirmEff.paths))

      const simBase = draftPolicy?.requires_simulation || {}
      const simEff = sectionValue('requires_simulation')
      addListLine('Requires simulation commands', listDelta(simBase.commands, simEff.commands))
      addScalarLine('Bulk file threshold', simBase.bulk_file_threshold, simEff.bulk_file_threshold)
      addScalarLine('Simulation max retries', simBase.max_retries, simEff.max_retries)

      const allowedBase = draftPolicy?.allowed || {}
      const allowedEff = sectionValue('allowed')
      addListLine('Allowed paths whitelist', listDelta(allowedBase.paths_whitelist, allowedEff.paths_whitelist))
      addScalarLine('Allowed max files/operation', allowedBase.max_files_per_operation, allowedEff.max_files_per_operation)
      addScalarLine('Allowed max file size MB', allowedBase.max_file_size_mb, allowedEff.max_file_size_mb)
      addScalarLine('Allowed max directory depth', allowedBase.max_directory_depth, allowedEff.max_directory_depth)

      const netBase = draftPolicy?.network || {}
      const netEff = sectionValue('network')
      addScalarLine('Network enforcement mode', netBase.enforcement_mode, netEff.enforcement_mode)
      addScalarLine('Network block unknown domains', netBase.block_unknown_domains, netEff.block_unknown_domains)
      addListLine('Network commands', listDelta(netBase.commands, netEff.commands))
      addListLine('Network allowlist', listDelta(netBase.allowed_domains, netEff.allowed_domains))
      addListLine('Network blocklist', listDelta(netBase.blocked_domains, netEff.blocked_domains))

      const exeBase = draftPolicy?.execution || {}
      const exeEff = sectionValue('execution')
      addScalarLine('Execution timeout seconds', exeBase.max_command_timeout_seconds, exeEff.max_command_timeout_seconds)
      addScalarLine('Execution max output chars', exeBase.max_output_chars, exeEff.max_output_chars)
      addScalarLine('Containment mode', exeBase?.shell_workspace_containment?.mode, exeEff?.shell_workspace_containment?.mode)
      addScalarLine('Containment log_paths', exeBase?.shell_workspace_containment?.log_paths, exeEff?.shell_workspace_containment?.log_paths)
      addListLine(
        'Containment exempt commands',
        listDelta(exeBase?.shell_workspace_containment?.exempt_commands, exeEff?.shell_workspace_containment?.exempt_commands)
      )

      if (lines.length === 1) lines.push('No differences from baseline.')
      window.alert(lines.join('\n'))
    }

    return (
      <div className="space-y-3">
        <div className="bg-white border border-slate-200 rounded-[10px] p-3 shadow-sm space-y-3">
          <div className="text-sm font-semibold text-slate-800">Agent Overrides</div>
          <div className="text-xs text-slate-600">
            Baseline policy remains global. Agent overrides apply only to: <span className="font-mono">blocked, requires_confirmation, requires_simulation, allowed, network, execution</span>.
            Workspace remains controlled by MCP env (<span className="font-mono">AIRG_WORKSPACE</span>), not policy overrides.
          </div>
          <div className="grid grid-cols-1 md:grid-cols-[1fr_auto] gap-2">
            <div className="flex gap-2 items-center">
              <select
                value={overrideAgentId}
                onChange={(e) => setOverrideAgentId(e.target.value)}
                className="border border-slate-300 rounded-[10px] px-3 py-2 text-sm bg-white"
              >
                <option value="">Select agent…</option>
                {knownAgentIds.map((id) => (
                  <option key={id} value={id}>{id}</option>
                ))}
              </select>
              <span className="text-xs text-slate-500">
                Manage agent profiles in <span className="font-semibold">Settings → Agents</span>.
              </span>
            </div>
            <div className="flex gap-2 justify-end">
              <button
                onClick={summarizeQuickDiff}
                disabled={!overrideAgentId}
                className="px-3 py-1.5 rounded-[10px] border border-blue-300 text-blue-700 bg-blue-50 text-sm disabled:opacity-50"
              >
                Quick Diff
              </button>
              <button
                onClick={resetAgentOverrides}
                disabled={!overrideAgentId}
                className="px-3 py-1.5 rounded-[10px] border border-amber-300 text-amber-700 bg-amber-50 text-sm disabled:opacity-50"
              >
                Reset to Inherited
              </button>
            </div>
          </div>
          <div className="text-xs text-slate-500">
            Override sections enabled: <span className="font-mono">{overrideAgentId ? String(AGENT_OVERRIDE_SECTIONS.filter((s) => isSectionOverridden(s)).length) : '0'}</span>
          </div>
        </div>

        {!overrideAgentId && (
          <div className="bg-white border border-slate-200 rounded-[10px] p-4 shadow-sm text-sm text-slate-600">
            Select an existing agent to edit override sections. Create agents in Settings → Agents.
          </div>
        )}

        {overrideAgentId && (
          <div className="space-y-3">
            {AGENT_OVERRIDE_SECTIONS.map((section) => {
              const enabled = isSectionOverridden(section)
              const expanded = !!overrideExpanded[section]
              const effective = enabled ? 'Overridden' : 'Inherited'
              const sectionData = sectionValue(section)
              return (
                <div key={section} className="bg-white border border-slate-200 rounded-[10px] p-3 shadow-sm space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <button onClick={() => toggleExpanded(section)} className="text-sm font-semibold text-slate-800 hover:text-slate-900">
                        {expanded ? '▾' : '▸'} {AGENT_OVERRIDE_SECTION_LABELS[section]}
                      </button>
                      <span className={`text-[11px] px-2 py-0.5 rounded border ${enabled ? 'bg-blue-50 border-blue-200 text-blue-700' : 'bg-slate-50 border-slate-200 text-slate-600'}`}>
                        {effective}
                      </span>
                    </div>
                    <div className="flex gap-2 text-xs">
                      <button
                        onClick={() => showBaselineInfo(section)}
                        className="px-2 py-1 rounded border border-slate-300 bg-white text-slate-700"
                        title="Show baseline configuration"
                      >
                        ℹ️
                      </button>
                      <button
                        onClick={() => setInherit(section)}
                        className="px-2 py-1 rounded border border-slate-300 bg-white text-slate-700"
                      >
                        Inherit
                      </button>
                      <button
                        onClick={() => setOverride(section)}
                        className="px-2 py-1 rounded border border-blue-300 bg-blue-50 text-blue-700"
                      >
                        Override
                      </button>
                    </div>
                  </div>
                  {expanded && section === 'blocked' && (
                    <div className="space-y-3">
                      {['commands', 'paths', 'extensions'].map((field) => (
                        <div key={field} className="border border-slate-200 rounded-[10px] p-2 space-y-2">
                          <div className="text-xs font-semibold text-slate-700 capitalize">{field}</div>
                          <div className="flex gap-2">
                            <input
                              value={overrideListInputs[`${section}.${field}`] || ''}
                              onChange={(e) => setOverrideListInputs((prev) => ({ ...prev, [`${section}.${field}`]: e.target.value }))}
                              className="flex-1 border border-slate-300 rounded px-2 py-1 text-xs font-mono"
                            />
                            <button onClick={() => updateListField(section, field)} className="px-2 py-1 rounded bg-[#0055ff] text-white text-xs">Add</button>
                          </div>
                          <div className="flex flex-wrap gap-1">
                            {((sectionData?.[field]) || []).map((item) => (
                              <span key={item} className="inline-flex items-center gap-1 px-2 py-1 rounded border border-slate-300 bg-slate-50 text-xs font-mono">
                                {item}
                                <button onClick={() => removeListField(section, field, item)} className="text-red-600">×</button>
                              </span>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                  {expanded && section === 'allowed' && (
                    <div className="space-y-3">
                      <div className="border border-slate-200 rounded-[10px] p-2 space-y-2">
                        <div className="text-xs font-semibold text-slate-700">paths_whitelist</div>
                        <div className="flex gap-2">
                          <input value={overrideListInputs['allowed.paths_whitelist'] || ''} onChange={(e) => setOverrideListInputs((p) => ({ ...p, 'allowed.paths_whitelist': e.target.value }))} className="flex-1 border border-slate-300 rounded px-2 py-1 text-xs font-mono" />
                          <button onClick={() => updateListField('allowed', 'paths_whitelist')} className="px-2 py-1 rounded bg-[#0055ff] text-white text-xs">Add</button>
                        </div>
                        <div className="flex flex-wrap gap-1">
                          {(sectionData?.paths_whitelist || []).map((item) => <span key={item} className="inline-flex items-center gap-1 px-2 py-1 rounded border border-slate-300 bg-slate-50 text-xs font-mono">{item}<button onClick={() => removeListField('allowed', 'paths_whitelist', item)} className="text-red-600">×</button></span>)}
                        </div>
                      </div>
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                        <label className="text-xs">Max files per operation<input type="number" min={0} className="mt-1 w-full border border-slate-300 rounded px-2 py-1 text-xs" value={sectionData?.max_files_per_operation ?? 0} onChange={(e) => setSectionValue('allowed', { ...sectionData, max_files_per_operation: Math.max(0, parseInt(e.target.value, 10) || 0) })} /></label>
                        <label className="text-xs">Max file size MB<input type="number" min={0} className="mt-1 w-full border border-slate-300 rounded px-2 py-1 text-xs" value={sectionData?.max_file_size_mb ?? 0} onChange={(e) => setSectionValue('allowed', { ...sectionData, max_file_size_mb: Math.max(0, parseInt(e.target.value, 10) || 0) })} /></label>
                        <label className="text-xs">Max directory depth<input type="number" min={0} className="mt-1 w-full border border-slate-300 rounded px-2 py-1 text-xs" value={sectionData?.max_directory_depth ?? 0} onChange={(e) => setSectionValue('allowed', { ...sectionData, max_directory_depth: Math.max(0, parseInt(e.target.value, 10) || 0) })} /></label>
                      </div>
                    </div>
                  )}
                  {expanded && section === 'requires_confirmation' && (
                    <div className="space-y-3">
                      {['commands', 'paths'].map((field) => (
                        <div key={field} className="border border-slate-200 rounded-[10px] p-2 space-y-2">
                          <div className="text-xs font-semibold text-slate-700 capitalize">{field}</div>
                          <div className="flex gap-2"><input value={overrideListInputs[`${section}.${field}`] || ''} onChange={(e) => setOverrideListInputs((p) => ({ ...p, [`${section}.${field}`]: e.target.value }))} className="flex-1 border border-slate-300 rounded px-2 py-1 text-xs font-mono" /><button onClick={() => updateListField(section, field)} className="px-2 py-1 rounded bg-[#0055ff] text-white text-xs">Add</button></div>
                          <div className="flex flex-wrap gap-1">{((sectionData?.[field]) || []).map((item) => <span key={item} className="inline-flex items-center gap-1 px-2 py-1 rounded border border-slate-300 bg-slate-50 text-xs font-mono">{item}<button onClick={() => removeListField(section, field, item)} className="text-red-600">×</button></span>)}</div>
                        </div>
                      ))}
                    </div>
                  )}
                  {expanded && section === 'requires_simulation' && (
                    <div className="space-y-3">
                      <div className="border border-slate-200 rounded-[10px] p-2 space-y-2">
                        <div className="text-xs font-semibold text-slate-700">commands</div>
                        <div className="flex gap-2"><input value={overrideListInputs['requires_simulation.commands'] || ''} onChange={(e) => setOverrideListInputs((p) => ({ ...p, 'requires_simulation.commands': e.target.value }))} className="flex-1 border border-slate-300 rounded px-2 py-1 text-xs font-mono" /><button onClick={() => updateListField('requires_simulation', 'commands')} className="px-2 py-1 rounded bg-[#0055ff] text-white text-xs">Add</button></div>
                        <div className="flex flex-wrap gap-1">{((sectionData?.commands) || []).map((item) => <span key={item} className="inline-flex items-center gap-1 px-2 py-1 rounded border border-slate-300 bg-slate-50 text-xs font-mono">{item}<button onClick={() => removeListField('requires_simulation', 'commands', item)} className="text-red-600">×</button></span>)}</div>
                      </div>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                        <label className="text-xs">Bulk file threshold<input type="number" min={0} className="mt-1 w-full border border-slate-300 rounded px-2 py-1 text-xs" value={sectionData?.bulk_file_threshold ?? 0} onChange={(e) => setSectionValue('requires_simulation', { ...sectionData, bulk_file_threshold: Math.max(0, parseInt(e.target.value, 10) || 0) })} /></label>
                        <label className="text-xs">Max retries<input type="number" min={0} className="mt-1 w-full border border-slate-300 rounded px-2 py-1 text-xs" value={sectionData?.max_retries ?? 0} onChange={(e) => setSectionValue('requires_simulation', { ...sectionData, max_retries: Math.max(0, parseInt(e.target.value, 10) || 0) })} /></label>
                      </div>
                    </div>
                  )}
                  {expanded && section === 'network' && (
                    <div className="space-y-3">
                      <div className="flex gap-3 text-xs">
                        {['off', 'monitor', 'enforce'].map((mode) => <label key={mode} className="flex items-center gap-1"><input type="radio" checked={(sectionData?.enforcement_mode || 'off') === mode} onChange={() => setSectionValue('network', { ...sectionData, enforcement_mode: mode })} /> <span className="font-mono">{mode}</span></label>)}
                      </div>
                      <label className="text-xs inline-flex items-center gap-2"><input type="checkbox" checked={Boolean(sectionData?.block_unknown_domains)} onChange={(e) => setSectionValue('network', { ...sectionData, block_unknown_domains: e.target.checked })} /> block_unknown_domains</label>
                      {['commands', 'allowed_domains', 'blocked_domains'].map((field) => (
                        <div key={field} className="border border-slate-200 rounded-[10px] p-2 space-y-2">
                          <div className="text-xs font-semibold text-slate-700">{field}</div>
                          <div className="flex gap-2"><input value={overrideListInputs[`network.${field}`] || ''} onChange={(e) => setOverrideListInputs((p) => ({ ...p, [`network.${field}`]: e.target.value }))} className="flex-1 border border-slate-300 rounded px-2 py-1 text-xs font-mono" /><button onClick={() => updateListField('network', field, field.includes('domains') ? normalizeDomain : (v) => v)} className="px-2 py-1 rounded bg-[#0055ff] text-white text-xs">Add</button></div>
                          <div className="flex flex-wrap gap-1">{((sectionData?.[field]) || []).map((item) => <span key={item} className="inline-flex items-center gap-1 px-2 py-1 rounded border border-slate-300 bg-slate-50 text-xs font-mono">{item}<button onClick={() => removeListField('network', field, item)} className="text-red-600">×</button></span>)}</div>
                        </div>
                      ))}
                    </div>
                  )}
                  {expanded && section === 'execution' && (
                    <div className="space-y-3">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                        <label className="text-xs">Max command timeout seconds<input type="number" min={1} className="mt-1 w-full border border-slate-300 rounded px-2 py-1 text-xs" value={sectionData?.max_command_timeout_seconds ?? 30} onChange={(e) => setSectionValue('execution', { ...sectionData, max_command_timeout_seconds: Math.max(1, parseInt(e.target.value, 10) || 1) })} /></label>
                        <label className="text-xs">Max output chars<input type="number" min={1024} className="mt-1 w-full border border-slate-300 rounded px-2 py-1 text-xs" value={sectionData?.max_output_chars ?? 200000} onChange={(e) => setSectionValue('execution', { ...sectionData, max_output_chars: Math.max(1024, parseInt(e.target.value, 10) || 1024) })} /></label>
                      </div>
                      <div className="border border-slate-200 rounded-[10px] p-2 space-y-2">
                        <div className="text-xs font-semibold text-slate-700">shell_workspace_containment</div>
                        <div className="flex gap-3 text-xs">{['off', 'monitor', 'enforce'].map((mode) => <label key={mode} className="flex items-center gap-1"><input type="radio" checked={(sectionData?.shell_workspace_containment?.mode || 'off') === mode} onChange={() => setSectionValue('execution', { ...sectionData, shell_workspace_containment: { ...(sectionData?.shell_workspace_containment || {}), mode } })} /> <span className="font-mono">{mode}</span></label>)}</div>
                        <label className="text-xs inline-flex items-center gap-2"><input type="checkbox" checked={Boolean(sectionData?.shell_workspace_containment?.log_paths)} onChange={(e) => setSectionValue('execution', { ...sectionData, shell_workspace_containment: { ...(sectionData?.shell_workspace_containment || {}), log_paths: e.target.checked } })} /> log_paths</label>
                        <div className="flex gap-2"><input value={overrideListInputs['execution.shell_workspace_containment.exempt_commands'] || ''} onChange={(e) => setOverrideListInputs((p) => ({ ...p, 'execution.shell_workspace_containment.exempt_commands': e.target.value }))} className="flex-1 border border-slate-300 rounded px-2 py-1 text-xs font-mono" /><button onClick={() => {
                          const raw = String(overrideListInputs['execution.shell_workspace_containment.exempt_commands'] || '').trim()
                          if (!raw) return
                          const current = sectionData?.shell_workspace_containment || {}
                          const nextList = Array.from(new Set([...(current.exempt_commands || []), raw]))
                          setSectionValue('execution', { ...sectionData, shell_workspace_containment: { ...current, exempt_commands: nextList } })
                          setOverrideListInputs((p) => ({ ...p, 'execution.shell_workspace_containment.exempt_commands': '' }))
                        }} className="px-2 py-1 rounded bg-[#0055ff] text-white text-xs">Add exempt command</button></div>
                        <div className="flex flex-wrap gap-1">{((sectionData?.shell_workspace_containment?.exempt_commands) || []).map((item) => <span key={item} className="inline-flex items-center gap-1 px-2 py-1 rounded border border-slate-300 bg-slate-50 text-xs font-mono">{item}<button onClick={() => {
                          const current = sectionData?.shell_workspace_containment || {}
                          const nextList = (current.exempt_commands || []).filter((x) => x !== item)
                          setSectionValue('execution', { ...sectionData, shell_workspace_containment: { ...current, exempt_commands: nextList } })
                        }} className="text-red-600">×</button></span>)}</div>
                      </div>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </div>
    )
  }

  function PolicyPanel() {
    return (
      <>
        {activePolicyTab === 'commands' && CommandsPanel()}
        {activePolicyTab === 'paths' && PathsPanel()}
        {activePolicyTab === 'extensions' && ExtensionsPanel()}
        {activePolicyTab === 'network' && NetworkPanel()}
        {activePolicyTab === 'agent_overrides' && AgentOverridesPanel()}
        {activePolicyTab === 'advanced' && AdvancedPolicyPanel()}
        <div className="mt-4 bg-white border border-slate-200 rounded-[10px] p-3 shadow-sm">
          <button onClick={() => setJsonOpen((x) => !x)} className="text-sm font-medium text-slate-700">
            {jsonOpen ? '▾' : '▸'} Advanced JSON
          </button>
          {jsonOpen && (
            <textarea
              value={jsonText}
              onChange={(e) => onJsonChange(e.target.value)}
              className="mt-3 w-full h-72 border border-slate-300 rounded-[10px] p-3 font-mono text-xs"
            />
          )}
          {jsonError && <div className="mt-2 text-sm text-red-600">{jsonError}</div>}
        </div>
      </>
    )
  }

  function SettingsPanel() {
    const postureRows = agentPosture?.profiles || []
    const postureTotals = agentPosture?.totals || { green: 0, yellow: 0, red: 0 }
    const postureDiscovered = agentPosture?.discovered_unregistered || []
    const sentinelArtifacts = scriptSentinelData?.artifacts?.items || []
    const sentinelSummary = scriptSentinelData?.summary || null
    const postureStatusLabel = {
      green: 'Hardened',
      yellow: 'Partial',
      red: 'Unprotected',
    }
    const workspaceHints = Array.from(
      new Set(
        [runtimePaths.AIRG_WORKSPACE, ...agentProfiles.map((p) => p.workspace || '')]
          .map((v) => String(v || '').trim())
          .filter(Boolean)
      )
    )

    const updateProfile = (profileId, patch) => {
      setAgentProfiles((prev) =>
        prev.map((item) => (item.profile_id === profileId ? { ...item, ...patch } : item))
      )
    }

    const profileComparable = (profile) => ({
      name: String(profile?.name || '').trim(),
      agent_type: String(profile?.agent_type || '').trim(),
      agent_id: String(profile?.agent_id || '').trim(),
      workspace: String(profile?.workspace || '').trim(),
    })

    const isProfileDirty = (profile) => {
      const id = String(profile?.profile_id || '').trim()
      const saved = settingsSavedProfiles[id]
      if (!saved) {
        return Boolean(
          String(profile?.name || '').trim() ||
          String(profile?.agent_id || '').trim() ||
          String(profile?.workspace || '').trim()
        )
      }
      return JSON.stringify(profileComparable(profile)) !== JSON.stringify(saved)
    }

    const addProfileRow = () => {
      setAgentProfiles((prev) => [...prev, emptyProfile()])
    }

    const duplicateAgentIdForProfile = (profile) => {
      const currentId = String(profile?.agent_id || '').trim()
      const currentProfileId = String(profile?.profile_id || '').trim()
      if (!currentId) return ''
      const duplicate = (agentProfiles || []).some((item) => {
        const otherProfileId = String(item?.profile_id || '').trim()
        const otherAgentId = String(item?.agent_id || '').trim()
        if (!otherAgentId) return false
        if (otherProfileId === currentProfileId) return false
        return otherAgentId === currentId
      })
      return duplicate ? currentId : ''
    }

    const saveRow = async (profile) => {
      setSettingsLoading(true)
      setSettingsError('')
      const duplicateId = duplicateAgentIdForProfile(profile)
      if (duplicateId) {
        setSettingsError(`Duplicate agent_id: ${duplicateId}. Agent IDs must be unique.`)
        setSettingsLoading(false)
        return
      }
      const profileId = String(profile?.profile_id || '')
      const dirtyBeforeSave = isProfileDirty(profile)
      const hadSavedConfig = Boolean(profile?.last_saved_path)
      try {
        await upsertSettingsProfile(profile)
        await generateAgentConfig(profile.profile_id, true)
        if (profileId === 'default-agent') {
          const reconfig = await reconfigureRuntimeProfile(profileId)
          if (reconfig.runtime_env_updated) {
            setSettingsError('Runtime defaults updated. Restart airg-ui service and reconfigure MCP for affected agents.')
          }
        }
        if (hadSavedConfig && dirtyBeforeSave) {
          setSettingsNeedsReconfigure((prev) => ({ ...prev, [profileId]: true }))
        }
        setMessage('Profile saved and config generated')
      } catch (err) {
        const payload = err?.payload
        if (payload?.workspace_missing && payload?.workspace) {
          const ok = window.confirm(`Workspace does not exist:\n${payload.workspace}\n\nCreate this directory now?`)
          if (ok) {
            try {
              await upsertSettingsProfile(profile, { createWorkspace: true })
              await generateAgentConfig(profile.profile_id, true)
              if (profileId === 'default-agent') {
                const reconfig = await reconfigureRuntimeProfile(profileId)
                if (reconfig.runtime_env_updated) {
                  setSettingsError('Runtime defaults updated. Restart airg-ui service and reconfigure MCP for affected agents.')
                }
              }
              if (hadSavedConfig && dirtyBeforeSave) {
                setSettingsNeedsReconfigure((prev) => ({ ...prev, [profileId]: true }))
              }
              setMessage('Profile saved, workspace created, and config generated')
              setSettingsError('')
            } catch (innerErr) {
              setSettingsError(String(innerErr.message || innerErr))
            }
          } else {
            setSettingsError(String(err.message || err))
          }
        } else {
          setSettingsError(String(err.message || err))
        }
      } finally {
        setSettingsLoading(false)
      }
    }

    const copyJson = async (profile) => {
      setSettingsLoading(true)
      setSettingsError('')
      const duplicateId = duplicateAgentIdForProfile(profile)
      if (duplicateId) {
        setSettingsError(`Duplicate agent_id: ${duplicateId}. Agent IDs must be unique.`)
        setSettingsLoading(false)
        return
      }
      try {
        await upsertSettingsProfile(profile)
        const payload = await generateAgentConfig(profile.profile_id, false)
        setCopyAssistModal({
          open: true,
          title: 'Copy JSON Configuration',
          content: JSON.stringify(payload.generated?.file_json || {}, null, 2),
        })
      } catch (err) {
        setSettingsError(String(err.message || err))
      } finally {
        setSettingsLoading(false)
      }
    }

    const copyCli = async (profile) => {
      setSettingsLoading(true)
      setSettingsError('')
      const duplicateId = duplicateAgentIdForProfile(profile)
      if (duplicateId) {
        setSettingsError(`Duplicate agent_id: ${duplicateId}. Agent IDs must be unique.`)
        setSettingsLoading(false)
        return
      }
      try {
        await upsertSettingsProfile(profile)
        const payload = await generateAgentConfig(profile.profile_id, false)
        setCopyAssistModal({
          open: true,
          title: 'Copy CLI Command',
          content: String(payload.generated?.command_text || ''),
        })
      } catch (err) {
        setSettingsError(String(err.message || err))
      } finally {
        setSettingsLoading(false)
      }
    }

    const openConfig = async (profile) => {
      setSettingsLoading(true)
      setSettingsError('')
      try {
        const opened = await openSavedConfigFile(profile.profile_id)
        const blob = new Blob([opened.file_content || ''], { type: 'application/json' })
        const url = URL.createObjectURL(blob)
        const win = window.open(url, '_blank', 'noopener,noreferrer')
        if (!win) {
          const a = document.createElement('a')
          a.href = url
          a.download = opened.file_path.split('/').pop() || 'airg-mcp-config.json'
          document.body.appendChild(a)
          a.click()
          document.body.removeChild(a)
        }
        setTimeout(() => URL.revokeObjectURL(url), 5000)
        setMessage('Opened configuration file')
      } catch (err) {
        setSettingsError(String(err.message || err))
      } finally {
        setSettingsLoading(false)
      }
    }

    const showInfo = async (profile) => {
      setSettingsLoading(true)
      setSettingsError('')
      try {
        await upsertSettingsProfile(profile)
        const payload = await generateAgentConfig(profile.profile_id, false)
        window.alert(payload.generated?.instructions || 'No instructions available.')
      } catch (err) {
        setSettingsError(String(err.message || err))
      } finally {
        setSettingsLoading(false)
      }
    }

    const deleteRow = async (profile) => {
      if (!window.confirm(`Delete profile "${profile.name || profile.agent_id || profile.profile_id}"?`)) return
      const isUnsavedLocalRow =
        !String(profile.name || '').trim() &&
        !String(profile.agent_id || '').trim() &&
        !String(profile.workspace || '').trim() &&
        !String(profile.last_generated_at || '').trim() &&
        !String(profile.last_saved_path || '').trim()
      if (isUnsavedLocalRow) {
        setAgentProfiles((prev) => prev.filter((item) => item.profile_id !== profile.profile_id))
        setMessage('Unsaved profile removed')
        return
      }
      setSettingsLoading(true)
      setSettingsError('')
      try {
        await deleteSettingsProfile(profile.profile_id)
        setSettingsNeedsReconfigure((prev) => {
          const out = { ...prev }
          delete out[profile.profile_id]
          return out
        })
        setMessage('Profile deleted')
      } catch (err) {
        const msg = String(err.message || err)
        if (msg.toLowerCase().includes('profile not found')) {
          setAgentProfiles((prev) => prev.filter((item) => item.profile_id !== profile.profile_id))
          setMessage('Profile removed')
        } else {
          setSettingsError(msg)
        }
      } finally {
        setSettingsLoading(false)
      }
    }

    const setProfileActionLoading = (profileId, value) => {
      setAgentConfigActionLoading((prev) => ({ ...prev, [profileId]: value }))
    }

    const applyHardeningForProfile = async (row, { autoAddMcp = false } = {}) => {
      const profileId = String(row?.profile_id || '').trim()
      if (!profileId) return
      setProfileActionLoading(profileId, true)
      setSettingsError('')
      try {
        const payload = await applyAgentConfigHardening(profileId, { autoAddMcp })
        const diffSummary = Array.isArray(payload?.diff_summary) ? payload.diff_summary : []
        setMessage(`Hardening applied for ${row?.name || row?.agent_id || profileId}`)
        setCopyAssistModal({
          open: true,
          title: `Hardening Diff · ${row?.name || row?.agent_id || profileId}`,
          content: diffSummary.length ? diffSummary.join('\n') : 'No visible diff. Target files already matched AIRG hardening baseline.',
        })
      } catch (err) {
        const payload = err?.payload || {}
        if (payload?.requires_mcp) {
          const confirmAutoAdd = window.confirm(
            `AIRG MCP server was not detected for ${row?.name || row?.agent_id || profileId}.\n\nAdd AIRG MCP to workspace .mcp.json and continue?`
          )
          if (confirmAutoAdd) {
            try {
              const retry = await applyAgentConfigHardening(profileId, { autoAddMcp: true })
              const diffSummary = Array.isArray(retry?.diff_summary) ? retry.diff_summary : []
              setMessage(`Hardening applied for ${row?.name || row?.agent_id || profileId} (MCP auto-added)`)
              setCopyAssistModal({
                open: true,
                title: `Hardening Diff · ${row?.name || row?.agent_id || profileId}`,
                content: diffSummary.length ? diffSummary.join('\n') : 'No visible diff. Target files already matched AIRG hardening baseline.',
              })
            } catch (retryErr) {
              setSettingsError(String(retryErr.message || retryErr))
            }
          } else {
            setSettingsError(String(err.message || err))
          }
        } else {
          setSettingsError(String(err.message || err))
        }
      } finally {
        setProfileActionLoading(profileId, false)
      }
    }

    const undoHardeningForProfile = async (row) => {
      const profileId = String(row?.profile_id || '').trim()
      if (!profileId) return
      if (!window.confirm(`Undo last AIRG hardening apply for ${row?.name || row?.agent_id || profileId}?`)) return
      setProfileActionLoading(profileId, true)
      setSettingsError('')
      try {
        const payload = await undoAgentConfigHardening(profileId)
        setMessage(`Undo completed for ${row?.name || row?.agent_id || profileId}`)
        setCopyAssistModal({
          open: true,
          title: `Hardening Undo · ${row?.name || row?.agent_id || profileId}`,
          content: `Restored ${payload?.undone_changes || 0} file change(s) from AIRG backup state.`,
        })
      } catch (err) {
        setSettingsError(String(err.message || err))
      } finally {
        setProfileActionLoading(profileId, false)
      }
    }

    const hookSnippet = `{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          { "type": "command", "command": "airg-hook" }
        ]
      }
    ]
  }
}`

    const claudeHardenSnippet = `{
  "permissions": {
    "deny": ["Bash", "Write", "Edit", "MultiEdit"],
    "allow": [
      "mcp__ai-runtime-guard__execute_command",
      "mcp__ai-runtime-guard__write_file",
      "mcp__ai-runtime-guard__read_file",
      "mcp__ai-runtime-guard__list_directory",
      "mcp__ai-runtime-guard__restore_backup",
      "Read",
      "Glob",
      "Grep",
      "LS",
      "Task",
      "WebSearch"
    ]
  },
  "sandbox": {
    "enabled": true,
    "allowUnsandboxedCommands": false
  }
}`

    if (activeSettingsTab === 'advanced') {
      return (
        <div className="bg-white border border-slate-200 rounded-[10px] p-6 shadow-sm text-slate-600 text-sm">
          <div className="font-semibold text-slate-800 mb-2">Advanced Settings</div>
          <div>This section is reserved for future global settings and adapter behavior controls.</div>
        </div>
      )
    }

    return (
      <div className="space-y-4">
        <div className="bg-white border border-slate-200 rounded-[10px] p-4 shadow-sm">
          <div className="flex items-center justify-between mb-3">
            <div>
              <div className="text-sm font-semibold text-slate-800">Configured Agents</div>
              <div className="text-xs text-slate-500">Save generates and stores MCP config in runtime state.</div>
            </div>
            <button onClick={addProfileRow} className="px-3 py-1.5 rounded-[10px] border border-slate-300 text-sm bg-white hover:bg-slate-50">Add Agent</button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-sm border-collapse">
              <thead>
                <tr className="text-left text-xs text-slate-500 border-b border-slate-200">
                  <th className="py-2 pr-2">Agent Type</th>
                  <th className="py-2 px-2">Profile Name</th>
                  <th className="py-2 px-2">Agent ID</th>
                  <th className="py-2 px-2">Workspace</th>
                  <th className="py-2 px-2 text-center"><div className="flex justify-center"><UiIcon kind="save" /></div></th>
                  <th className="py-2 px-2 text-center"><div className="flex justify-center"><UiIcon kind="folder" /></div></th>
                  <th className="py-2 px-2 text-center"><div className="flex items-center justify-center gap-1"><UiIcon kind="copy" /><span>JSON</span></div></th>
                  <th className="py-2 px-2 text-center"><div className="flex items-center justify-center gap-1"><UiIcon kind="terminal" /><span>CLI</span></div></th>
                  <th className="py-2 px-2 text-center"><div className="flex justify-center"><UiIcon kind="info" /></div></th>
                  <th className="py-2 pl-3 text-center border-l-2 border-slate-300"><div className="flex justify-center"><UiIcon kind="trash" /></div></th>
                </tr>
              </thead>
              <tbody>
                {agentProfiles.map((profile) => {
                  const configured = Boolean(profile.last_saved_path)
                  const dirty = isProfileDirty(profile)
                  const needsReconfigure = Boolean(settingsNeedsReconfigure[profile.profile_id])
                  return (
                    <tr key={profile.profile_id} className={`border-b border-slate-100 ${configured ? 'bg-slate-50' : 'bg-white'}`}>
                      <td className="py-2 pr-2 align-top">
                        <select
                          className="w-full border border-slate-300 rounded px-2 py-1 text-xs"
                          value={profile.agent_type || 'claude_code'}
                          onChange={(e) => updateProfile(profile.profile_id, { agent_type: e.target.value })}
                        >
                          {agentTypes.map((opt) => <option key={opt.id} value={opt.id}>{opt.label}</option>)}
                        </select>
                      </td>
                      <td className="py-2 px-2 align-top">
                        <input
                          type="text"
                          className="w-full border border-slate-300 rounded px-2 py-1 text-xs"
                          value={profile.name || ''}
                          onChange={(e) => updateProfile(profile.profile_id, { name: e.target.value })}
                        />
                      </td>
                      <td className="py-2 px-2 align-top">
                        <input
                          type="text"
                          className="w-full border border-slate-300 rounded px-2 py-1 text-xs font-mono"
                          value={profile.agent_id || ''}
                          onChange={(e) => updateProfile(profile.profile_id, { agent_id: e.target.value })}
                        />
                      </td>
                      <td className="py-2 px-2 align-top">
                        <div className="flex gap-1">
                          <input
                            list={`workspace-hints-${profile.profile_id}`}
                            type="text"
                            className="w-full border border-slate-300 rounded px-2 py-1 text-xs font-mono"
                            value={profile.workspace || ''}
                            onChange={(e) => updateProfile(profile.profile_id, { workspace: e.target.value })}
                          />
                          <datalist id={`workspace-hints-${profile.profile_id}`}>
                            {workspaceHints.map((hint) => <option key={hint} value={hint} />)}
                          </datalist>
                          <button
                            title="Use current AIRG workspace"
                            className="px-2 py-1 border border-slate-300 rounded text-xs bg-white hover:bg-slate-50"
                            onClick={() => updateProfile(profile.profile_id, { workspace: runtimePaths.AIRG_WORKSPACE || profile.workspace || '' })}
                          >
                            ↺
                          </button>
                        </div>
                        {profile.last_generated_at && (
                          <div className="text-[10px] text-slate-500 mt-1">Last generated {relativeTime(profile.last_generated_at)}</div>
                        )}
                        {dirty && (
                          <div className="text-[10px] text-amber-700 mt-1">Unsaved changes for this profile.</div>
                        )}
                        {needsReconfigure && (
                          <div className="text-[10px] text-blue-700 mt-1">MCP reconfiguration required for this agent after profile changes.</div>
                        )}
                      </td>
                      <td className="py-2 px-2 text-center align-top">
                        <button className="px-2 py-1 border border-slate-300 rounded-[10px] bg-white hover:bg-slate-50" onClick={() => saveRow(profile)} title="Save + generate + store">
                          <UiIcon kind="save" />
                        </button>
                      </td>
                      <td className="py-2 px-2 text-center align-top">
                        <button className="px-2 py-1 border border-slate-300 rounded-[10px] bg-white hover:bg-slate-50 disabled:opacity-50" onClick={() => openConfig(profile)} disabled={!profile.last_saved_path} title="Open configuration file">
                          <UiIcon kind="folder" />
                        </button>
                      </td>
                      <td className="py-2 px-2 text-center align-top">
                        <button className="px-2 py-1 border border-slate-300 rounded-[10px] bg-white hover:bg-slate-50" onClick={() => copyJson(profile)} title="Copy JSON to clipboard">
                          <UiIcon kind="copy" />
                        </button>
                      </td>
                      <td className="py-2 px-2 text-center align-top">
                        <button className="px-2 py-1 border border-slate-300 rounded-[10px] bg-white hover:bg-slate-50" onClick={() => copyCli(profile)} title="Copy CLI command to clipboard">
                          <UiIcon kind="terminal" />
                        </button>
                      </td>
                      <td className="py-2 px-2 text-center align-top">
                        <button className="px-2 py-1 border border-slate-300 rounded-[10px] bg-white hover:bg-slate-50" onClick={() => showInfo(profile)} title="Show instructions">
                          <UiIcon kind="info" />
                        </button>
                      </td>
                      <td className="py-2 pl-3 text-center border-l-2 border-slate-300 align-top">
                        <button className="px-2 py-1 border border-red-300 text-red-700 rounded-[10px] bg-red-50 hover:bg-red-100" onClick={() => deleteRow(profile)} title="Delete profile">
                          <UiIcon kind="trash" className="w-4 h-4" />
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>

          {!agentProfiles.length && (
            <div className="text-sm text-slate-500 py-6 text-center">No configured agents yet. Click Add Agent to create one.</div>
          )}

          <div className="text-xs text-slate-500 mt-3">
            Profile Storage Location: <span className="font-mono">{settingsConfigsDir || '-'}</span>
          </div>
          {settingsError && <div className="text-sm text-red-600 mt-2">{settingsError}</div>}
        </div>

        <div className="bg-white border border-slate-200 rounded-[10px] p-4 shadow-sm">
          <div className="flex items-center justify-between mb-3">
            <div>
              <div className="text-sm font-semibold text-slate-800">Agent Security Posture</div>
              <div className="text-xs text-slate-500">Detection plus safe apply/undo for supported agent config targets.</div>
            </div>
            <button
              onClick={fetchAgentPosture}
              className="px-3 py-1.5 rounded-[10px] border border-slate-300 text-xs bg-white hover:bg-slate-50"
              disabled={agentPostureLoading}
            >
              {agentPostureLoading ? 'Refreshing…' : 'Refresh'}
            </button>
          </div>

          <div className="flex flex-wrap gap-2 mb-3">
            <span className="badge badge-allowed">Green: {postureTotals.green || 0}</span>
            <span className="badge badge-pending">Yellow: {postureTotals.yellow || 0}</span>
            <span className="badge badge-blocked">Red: {postureTotals.red || 0}</span>
          </div>

          {agentPostureError && <div className="text-sm text-red-600 mb-2">{agentPostureError}</div>}

          <div className="posture-grid">
            {postureRows.map((row, idx) => {
              const status = String(row?.status || 'red').toLowerCase()
              const signals = row?.signals || {}
              const boolSignals = Object.entries(signals).filter(([, v]) => typeof v === 'boolean')
              return (
                <div key={`posture-${row.profile_id || row.agent_id || idx}`} className={`posture-card ${status}`}>
                  <div className="posture-card-header">
                    <div>
                      <span className="agent-name">{row.name || row.profile_id || 'Unnamed Agent'}</span>
                      <span className="agent-type">{row.agent_type || 'unknown'}</span>
                      <div className="text-[11px] text-[var(--text-tertiary)] font-mono mt-1">{row.agent_id || '-'}</div>
                      <div className="text-[11px] text-[var(--text-secondary)] font-mono break-all">{row.workspace || '-'}</div>
                    </div>
                    <span className={`posture-badge ${status}`}>
                      {postureStatusLabel[status] || 'Unprotected'}
                    </span>
                  </div>

                  <div className="text-[11px] text-[var(--text-secondary)] mb-3">{row.rationale || ''}</div>
                  <div className="posture-signals">
                    {boolSignals.map(([k, v]) => (
                      <span key={`${row.profile_id}-${k}`} className="signal-indicator">
                        <span className={`dot ${v ? 'active' : 'inactive'}`} />
                        <span>{k.replaceAll('_', ' ')}</span>
                      </span>
                    ))}
                  </div>

                  {Array.isArray(row?.missing_controls) && row.missing_controls.length > 0 && (
                    <div className="posture-recommendations mt-2">
                      {row.missing_controls.map((item) => (
                        <span key={`${row.profile_id}-${item}`} className="recommendation-chip">{item}</span>
                      ))}
                    </div>
                  )}

                  {['claude_code', 'claude_desktop', 'cursor'].includes(String(row?.agent_type || '').toLowerCase()) && (
                    <div className="mt-3 flex flex-wrap gap-2">
                      <button
                        onClick={() => applyHardeningForProfile(row)}
                        className="px-2 py-1 border border-slate-300 rounded text-xs bg-white hover:bg-slate-50 disabled:opacity-50"
                        disabled={Boolean(agentConfigActionLoading[row.profile_id])}
                      >
                        {agentConfigActionLoading[row.profile_id] ? 'Applying…' : 'Apply Hardening'}
                      </button>
                      <button
                        onClick={() => undoHardeningForProfile(row)}
                        className="px-2 py-1 border border-slate-300 rounded text-xs bg-white hover:bg-slate-50 disabled:opacity-50"
                        disabled={Boolean(agentConfigActionLoading[row.profile_id]) || !Boolean(row?.undo_available)}
                      >
                        Undo Last Apply
                      </button>
                    </div>
                  )}
                </div>
              )
            })}
          </div>

          {!postureRows.length && !agentPostureLoading && <div className="text-sm text-slate-500 py-4 text-center">No posture data available yet.</div>}

          <div className="mt-3 pt-3 border-t border-slate-200">
            <div className="text-xs font-semibold text-slate-600 uppercase tracking-wide mb-2">Claude Hook Setup Snippet</div>
            <pre className="text-[11px] font-mono whitespace-pre-wrap break-all bg-slate-50 border border-slate-200 rounded p-2 mb-2">{hookSnippet}</pre>
            <div className="flex flex-wrap gap-2 mb-2">
              <button
                onClick={() => setCopyAssistModal({ open: true, title: 'Claude Hook Setup Snippet', content: hookSnippet })}
                className="px-2 py-1 border border-slate-300 rounded text-xs bg-white hover:bg-slate-50"
              >
                Copy Hook Snippet
              </button>
              <button
                onClick={() => setCopyAssistModal({ open: true, title: 'Claude Baseline Hardening Snippet', content: claudeHardenSnippet })}
                className="px-2 py-1 border border-slate-300 rounded text-xs bg-white hover:bg-slate-50"
              >
                Copy Hardening Snippet
              </button>
            </div>
            <div className="text-xs text-slate-500 mb-3">Dev2 can apply/undo baseline hardening directly for supported profiles. Keep snippets for manual review/customization.</div>
          </div>

          <div className="mt-1 pt-3 border-t border-slate-200">
            <div className="text-xs font-semibold text-slate-600 uppercase tracking-wide mb-2">Recommended Next Actions</div>
            {postureRows.length ? (
              <div className="space-y-2 mb-3">
                {postureRows.map((row, idx) => (
                  <div key={`advice-${row.profile_id || idx}`} className="text-xs border border-slate-200 rounded px-2 py-1 bg-slate-50">
                    <div className="font-medium text-slate-700 mb-1">{row.name || row.profile_id || row.agent_id || 'Agent'}</div>
                    {Array.isArray(row?.recommended_actions) && row.recommended_actions.length ? (
                      row.recommended_actions.map((line, ix) => (
                        <div key={`${row.profile_id || idx}-line-${ix}`} className="text-slate-600">- {line}</div>
                      ))
                    ) : (
                      <div className="text-slate-500">No recommendations.</div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-xs text-slate-500 mb-3">No posture rows available.</div>
            )}
          </div>

          <div className="mt-1 pt-3 border-t border-slate-200">
            <div className="text-xs font-semibold text-slate-600 uppercase tracking-wide mb-2">Unregistered Agent Configs Detected</div>
            {postureDiscovered.length ? (
              <div className="space-y-1">
                {postureDiscovered.map((item, idx) => (
                  <div key={`${item.path}-${idx}`} className="text-xs border border-slate-200 rounded px-2 py-1 bg-slate-50">
                    <span className="font-medium text-slate-700">{item.agent_type || 'agent'}</span>
                    <span className="text-slate-500"> ({item.scope || 'unknown'})</span>
                    <div className="font-mono text-[11px] text-slate-600 break-all">{item.path}</div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-xs text-slate-500">No additional config files detected outside registered profiles.</div>
            )}
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-[10px] p-4 shadow-sm">
          <div className="flex items-center justify-between mb-3">
            <div>
              <div className="text-sm font-semibold text-slate-800">Script Sentinel</div>
              <div className="text-xs text-slate-500">Policy-intent continuity for script-mediated command execution.</div>
            </div>
            <button
              onClick={fetchScriptSentinel}
              className="px-3 py-1.5 rounded-[10px] border border-slate-300 text-xs bg-white hover:bg-slate-50"
              disabled={scriptSentinelLoading}
            >
              {scriptSentinelLoading ? 'Refreshing…' : 'Refresh'}
            </button>
          </div>

          {sentinelSummary && (
            <div className="grid grid-cols-2 md:grid-cols-6 gap-2 mb-3 text-xs">
              <div className="border border-slate-200 rounded px-2 py-1 bg-slate-50">Flagged: <span className="font-semibold">{sentinelSummary.flagged_artifacts || 0}</span></div>
              <div className="border border-slate-200 rounded px-2 py-1 bg-slate-50">Checks(24h): <span className="font-semibold">{sentinelSummary.total_checks || 0}</span></div>
              <div className="border border-slate-200 rounded px-2 py-1 bg-slate-50">Blocked: <span className="font-semibold">{sentinelSummary.blocked || 0}</span></div>
              <div className="border border-slate-200 rounded px-2 py-1 bg-slate-50">Needs Approval: <span className="font-semibold">{sentinelSummary.requires_confirmation || 0}</span></div>
              <div className="border border-slate-200 rounded px-2 py-1 bg-slate-50">Trusted: <span className="font-semibold">{sentinelSummary.trusted_allowances || 0}</span></div>
              <div className="border border-slate-200 rounded px-2 py-1 bg-slate-50">Dismissed Once: <span className="font-semibold">{sentinelSummary.one_time_allowances || 0}</span></div>
            </div>
          )}

          {scriptSentinelError && <div className="text-sm text-red-600 mb-2">{scriptSentinelError}</div>}

          <div className="overflow-x-auto">
            <table className="w-full text-xs border-collapse">
              <thead>
                <tr className="text-left text-slate-500 border-b border-slate-200">
                  <th className="py-2 pr-2">Path</th>
                  <th className="py-2 px-2">Hash</th>
                  <th className="py-2 px-2">Matched Signatures</th>
                  <th className="py-2 px-2">Last Seen</th>
                  <th className="py-2 px-2 text-center">Actions</th>
                </tr>
              </thead>
              <tbody>
                {sentinelArtifacts.map((item) => {
                  const hash = String(item.content_hash || '')
                  const onceKey = `once:${hash}`
                  const trustKey = `persistent:${hash}`
                  const signatures = Array.isArray(item.matched_signatures) ? item.matched_signatures : []
                  const signaturePreview = signatures
                    .map((sig) => String(sig?.pattern || sig?.normalized_pattern || ''))
                    .filter(Boolean)
                    .slice(0, 4)
                    .join(', ')
                  return (
                    <tr key={`${item.path}:${hash}`} className="border-b border-slate-100">
                      <td className="py-2 pr-2 font-mono break-all">{item.path}</td>
                      <td className="py-2 px-2 font-mono break-all">{hash}</td>
                      <td className="py-2 px-2 text-slate-600">{signaturePreview || '-'}</td>
                      <td className="py-2 px-2 text-slate-600">{relativeTime(item.path_last_seen_ts || item.last_seen_ts || '')}</td>
                      <td className="py-2 px-2">
                        <div className="flex items-center justify-center gap-2">
                          <button
                            onClick={() => scriptSentinelAllowance(hash, 'once')}
                            className="px-2 py-1 border border-slate-300 rounded bg-white hover:bg-slate-50 disabled:opacity-50"
                            disabled={Boolean(scriptSentinelActionLoading[onceKey])}
                          >
                            Dismiss Once
                          </button>
                          <button
                            onClick={() => scriptSentinelAllowance(hash, 'persistent')}
                            className="px-2 py-1 border border-slate-300 rounded bg-white hover:bg-slate-50 disabled:opacity-50"
                            disabled={Boolean(scriptSentinelActionLoading[trustKey])}
                          >
                            Trust Artifact
                          </button>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>

          {!sentinelArtifacts.length && !scriptSentinelLoading && (
            <div className="text-xs text-slate-500 mt-2">No flagged script artifacts recorded yet.</div>
          )}
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
        <div className="bg-white rounded-[10px] border border-slate-200 shadow-lg w-full max-w-lg" onClick={(e) => e.stopPropagation()}>
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

  function CommandEditModal() {
    if (!commandEditModal.open) return null
    const nonAllTabs = tabDefs.filter((t) => t.id !== 'all')
    return (
      <div className="fixed inset-0 z-30 bg-slate-900/40 flex items-center justify-center p-4" onClick={() => setCommandEditModal({ open: false, original: '', command: '', description: '', tabIds: [] })}>
        <div className="bg-white rounded-[10px] border border-slate-200 shadow-lg w-full max-w-2xl" onClick={(e) => e.stopPropagation()}>
          <div className="px-4 py-3 border-b border-slate-200 flex items-center justify-between">
            <div className="font-semibold text-slate-800">Edit Command</div>
            <button className="text-slate-500 hover:text-slate-700" onClick={() => setCommandEditModal({ open: false, original: '', command: '', description: '', tabIds: [] })}>✕</button>
          </div>
          <div className="p-4 space-y-3 text-sm">
            <label className="block">
              <div className="text-xs uppercase tracking-wide text-slate-500 mb-1">Command</div>
              <input
                value={commandEditModal.command}
                onChange={(e) => setCommandEditModal((prev) => ({ ...prev, command: e.target.value }))}
                className="w-full border border-slate-300 rounded-[10px] px-3 py-2 font-mono text-xs"
              />
            </label>
            <label className="block">
              <div className="text-xs uppercase tracking-wide text-slate-500 mb-1">Description</div>
              <input
                value={commandEditModal.description}
                onChange={(e) => setCommandEditModal((prev) => ({ ...prev, description: e.target.value }))}
                className="w-full border border-slate-300 rounded-[10px] px-3 py-2 text-sm"
                placeholder="Description/comment shown in info modal"
              />
            </label>
            <div>
              <div className="text-xs uppercase tracking-wide text-slate-500 mb-1">Categories</div>
              <div className="flex flex-wrap gap-2">
                {nonAllTabs.map((tab) => (
                  <label key={tab.id} className="text-xs border border-slate-300 rounded px-2 py-1 bg-slate-50 flex items-center gap-1">
                    <input
                      type="checkbox"
                      checked={commandEditModal.tabIds.includes(tab.id)}
                      onChange={(e) => {
                        setCommandEditModal((prev) => ({
                          ...prev,
                          tabIds: e.target.checked
                            ? Array.from(new Set([...(prev.tabIds || []), tab.id]))
                            : (prev.tabIds || []).filter((x) => x !== tab.id),
                        }))
                      }}
                    />
                    <span>{tab.label}</span>
                  </label>
                ))}
              </div>
            </div>
          </div>
          <div className="px-4 py-3 border-t border-slate-200 flex justify-end gap-2">
            <button
              className="px-3 py-1.5 rounded-[10px] border border-slate-300 text-slate-700"
              onClick={() => setCommandEditModal({ open: false, original: '', command: '', description: '', tabIds: [] })}
            >
              Cancel
            </button>
            <button className="px-3 py-1.5 rounded-[10px] bg-[#0055ff] text-white" onClick={saveCommandEdit}>
              Save
            </button>
          </div>
        </div>
      </div>
    )
  }

  function ValidationErrorModal() {
    if (!validationErrorModal.open) return null
    return (
      <div
        className="fixed inset-0 z-30 bg-slate-900/40 flex items-center justify-center p-4"
        onClick={() => setValidationErrorModal({ open: false, title: '', details: '' })}
      >
        <div className="bg-white rounded-[10px] border border-slate-200 shadow-lg w-full max-w-2xl" onClick={(e) => e.stopPropagation()}>
          <div className="px-4 py-3 border-b border-slate-200 flex items-center justify-between">
            <div className="font-semibold text-red-700">{validationErrorModal.title || 'Validation Error'}</div>
            <button className="text-slate-500 hover:text-slate-700" onClick={() => setValidationErrorModal({ open: false, title: '', details: '' })}>✕</button>
          </div>
          <div className="p-4">
            <pre className="text-xs font-mono whitespace-pre-wrap break-all bg-slate-50 border border-slate-200 rounded p-3">
              {validationErrorModal.details || 'No details returned from backend.'}
            </pre>
          </div>
        </div>
      </div>
    )
  }

  function CopyAssistModal() {
    if (!copyAssistModal.open) return null
    const onSelectAll = () => {
      if (!copyAssistRef.current) return
      copyAssistRef.current.focus()
      copyAssistRef.current.select()
    }
    return (
      <div
        className="fixed inset-0 z-30 bg-slate-900/40 flex items-center justify-center p-4"
        onClick={() => setCopyAssistModal({ open: false, title: '', content: '' })}
      >
        <div className="bg-white rounded-[10px] border border-slate-200 shadow-lg w-full max-w-3xl" onClick={(e) => e.stopPropagation()}>
          <div className="px-4 py-3 border-b border-slate-200 flex items-center justify-between">
            <div className="font-semibold text-slate-800">{copyAssistModal.title || 'Copy Content'}</div>
            <button className="text-slate-500 hover:text-slate-700" onClick={() => setCopyAssistModal({ open: false, title: '', content: '' })}>✕</button>
          </div>
          <div className="p-4 space-y-3">
            <textarea
              ref={copyAssistRef}
              readOnly
              value={copyAssistModal.content || ''}
              className="w-full h-72 border border-slate-300 rounded-[10px] p-3 font-mono text-xs"
            />
            <div className="flex justify-end gap-2">
              <button className="px-3 py-1.5 rounded-[10px] border border-slate-300 text-slate-700" onClick={onSelectAll}>
                Select All
              </button>
              <button className="px-3 py-1.5 rounded-[10px] bg-[#0055ff] text-white" onClick={() => setCopyAssistModal({ open: false, title: '', content: '' })}>
                Close
              </button>
            </div>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className='airg-app-shell relative min-h-screen bg-[var(--bg-app)] text-[var(--text-primary)] overflow-hidden'>
      <div className="relative z-10 mx-auto max-w-[1720px] border border-[var(--border-default)] overflow-hidden bg-[var(--bg-app)] shadow-sm h-screen grid grid-cols-[var(--sidebar-width)_1fr]">
        <aside className="airg-sidebar h-full min-h-0 border-r border-white/10 bg-[var(--bg-sidebar)] flex flex-col">
          <div className="h-[78px] px-5 border-b border-white/10 flex items-center sidebar-brand">
            <div className="flex items-center gap-2">
              <img
                src={runtimeGuardLogo64}
                srcSet={`${runtimeGuardLogo64} 1x, ${runtimeGuardLogo128} 2x`}
                alt="Runtime Guard logo"
                className="w-8 h-8 object-contain logo-icon"
              />
              <div>
                <div className="text-sm font-semibold text-[var(--text-sidebar-active)] app-name">Runtime Guard</div>
                <div className="text-xs text-[var(--text-sidebar-heading)] app-subtitle">Policy Control Plane</div>
              </div>
            </div>
          </div>
          <nav className="flex-1 min-h-0 overflow-y-auto p-3">
            {RAIL_ITEMS.map(renderSidebarSection)}
          </nav>
          <div className="p-4 border-t border-white/10 sidebar-footer">
            <div className="rounded-[8px] px-0 py-1 text-xs text-[var(--text-sidebar-heading)] flex items-center gap-2 sidebar-server-status">
              <span className="w-1.5 h-1.5 rounded-full bg-[var(--status-green)] dot" />
              Server active · v2.0.dev2
            </div>
          </div>
        </aside>

        <div className="airg-content flex flex-col min-w-0 min-h-0 bg-[var(--bg-app)]">
          <div className="h-[78px] px-6 border-b border-[var(--border-default)] bg-[var(--bg-header-bar)] flex items-center justify-between gap-3 page-header">
            <div className="min-w-0">
              <div className="text-lg font-semibold text-[var(--text-primary)] title">{pageTitle}</div>
              <div className="text-xs text-[var(--text-secondary)] mt-0.5 flex flex-wrap items-center gap-3">
                {policyHash && <span className="font-mono hash">hash {String(policyHash).slice(0, 12)}</span>}
                {unsaved && <span className="inline-flex items-center gap-1 text-[var(--status-amber)]"><span className="w-1.5 h-1.5 rounded-full bg-[var(--status-amber)]" />Unsaved changes</span>}
              </div>
            </div>
            {activeRail === 'policy' && (
              <div className="flex flex-wrap items-center justify-end gap-2">
                <button onClick={onReload} className="btn btn-ghost">Reload</button>
                <button
                  onClick={onValidate}
                  className={`btn ${validateButtonState === 'success' ? 'btn-success-filled' : 'btn-success'}`}
                >
                  {validateButtonState === 'success' ? 'OK' : 'Validate'}
                </button>
                <button
                  onClick={onApply}
                  className={`btn ${applyButtonState === 'success' ? 'btn-success-filled' : 'btn-primary'}`}
                >
                  {applyButtonState === 'success' ? 'Applied' : 'Apply'}
                </button>
                <button
                  onClick={onRevertLastApply}
                  disabled={!hasRevertSnapshot}
                  className="btn btn-ghost disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Revert
                </button>
                <button
                  onClick={onResetDefaults}
                  disabled={!hasDefaultSnapshot}
                  className="btn btn-danger disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Reset
                </button>
              </div>
            )}
          </div>

          <main className="page-body flex-1 min-h-0 overflow-y-auto p-6">
            {!loaded && <div className="text-slate-500">Loading...</div>}
            {loaded && activeRail === 'approvals' && ApprovalsPanel()}
            {loaded && activeRail === 'policy' && PolicyPanel()}
            {loaded && activeRail === 'reports' && ReportsPanel()}
            {loaded && activeRail === 'settings' && SettingsPanel()}
          </main>
        </div>
      </div>
      {CommandInfoModal()}
      {CommandEditModal()}
      {ValidationErrorModal()}
      {CopyAssistModal()}
    </div>
  )
}
