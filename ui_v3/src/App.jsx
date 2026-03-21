import React, { useEffect, useMemo, useRef, useState } from 'react'
import runtimeGuardLogo64 from './assets/logo_v4_64px.png'
import runtimeGuardLogo128 from './assets/logo_v4_128px.png'
import SegControl from './components/SegControl'
import IconBtn, { PencilIcon, RemoveIcon } from './components/IconBtn'
import CollapsibleSection from './components/CollapsibleSection'

const API_BASE = 'http://127.0.0.1:5001'
const RAIL_ITEMS = [
  { id: 'approvals', label: 'Approvals' },
  { id: 'policy', label: 'Policy' },
  { id: 'reports', label: 'Reports' },
  { id: 'settings', label: 'Settings' }
]
const POLICY_TABS = [
  { id: 'rules', label: 'Rules' },
  { id: 'network', label: 'Network' },
  { id: 'agent_overrides', label: 'Agent Overrides' },
  { id: 'advanced', label: 'Advanced' },
]
const REPORT_TABS = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'sentinel', label: 'Script Sentinel' },
  { id: 'log', label: 'Log' },
]
const SETTINGS_TABS = [
  { id: 'agents', label: 'Agents' },
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
  requires_confirmation: 'badge badge-pending',
  blocked: 'badge badge-blocked'
}

const STATUS_LABEL = {
  allowed: 'Allowed',
  requires_confirmation: 'Requires Approval',
  blocked: 'Blocked'
}

const AGENT_OVERRIDE_SECTIONS = [
  'blocked',
  'requires_confirmation',
  'allowed',
  'network',
  'execution',
]
const AGENT_OVERRIDE_SECTION_LABELS = {
  blocked: 'Blocked',
  requires_confirmation: 'Require Confirmation',
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
  return 'allowed'
}

function setTier(policy, cmd, tier) {
  const next = deepClone(policy)
  const remove = (arr = []) => arr.filter((x) => x !== cmd)
  next.blocked.commands = remove(next.blocked?.commands)
  next.requires_confirmation.commands = remove(next.requires_confirmation?.commands)
  if (tier === 'blocked') next.blocked.commands.push(cmd)
  if (tier === 'requires_confirmation') next.requires_confirmation.commands.push(cmd)
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

function formatExpiry(seconds) {
  const total = Number(seconds || 0)
  if (total <= 0) return 'Expired'
  const mins = Math.floor(total / 60)
  const secs = total % 60
  if (mins > 0) return `${mins}m ${secs}s`
  return `${secs}s`
}

function ensureScriptSentinelPolicy(policy) {
  const next = deepClone(policy || {})
  const current = isPlainObject(next.script_sentinel) ? next.script_sentinel : {}
  const scanMode = ['exec_context', 'exec_context_plus_mentions'].includes(String(current.scan_mode || '').trim())
    ? String(current.scan_mode).trim()
    : 'exec_context'
  next.script_sentinel = {
    enabled: Boolean(current.enabled),
    mode: ['match_original', 'block', 'requires_confirmation'].includes(String(current.mode || '').trim())
      ? String(current.mode).trim()
      : 'match_original',
    scan_mode: scanMode,
    max_scan_bytes: Math.max(1024, Number.parseInt(String(current.max_scan_bytes ?? '1048576'), 10) || 1048576),
    include_wrappers: current.include_wrappers === undefined ? true : Boolean(current.include_wrappers),
  }
  return next
}

export default function App() {
  const [activeRail, setActiveRail] = useState('approvals')
  const [activeApprovalsTab, setActiveApprovalsTab] = useState('pending')
  const [activePolicyTab, setActivePolicyTab] = useState('rules')
  const [policyHash, setPolicyHash] = useState('')
  const [appliedPolicy, setAppliedPolicy] = useState(null)
  const [draftPolicy, setDraftPolicy] = useState(null)
  const [search, setSearch] = useState('')
  const [jsonOpen, setJsonOpen] = useState(false)
  const [jsonText, setJsonText] = useState('')
  const [jsonError, setJsonError] = useState('')
  const [message, setMessage] = useState('')
  const [pendingApprovals, setPendingApprovals] = useState([])
  const [approvalHistory, setApprovalHistory] = useState([])
  const [approvalHistoryError, setApprovalHistoryError] = useState('')
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
  const [newNetworkCommand, setNewNetworkCommand] = useState('')
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
  const [agentScopeOptions, setAgentScopeOptions] = useState({})
  const [settingsConfigsDir, setSettingsConfigsDir] = useState('')
  const [settingsLoading, setSettingsLoading] = useState(false)
  const [settingsError, setSettingsError] = useState('')
  const [selectedSettingsProfileId, setSelectedSettingsProfileId] = useState('')
  const [settingsSavedProfiles, setSettingsSavedProfiles] = useState({})
  const [settingsNeedsReconfigure, setSettingsNeedsReconfigure] = useState({})
  const [generatedCliByProfile, setGeneratedCliByProfile] = useState({})
  const [hardeningPanelOpenByProfile, setHardeningPanelOpenByProfile] = useState({})
  const [hardeningOptionsByProfile, setHardeningOptionsByProfile] = useState({})
  const [agentPosture, setAgentPosture] = useState({ profiles: [], discovered_unregistered: [], totals: { green: 0, yellow: 0, red: 0 } })
  const [agentPostureLoading, setAgentPostureLoading] = useState(false)
  const [agentPostureError, setAgentPostureError] = useState('')
  const [scriptSentinelData, setScriptSentinelData] = useState({ artifacts: { total: 0, items: [] }, summary: null })
  const [scriptSentinelLoading, setScriptSentinelLoading] = useState(false)
  const [scriptSentinelError, setScriptSentinelError] = useState('')
  const [scriptSentinelActionLoading, setScriptSentinelActionLoading] = useState({})
  const [agentConfigActionLoading, setAgentConfigActionLoading] = useState({})
  const [advancedBackupOpen, setAdvancedBackupOpen] = useState(false)
  const [advancedReportsOpen, setAdvancedReportsOpen] = useState(false)
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
  const [settingsInfoModal, setSettingsInfoModal] = useState({
    open: false,
    title: '',
    content: '',
  })
  const [rulesWhitelistOpen, setRulesWhitelistOpen] = useState(false)
  const pollRef = useRef(null)
  const [overrideAgentId, setOverrideAgentId] = useState('')
  const [overrideExpanded, setOverrideExpanded] = useState({})
  const [overrideDiffModal, setOverrideDiffModal] = useState({
    open: false,
    agentId: '',
    lines: [],
  })
  const [overrideBaselineModal, setOverrideBaselineModal] = useState({
    open: false,
    sectionLabel: '',
    baselineData: {},
  })
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
    if (activeRail === 'approvals') {
      const tab = (NAV_CHILDREN.approvals || []).find((t) => t.id === activeApprovalsTab)
      return `Approvals · ${tab?.label || 'Pending'}`
    }
    return 'Approvals · Pending'
  }, [activeRail, activeApprovalsTab, activePolicyTab, reportsTab, activeSettingsTab])

  useEffect(() => {
    if (!overrideAgentId && knownAgentIds.length) {
      setOverrideAgentId(knownAgentIds[0])
    } else if (overrideAgentId && !knownAgentIds.includes(overrideAgentId)) {
      setOverrideAgentId(knownAgentIds[0] || '')
    }
  }, [knownAgentIds, overrideAgentId])

  useEffect(() => {
    setSelectedSettingsProfileId((prev) => {
      const ids = (agentProfiles || [])
        .map((profile) => String(profile?.profile_id || '').trim())
        .filter(Boolean)
      if (!ids.length) return ''
      if (prev && ids.includes(prev)) return prev
      return ids[0]
    })
  }, [agentProfiles])

  useEffect(() => {
    setHardeningOptionsByProfile((prev) => {
      const next = { ...prev }
      const activeIds = new Set()
      ;(agentProfiles || []).forEach((profile) => {
        const profileId = String(profile?.profile_id || '').trim()
        if (!profileId) return
        activeIds.add(profileId)
        if (!next[profileId]) {
          next[profileId] = defaultHardeningOptionsForProfile(profile)
        } else {
          next[profileId] = {
            ...next[profileId],
            scope: normalizeScopeForAgentType(profile?.agent_type, next[profileId]?.scope || profile?.agent_scope),
          }
        }
      })
      Object.keys(next).forEach((profileId) => {
        if (!activeIds.has(profileId)) delete next[profileId]
      })
      return next
    })
  }, [agentProfiles, agentScopeOptions])

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

  async function fetchApprovalsHistory() {
    try {
      const res = await fetch(`${API_BASE}/approvals/history?limit=200`)
      if (!res.ok) {
        setApprovalHistoryError(`History load failed (${res.status})`)
        return
      }
      const payload = await res.json()
      setApprovalHistory(payload.history || [])
      setApprovalHistoryError('')
    } catch (err) {
      setApprovalHistoryError(String(err.message || err))
    }
  }

  function emptyProfile() {
    return {
      profile_id: `profile-${Date.now()}`,
      name: '',
      agent_type: 'claude_code',
      agent_scope: 'local',
      workspace: '',
      agent_id: '',
      last_generated_at: '',
      last_saved_path: '',
      last_saved_instructions_path: '',
    }
  }

  function defaultScopeForAgentType(agentType) {
    const normalized = String(agentType || '').trim().toLowerCase()
    if (normalized === 'claude_code') return 'local'
    if (normalized === 'codex') return 'global'
    return 'default'
  }

  function scopeOptionsForAgentType(agentType) {
    const normalized = String(agentType || '').trim().toLowerCase()
    const configured = Array.isArray(agentScopeOptions?.[normalized]) ? agentScopeOptions[normalized] : []
    if (configured.length) return configured
    if (normalized === 'claude_code') {
      return [
        { id: 'local', label: 'Local' },
        { id: 'project', label: 'Project' },
        { id: 'user', label: 'User' },
      ]
    }
    if (normalized === 'codex') {
      return [
        { id: 'global', label: 'Global' },
        { id: 'project', label: 'Project' },
      ]
    }
    return [{ id: 'default', label: 'Default' }]
  }

  function normalizeScopeForAgentType(agentType, scopeValue) {
    const options = scopeOptionsForAgentType(agentType)
    const allowed = new Set(options.map((item) => String(item?.id || '').trim().toLowerCase()).filter(Boolean))
    const requested = String(scopeValue || '').trim().toLowerCase()
    if (allowed.has(requested)) return requested
    return defaultScopeForAgentType(agentType)
  }

  function defaultHardeningOptionsForProfile(profile) {
    const agentType = String(profile?.agent_type || '').trim().toLowerCase()
    const scope = normalizeScopeForAgentType(agentType, profile?.agent_scope || defaultScopeForAgentType(agentType))
    return {
      scope,
      hook_enabled: true,
      restrict_native_tools: true,
      native_tools: {
        Bash: true,
        Glob: true,
        Grep: true,
        Read: true,
        Write: true,
        Edit: true,
        MultiEdit: true,
      },
      sandbox_enabled: true,
      sandbox_escape_closed: true,
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
        agent_scope: String(p?.agent_scope || '').trim(),
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
      setAgentScopeOptions(payload.agent_scopes || {})
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

  async function applyAgentConfigHardening(profileId, { autoAddMcp = false, options = null } = {}) {
    const res = await fetch(`${API_BASE}/settings/agents/config-apply`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ profile_id: profileId, auto_add_mcp: autoAddMcp, options }),
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
    fetchApprovalsHistory()
    pollRef.current = setInterval(() => {
      fetchApprovals()
      fetchApprovalsHistory()
    }, 3000)
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
  }, [activeRail, activeSettingsTab])

  useEffect(() => {
    if (activeRail !== 'reports' || reportsTab !== 'sentinel') return
    fetchScriptSentinel()
  }, [activeRail, reportsTab])

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
    return base.filter((cmd) => !q || cmd.toLowerCase().includes(q))
  }, [allCommands, search])

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

  function onAddCommand() {
    const command = normalizeCommandName(newCommand)
    if (!command) {
      setMessage('Command text is required')
      return
    }
    if (allCommands.includes(command)) {
      setMessage(`Command "${command}" already exists`)
      return
    }

    setDraftPolicy((prev) => {
      let next = deepClone(prev)
      next = ensureUiCatalogTab(next, 'all', 'All Commands')
      const tab = next.ui_catalog.tabs.find((t) => t.id === 'all')
      if (!tab.commands.includes(command)) {
        tab.commands.push(command)
        tab.commands.sort()
      }
      if (String(newComment || '').trim()) tab.descriptions[command] = String(newComment).trim()
      return next
    })

    setAllCommands((prev) => Array.from(new Set([...prev, command])).sort())
    if (String(newComment || '').trim()) {
      const comment = String(newComment).trim()
      setDescriptions((prev) => ({ ...prev, [command]: comment }))
    }
    setContexts((prev) => ({ ...prev, [command]: [] }))
    setTabCommands((prev) => {
      const next = { ...prev }
      next.all = Array.from(new Set([...(next.all || []), command])).sort()
      return next
    })
    setNewCommand('')
    setNewComment('')
    setMessage(`Command "${command}" added`)
  }

  function editCommandInline(original) {
    const currentDescription = String(descriptions[original] || '')
    const updatedRaw = window.prompt('Edit command pattern', original)
    if (updatedRaw === null) return
    const updated = normalizeCommandName(updatedRaw)
    if (!updated) {
      setMessage('Command text is required')
      return
    }
    if (updated !== original && allCommands.includes(updated)) {
      setMessage(`Command "${updated}" already exists`)
      return
    }
    const nextDescriptionRaw = window.prompt('Edit description (optional)', currentDescription)
    if (nextDescriptionRaw === null) return
    const updatedDescription = String(nextDescriptionRaw || '').trim()

    setDraftPolicy((prev) => {
      let next = deepClone(prev)
      const priorTier = tierFor(next, original)
      const remove = (arr = []) => arr.filter((x) => x !== original)
      next.blocked.commands = remove(next.blocked?.commands)
      next.requires_confirmation.commands = remove(next.requires_confirmation?.commands)
      if (priorTier === 'blocked') next.blocked.commands = Array.from(new Set([...(next.blocked.commands || []), updated])).sort()
      if (priorTier === 'requires_confirmation') {
        next.requires_confirmation.commands = Array.from(new Set([...(next.requires_confirmation.commands || []), updated])).sort()
      }

      next.ui_catalog = next.ui_catalog || {}
      next.ui_catalog.tabs = Array.isArray(next.ui_catalog.tabs) ? next.ui_catalog.tabs : []
      for (const tab of next.ui_catalog.tabs) {
        tab.commands = Array.isArray(tab.commands) ? tab.commands.filter((c) => c !== original) : []
        tab.descriptions = typeof tab.descriptions === 'object' && tab.descriptions ? tab.descriptions : {}
        delete tab.descriptions[original]
      }
      next = ensureUiCatalogTab(next, 'all', 'All Commands')
      const allTab = next.ui_catalog.tabs.find((t) => t.id === 'all')
      if (!allTab.commands.includes(updated)) {
        allTab.commands.push(updated)
        allTab.commands.sort()
      }
      if (updatedDescription) allTab.descriptions[updated] = updatedDescription
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
      next[updated] = []
      return next
    })
    setTabCommands((prev) => {
      const next = { ...prev }
      Object.keys(next).forEach((tabId) => {
        next[tabId] = (next[tabId] || []).filter((c) => c !== original)
      })
      next.all = Array.from(new Set([...(next.all || []), updated])).sort()
      return next
    })
    setMessage(`Command "${original}" updated`)
  }

  function removeCommandInline(command) {
    const ok = window.confirm(`Remove command "${command}"?`)
    if (!ok) return

    setDraftPolicy((prev) => {
      const next = deepClone(prev)
      next.blocked.commands = (next.blocked?.commands || []).filter((x) => x !== command)
      next.requires_confirmation.commands = (next.requires_confirmation?.commands || []).filter((x) => x !== command)
      next.ui_catalog = next.ui_catalog || {}
      next.ui_catalog.tabs = Array.isArray(next.ui_catalog.tabs) ? next.ui_catalog.tabs : []
      for (const tab of next.ui_catalog.tabs) {
        tab.commands = (tab.commands || []).filter((c) => c !== command)
        if (tab.descriptions && typeof tab.descriptions === 'object') delete tab.descriptions[command]
      }
      return next
    })
    setAllCommands((prev) => prev.filter((x) => x !== command))
    setDescriptions((prev) => {
      const next = { ...prev }
      delete next[command]
      return next
    })
    setContexts((prev) => {
      const next = { ...prev }
      delete next[command]
      return next
    })
    setTabCommands((prev) => {
      const next = { ...prev }
      Object.keys(next).forEach((tabId) => {
        next[tabId] = (next[tabId] || []).filter((c) => c !== command)
      })
      return next
    })
    setMessage(`Command "${command}" removed`)
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
      if (priorTier === 'blocked') next.blocked.commands = Array.from(new Set([...(next.blocked.commands || []), updated])).sort()
      if (priorTier === 'requires_confirmation') next.requires_confirmation.commands = Array.from(new Set([...(next.requires_confirmation.commands || []), updated])).sort()

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
    setRemoving((r) => ({ ...r, [token]: 'approved' }))
    setTimeout(() => {
      setPendingApprovals((prev) => prev.filter((p) => p.token !== token))
      setRemoving((r) => {
        const next = { ...r }
        delete next[token]
        return next
      })
    }, 600)
    fetchApprovalsHistory()
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
    setRemoving((r) => ({ ...r, [token]: 'denied' }))
    setTimeout(() => {
      setPendingApprovals((prev) => prev.filter((p) => p.token !== token))
      setRemoving((r) => {
        const next = { ...r }
        delete next[token]
        return next
      })
    }, 600)
    fetchApprovalsHistory()
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
    const [hovered, setHovered] = useState(false)
    const rowBg = currentTier === 'blocked' ? '#fff8f8' : currentTier === 'requires_confirmation' ? '#fffdf5' : 'white'
    const hoverBg = currentTier === 'blocked' ? '#fff2f2' : currentTier === 'requires_confirmation' ? '#fffaeb' : '#fafafa'
    const description = String(descriptions[cmd] || '').trim()

    return (
      <div
        onMouseEnter={() => setHovered(true)}
        onMouseLeave={() => setHovered(false)}
        style={{
          display: 'flex',
          alignItems: 'center',
          padding: '0 16px',
          borderBottom: '1px solid #f3f4f6',
          minHeight: 46,
          background: hovered ? hoverBg : rowBg,
          transition: 'background 0.1s',
        }}
      >
        <div style={{ flex: 1, padding: '8px 0', minWidth: 0 }}>
          <div style={{ fontSize: 13, fontWeight: 500, fontFamily: 'var(--font-mono)', color: '#111827' }}>{cmd}</div>
          {description && (
            <div style={{ fontSize: 11, color: '#9ca3af', marginTop: 1 }}>{description}</div>
          )}
        </div>

        <div style={{ width: 175, flexShrink: 0 }}>
          <SegControl
            value={currentTier}
            onChange={(nextTier) => setDraftPolicy((p) => setTier(p, cmd, nextTier))}
            options={[
              { label: 'Allow', value: 'allowed', activeClass: 'active-allow' },
              { label: 'Block', value: 'blocked', activeClass: 'active-block' },
              { label: 'Confirm', value: 'requires_confirmation', activeClass: 'active-confirm' },
            ]}
          />
        </div>

        <div
          style={{
            width: 44,
            flexShrink: 0,
            display: 'flex',
            gap: 2,
            justifyContent: 'flex-end',
            opacity: hovered ? 1 : 0,
            transition: 'opacity 0.15s',
          }}
        >
          <IconBtn icon={<PencilIcon />} variant="default" title="Edit" onClick={() => editCommandInline(cmd)} />
          <IconBtn icon={<RemoveIcon />} variant="danger" title="Remove" onClick={() => removeCommandInline(cmd)} />
        </div>
      </div>
    )
  }

  function ApprovalsPanel() {
    const activeTab = activeApprovalsTab === 'history' ? 'history' : 'pending'
    const pendingCount = pendingApprovals.length

    const handleRefresh = () => {
      fetchApprovals()
      fetchApprovalsHistory()
    }

    const tabs = [
      { key: 'pending', label: 'Pending', count: pendingCount },
      { key: 'history', label: 'History', count: null },
    ]

    function ExpandSection({ label, open, onToggle, children }) {
      return (
        <>
          <div
            onClick={onToggle}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 5,
              fontSize: 11,
              color: '#6b7280',
              cursor: 'pointer',
              padding: '0 16px 8px',
              userSelect: 'none',
              transition: 'color 0.15s',
            }}
            onMouseEnter={(e) => { e.currentTarget.style.color = '#4f46e5' }}
            onMouseLeave={(e) => { e.currentTarget.style.color = '#6b7280' }}
          >
            <svg
              style={{
                width: 10,
                height: 10,
                flexShrink: 0,
                transform: open ? 'rotate(90deg)' : 'none',
                transition: 'transform 0.15s',
              }}
              viewBox="0 0 10 10"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
            >
              <path d="M3 2l3 3-3 3" />
            </svg>
            {label}
          </div>
          {open && children}
        </>
      )
    }

    function ApprovalCard({ approval, onApprove, onDeny, removalState }) {
      const [cmdOpen, setCmdOpen] = useState(false)
      const [pathsOpen, setPathsOpen] = useState(false)
      const affectedPaths = Array.isArray(approval?.affected_paths) ? approval.affected_paths : []
      const sessionId = String(approval?.session_id || '')
      const borderLeftColor = removalState === 'approved'
        ? '#16a34a'
        : removalState === 'denied'
          ? '#dc2626'
          : '#f59e0b'

      return (
        <div
          style={{
            background: 'white',
            border: '1px solid #e5e7eb',
            borderLeft: `3px solid ${borderLeftColor}`,
            borderRadius: 8,
            marginBottom: 10,
            overflow: 'hidden',
            opacity: removalState ? 0.5 : 1,
            transition: 'all 0.2s',
          }}
        >
          <div style={{ padding: '14px 16px 0' }}>
            <div style={{ fontSize: 12, color: '#9ca3af', marginBottom: 6 }}>
              <strong style={{ color: '#374151', fontWeight: 600 }}>
                {approval?.agent_id || 'Unknown'}
              </strong>{' '}
              needs approval for:
            </div>

            <div
              style={{
                fontFamily: 'monospace',
                fontSize: 13,
                fontWeight: 500,
                color: '#111827',
                background: '#fafafa',
                border: '1px solid #f0f0f0',
                borderRadius: 5,
                padding: '8px 12px',
                marginBottom: 10,
                wordBreak: 'break-all',
                lineHeight: 1.5,
              }}
            >
              {approval?.command || ''}
            </div>

            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 12,
                fontSize: 11,
                color: '#9ca3af',
                marginBottom: 10,
              }}
            >
              <span>Requested {relativeTime(approval?.requested_at || '')}</span>
              <span>·</span>
              <span>
                Session{' '}
                <code
                  style={{
                    fontFamily: 'monospace',
                    fontSize: 10,
                    background: '#f3f4f6',
                    padding: '1px 5px',
                    borderRadius: 3,
                    color: '#6b7280',
                  }}
                >
                  {sessionId ? sessionId.slice(0, 14) : 'n/a'}
                </code>
              </span>
              <span>·</span>
              <span style={{ color: '#d97706', fontWeight: 500 }}>
                Expires in {formatExpiry(approval?.seconds_remaining)}
              </span>
            </div>
          </div>

          <ExpandSection
            label="Full command details"
            open={cmdOpen}
            onToggle={() => setCmdOpen((v) => !v)}
          >
            <div
              style={{
                padding: '10px 16px',
                background: '#fafafa',
                borderTop: '1px solid #f3f4f6',
                fontSize: 12,
              }}
            >
              {[
                ['Command', approval?.command || ''],
                ['Normalized', approval?.normalized_command || approval?.command || ''],
                ['Matched rule', approval?.matched_rule || '-'],
                ['Token', approval?.token || '-'],
              ].map(([label, val]) => (
                <div key={label} style={{ display: 'flex', gap: 8, marginBottom: 4 }}>
                  <span
                    style={{
                      fontSize: 10,
                      fontWeight: 600,
                      textTransform: 'uppercase',
                      letterSpacing: '0.06em',
                      color: '#9ca3af',
                      width: 90,
                      flexShrink: 0,
                      paddingTop: 2,
                    }}
                  >
                    {label}
                  </span>
                  <span
                    style={{
                      fontFamily: 'monospace',
                      fontSize: 11,
                      color: '#374151',
                      wordBreak: 'break-all',
                    }}
                  >
                    {val}
                  </span>
                </div>
              ))}
            </div>
          </ExpandSection>

          <ExpandSection
            label={`Affected paths (${affectedPaths.length})`}
            open={pathsOpen}
            onToggle={() => setPathsOpen((v) => !v)}
          >
            <div
              style={{
                padding: '10px 16px',
                background: '#fafafa',
                borderTop: '1px solid #f3f4f6',
              }}
            >
              {affectedPaths.length ? affectedPaths.map((p, i) => (
                <div
                  key={`${approval?.token || 'path'}-${i}`}
                  style={{ fontFamily: 'monospace', fontSize: 11, color: '#374151', marginBottom: 2 }}
                >
                  {p}
                </div>
              )) : (
                <div style={{ fontSize: 11, color: '#9ca3af' }}>No affected paths reported.</div>
              )}
            </div>
          </ExpandSection>

          <div
            style={{
              display: 'flex',
              gap: 8,
              padding: '12px 16px',
              borderTop: '1px solid #f3f4f6',
            }}
          >
            <button
              onClick={() => onApprove(approval?.token, approval?.command)}
              style={{
                background: '#4f46e5',
                color: 'white',
                border: 'none',
                borderRadius: 5,
                padding: '7px 20px',
                fontSize: 12,
                fontWeight: 600,
                cursor: 'pointer',
                fontFamily: 'inherit',
                transition: 'background 0.15s',
              }}
              onMouseEnter={(e) => { e.currentTarget.style.background = '#4338ca' }}
              onMouseLeave={(e) => { e.currentTarget.style.background = '#4f46e5' }}
            >
              Approve
            </button>

            <button
              onClick={() => onDeny(approval?.token)}
              style={{
                background: 'white',
                color: '#dc2626',
                border: '1px solid #fecaca',
                borderRadius: 5,
                padding: '7px 16px',
                fontSize: 12,
                fontWeight: 500,
                cursor: 'pointer',
                fontFamily: 'inherit',
                transition: 'all 0.15s',
              }}
              onMouseEnter={(e) => { e.currentTarget.style.background = '#fff5f5' }}
              onMouseLeave={(e) => { e.currentTarget.style.background = 'white' }}
            >
              Deny
            </button>
          </div>
        </div>
      )
    }

    const historyItems = approvalHistory.map((item) => {
      const decision = String(item?.decision || '').toLowerCase()
      return {
        command: String(item?.command || item?.normalized_command || '').trim(),
        agentId: String(item?.agent_id || 'Unknown'),
        requestedAt: String(item?.requested_at || ''),
        decidedAt: String(item?.resolved_at || item?.decided_at || ''),
        approver: String(item?.approver || 'User'),
        decision: decision === 'approved' ? 'approved' : 'denied',
      }
    })

    return (
      <div>
        <div className="topbar">
          <div>
            <div style={{ fontSize: 13, fontWeight: 600, color: '#0f0f0f' }}>
              {activeTab === 'pending' ? 'Approvals · Pending' : 'Approvals · History'}
            </div>
            <div style={{ fontSize: 10, color: '#9ca3af', fontFamily: 'monospace', marginTop: 1 }}>
              hash {String(policyHash || '').slice(0, 12)}
            </div>
          </div>
          <button className="btn btn-ghost" onClick={handleRefresh}>Refresh</button>
        </div>

        <div
          style={{
            background: 'white',
            borderBottom: '1px solid #e5e7eb',
            padding: '0 20px',
            display: 'flex',
            gap: 0,
            flexShrink: 0,
            borderLeft: '1px solid #e5e7eb',
            borderRight: '1px solid #e5e7eb',
            borderTop: 'none',
            borderBottomLeftRadius: 8,
            borderBottomRightRadius: 8,
            marginTop: -1,
            marginBottom: 12,
          }}
        >
          {tabs.map((tab) => (
            <div
              key={tab.key}
              onClick={() => setActiveApprovalsTab(tab.key)}
              style={{
                fontSize: 12,
                fontWeight: 500,
                padding: '10px 16px',
                cursor: 'pointer',
                color: activeTab === tab.key ? '#4f46e5' : '#6b7280',
                borderBottom: activeTab === tab.key ? '2px solid #4f46e5' : '2px solid transparent',
                transition: 'all 0.15s',
                display: 'flex',
                alignItems: 'center',
                gap: 6,
              }}
            >
              {tab.label}
              {tab.count !== null && (
                <span
                  style={{
                    background: tab.count > 0 ? '#fee2e2' : '#f3f4f6',
                    color: tab.count > 0 ? '#dc2626' : '#9ca3af',
                    fontSize: 10,
                    fontWeight: 700,
                    padding: '1px 6px',
                    borderRadius: 10,
                  }}
                >
                  {tab.count}
                </span>
              )}
            </div>
          ))}
        </div>

        {activeTab === 'pending' && (
          <>
            {!pendingApprovals.length ? (
              <div
                style={{
                  background: 'white',
                  border: '1px solid #e5e7eb',
                  borderRadius: 8,
                  padding: '48px 20px',
                  textAlign: 'center',
                }}
              >
                <div style={{ fontSize: 28, marginBottom: 10 }}>✓</div>
                <div style={{ fontSize: 14, fontWeight: 600, color: '#374151', marginBottom: 4 }}>
                  No pending approvals
                </div>
                <div style={{ fontSize: 12, color: '#9ca3af' }}>
                  Agents will appear here when they request confirmation for a command
                </div>
              </div>
            ) : (
              <div>
                {pendingApprovals.map((approval) => (
                  <ApprovalCard
                    key={approval.token}
                    approval={approval}
                    onApprove={approve}
                    onDeny={deny}
                    removalState={removing[approval.token]}
                  />
                ))}
              </div>
            )}
          </>
        )}

        {activeTab === 'history' && (
          <div
            style={{
              background: 'white',
              border: '1px solid #e5e7eb',
              borderRadius: 8,
              overflow: 'hidden',
            }}
          >
            {approvalHistoryError && (
              <div style={{ padding: '10px 16px', fontSize: 12, color: '#dc2626', borderBottom: '1px solid #f0f0f0' }}>
                {approvalHistoryError}
              </div>
            )}

            {!historyItems.length ? (
              <div style={{ padding: '36px 16px', textAlign: 'center', fontSize: 12, color: '#9ca3af' }}>
                No approval history yet.
              </div>
            ) : (
              <>
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'minmax(0, 1fr) 140px 140px 110px 96px',
                    gap: 12,
                    padding: '6px 16px',
                    background: '#fafafa',
                    borderBottom: '1px solid #f0f0f0',
                  }}
                >
                  {['Command', 'Requested', 'Decision time', 'Approver', 'Decision'].map((header) => (
                    <div
                      key={header}
                      style={{
                        fontSize: 10,
                        fontWeight: 600,
                        textTransform: 'uppercase',
                        letterSpacing: '0.06em',
                        color: '#9ca3af',
                      }}
                    >
                      {header}
                    </div>
                  ))}
                </div>

                {historyItems.map((item, idx) => (
                  <div
                    key={`history-${item.command}-${item.requestedAt}-${idx}`}
                    style={{
                      display: 'grid',
                      gridTemplateColumns: 'minmax(0, 1fr) 140px 140px 110px 96px',
                      gap: 12,
                      padding: '10px 16px',
                      borderBottom: idx < historyItems.length - 1 ? '1px solid #f3f4f6' : 'none',
                      alignItems: 'start',
                      transition: 'background 0.1s',
                    }}
                    onMouseEnter={(e) => { e.currentTarget.style.background = '#fafafa' }}
                    onMouseLeave={(e) => { e.currentTarget.style.background = 'white' }}
                  >
                    <div style={{ minWidth: 0 }}>
                      <div
                        style={{
                          fontFamily: 'monospace',
                          fontSize: 12,
                          color: '#374151',
                          whiteSpace: 'nowrap',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                        }}
                        title={item.command}
                      >
                        {item.command || '-'}
                      </div>
                      <div style={{ fontSize: 10, color: '#9ca3af', marginTop: 3 }}>
                        {item.agentId || 'Unknown'}
                      </div>
                    </div>

                    <div>
                      <div style={{ fontSize: 11, color: '#6b7280' }}>
                        {item.requestedAt ? relativeTime(item.requestedAt) : 'n/a'}
                      </div>
                      <div style={{ fontSize: 10, color: '#9ca3af', marginTop: 2, fontFamily: 'monospace' }}>
                        {item.requestedAt || 'n/a'}
                      </div>
                    </div>

                    <div>
                      <div style={{ fontSize: 11, color: '#6b7280' }}>
                        {item.decidedAt ? relativeTime(item.decidedAt) : 'n/a'}
                      </div>
                      <div style={{ fontSize: 10, color: '#9ca3af', marginTop: 2, fontFamily: 'monospace' }}>
                        {item.decidedAt || 'n/a'}
                      </div>
                    </div>

                    <div style={{ fontSize: 12, color: '#374151' }}>
                      {item.approver === 'human-operator' ? 'User' : item.approver}
                    </div>

                    <div>
                      <span
                        style={{
                          display: 'inline-block',
                          fontSize: 10,
                          fontWeight: 600,
                          padding: '2px 8px',
                          borderRadius: 10,
                          background: item.decision === 'approved' ? '#dcfce7' : '#fee2e2',
                          color: item.decision === 'approved' ? '#15803d' : '#dc2626',
                        }}
                      >
                        {item.decision === 'approved' ? 'Approved' : 'Denied'}
                      </span>
                    </div>
                  </div>
                ))}
              </>
            )}
          </div>
        )}
      </div>
    )
  }

  function ScriptSentinelPanel() {
    const sentinelArtifacts = scriptSentinelData?.artifacts?.items || []
    const sentinelSummary = scriptSentinelData?.summary || {}

    const stats = [
      { label: 'Flagged', value: Number(sentinelSummary.flagged_artifacts || 0), color: '#d97706' },
      { label: 'Checks (24h)', value: Number(sentinelSummary.total_checks || 0), color: '#111827' },
      { label: 'Blocked', value: Number(sentinelSummary.blocked || 0), color: '#dc2626' },
      { label: 'Needs Approval', value: Number(sentinelSummary.requires_confirmation || 0), color: '#111827' },
      { label: 'Trusted', value: Number(sentinelSummary.trusted_allowances || 0), color: '#15803d' },
      { label: 'Dismissed', value: Number(sentinelSummary.one_time_allowances || 0), color: '#111827' },
    ]

    const hasExecContext = (signatures = []) => signatures.some((sig) => {
      if (sig?.match_context === 'exec_context') return true
      if (sig?.enforceable === true) return true
      if (sig?.type === 'policy_command' && sig?.enforceable === undefined && !sig?.match_context) return true
      return false
    })

    const normalizeSignatureLabel = (sig) => String(sig?.pattern || sig?.normalized_pattern || '').trim()

    function HashCell({ hash }) {
      const [copied, setCopied] = useState(false)

      const handleClick = async () => {
        try {
          await navigator.clipboard?.writeText(hash)
          setCopied(true)
          setTimeout(() => setCopied(false), 1500)
        } catch {
          // noop: clipboard can fail in restricted contexts
        }
      }

      return (
        <div
          title={hash}
          onClick={handleClick}
          style={{
            fontFamily: 'monospace',
            fontSize: 11,
            color: copied ? '#15803d' : '#6b7280',
            cursor: 'pointer',
            whiteSpace: 'nowrap',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            transition: 'color 0.15s',
            userSelect: 'none',
          }}
          onMouseEnter={(e) => { if (!copied) e.currentTarget.style.color = '#4f46e5' }}
          onMouseLeave={(e) => { if (!copied) e.currentTarget.style.color = '#6b7280' }}
        >
          {copied ? 'Copied!' : `${hash.slice(0, 12)}…`}
        </div>
      )
    }

    return (
      <div>
        <div className="topbar">
          <div>
            <div style={{ fontSize: 13, fontWeight: 600, color: '#0f0f0f' }}>
              Reports · Script Sentinel
            </div>
            <div style={{ fontSize: 10, color: '#9ca3af', marginTop: 1 }}>
              Policy-intent continuity for script-mediated command execution
            </div>
          </div>
          <button className="btn btn-ghost" onClick={fetchScriptSentinel}>
            {scriptSentinelLoading ? 'Refreshing…' : 'Refresh'}
          </button>
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(6, minmax(0, 1fr))',
            gap: 8,
            marginTop: 12,
            marginBottom: 16,
          }}
        >
          {stats.map((item) => (
            <div
              key={item.label}
              style={{
                background: 'white',
                border: '1px solid #e5e7eb',
                borderRadius: 7,
                padding: '10px 14px',
              }}
            >
              <div
                style={{
                  fontSize: 10,
                  fontWeight: 600,
                  textTransform: 'uppercase',
                  letterSpacing: '0.06em',
                  color: '#9ca3af',
                  marginBottom: 5,
                }}
              >
                {item.label}
              </div>
              <div
                style={{
                  fontSize: 22,
                  fontWeight: 700,
                  color: item.color,
                  letterSpacing: '-0.02em',
                  lineHeight: 1,
                }}
              >
                {item.value}
              </div>
            </div>
          ))}
        </div>

        {scriptSentinelError && (
          <div style={{ marginBottom: 12, fontSize: 12, color: '#dc2626' }}>{scriptSentinelError}</div>
        )}

        <div
          style={{
            background: 'white',
            border: '1px solid #e5e7eb',
            borderRadius: 8,
            overflow: 'hidden',
          }}
        >
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: '2fr 1.4fr 80px 1fr 90px 110px',
              gap: 12,
              padding: '8px 12px',
              background: '#fafafa',
              borderBottom: '1px solid #f0f0f0',
            }}
          >
            {['Path', 'Hash', 'Exec context', 'Matched signatures', 'Last seen', 'Actions'].map((header) => (
              <div
                key={header}
                style={{
                  fontSize: 10,
                  fontWeight: 600,
                  textTransform: 'uppercase',
                  letterSpacing: '0.06em',
                  color: '#9ca3af',
                }}
              >
                {header}
              </div>
            ))}
          </div>

          {sentinelArtifacts.map((row, idx) => {
            const hash = String(row?.content_hash || '')
            const onceKey = `once:${hash}`
            const trustKey = `persistent:${hash}`
            const signatures = Array.isArray(row?.matched_signatures) ? row.matched_signatures : []
            const execContext = hasExecContext(signatures)
            const lastSeen = row?.path_last_seen_ts || row?.last_seen_ts || ''
            const signatureLabels = signatures
              .map((sig) => normalizeSignatureLabel(sig))
              .filter(Boolean)

            return (
              <div
                key={`${row?.path || 'row'}:${hash || idx}`}
                style={{
                  display: 'grid',
                  gridTemplateColumns: '2fr 1.4fr 80px 1fr 90px 110px',
                  gap: 12,
                  padding: '9px 12px',
                  borderBottom: idx < sentinelArtifacts.length - 1 ? '1px solid #f3f4f6' : 'none',
                  alignItems: 'center',
                }}
              >
                <div
                  title={row?.path || ''}
                  style={{
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    fontFamily: 'monospace',
                    fontSize: 12,
                    color: '#374151',
                  }}
                >
                  {row?.path || '-'}
                </div>

                <HashCell hash={hash} />

                <span
                  style={{
                    display: 'inline-block',
                    fontSize: 10,
                    fontWeight: 600,
                    padding: '2px 8px',
                    borderRadius: 10,
                    background: execContext ? '#dcfce7' : '#f3f4f6',
                    color: execContext ? '#15803d' : '#6b7280',
                    width: 'fit-content',
                  }}
                >
                  {execContext ? 'Yes' : 'No'}
                </span>

                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                  {signatureLabels.length ? signatureLabels.map((sig, sigIdx) => (
                    <span
                      key={`${hash}-sig-${sigIdx}`}
                      style={{
                        fontSize: 10,
                        fontFamily: 'monospace',
                        background: '#fef3c7',
                        color: '#92400e',
                        padding: '1px 6px',
                        borderRadius: 3,
                      }}
                    >
                      {sig}
                    </span>
                  )) : (
                    <span style={{ fontSize: 11, color: '#9ca3af' }}>-</span>
                  )}
                </div>

                <span style={{ fontSize: 11, color: '#9ca3af', whiteSpace: 'nowrap' }}>
                  {lastSeen ? relativeTime(lastSeen) : '-'}
                </span>

                <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                  <button
                    onClick={() => scriptSentinelAllowance(hash, 'once')}
                    style={{
                      fontSize: 10,
                      fontWeight: 500,
                      padding: '4px 8px',
                      borderRadius: 4,
                      border: '1px solid #e5e7eb',
                      background: 'white',
                      color: '#6b7280',
                      cursor: 'pointer',
                      whiteSpace: 'nowrap',
                      transition: 'all 0.15s',
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.background = '#f3f4f6'
                      e.currentTarget.style.color = '#374151'
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.background = 'white'
                      e.currentTarget.style.color = '#6b7280'
                    }}
                    disabled={Boolean(scriptSentinelActionLoading[onceKey])}
                  >
                    Dismiss once
                  </button>

                  <button
                    onClick={() => scriptSentinelAllowance(hash, 'persistent')}
                    style={{
                      fontSize: 10,
                      fontWeight: 500,
                      padding: '4px 8px',
                      borderRadius: 4,
                      border: '1px solid #bbf7d0',
                      background: '#f0fdf4',
                      color: '#15803d',
                      cursor: 'pointer',
                      whiteSpace: 'nowrap',
                      transition: 'all 0.15s',
                    }}
                    onMouseEnter={(e) => { e.currentTarget.style.background = '#dcfce7' }}
                    onMouseLeave={(e) => { e.currentTarget.style.background = '#f0fdf4' }}
                    disabled={Boolean(scriptSentinelActionLoading[trustKey])}
                  >
                    Trust
                  </button>
                </div>
              </div>
            )
          })}

          {!sentinelArtifacts.length && !scriptSentinelLoading && (
            <div style={{ padding: '18px 12px', fontSize: 12, color: '#9ca3af' }}>
              No flagged script artifacts recorded yet.
            </div>
          )}
        </div>
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
        {reportsTab === 'log' && (
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
              <span>last event</span>
            </div>
            <div className="status-item">
              <span className="value">{nextIndexIn}</span>
              <span>next index</span>
            </div>
          </div>
          {reportsError && <div className="mt-2 text-sm text-red-600">{reportsError}</div>}
          {reportsLoading && <div className="mt-2 text-xs text-slate-500">Refreshing reports...</div>}
          </div>
        )}

        {reportsTab !== 'sentinel' && (
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
        )}

        {reportsTab === 'sentinel' && (
          <ScriptSentinelPanel />
        )}

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
                    <th className="text-left px-2 py-1">Source</th>
                    <th className="text-left px-2 py-1">Tool</th>
                    <th className="text-left px-2 py-1">Decision</th>
                    <th className="text-left px-2 py-1">Event</th>
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
                    const source = String(e.source || '-')
                    const sourceClass = source === 'mcp-server'
                      ? 'bg-violet-100 text-violet-700 border-violet-200'
                      : source === 'human-operator'
                        ? 'bg-green-100 text-green-700 border-green-200'
                        : 'bg-slate-100 text-slate-600 border-slate-200'
                    const decision = String(e.policy_decision || '-')
                    const decisionClass = decision === 'blocked'
                      ? 'bg-red-100 text-red-600 border-red-200'
                      : decision === 'confirmed'
                        ? 'bg-amber-100 text-amber-700 border-amber-200'
                        : 'bg-slate-100 text-slate-600 border-slate-200'
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
                          <td className="px-2 py-1">
                            <span className={`inline-flex items-center px-2 py-0.5 rounded border text-[11px] ${sourceClass}`}>{source}</span>
                          </td>
                          <td className="px-2 py-1">{e.tool || '-'}</td>
                          <td className="px-2 py-1">
                            <span className={`inline-flex items-center px-2 py-0.5 rounded border text-[11px] ${decisionClass}`}>{decision}</span>
                          </td>
                          <td className="px-2 py-1">
                            {e.event ? (
                              <span className="inline-flex items-center px-2 py-0.5 rounded border text-[11px] font-mono bg-amber-100 text-amber-800 border-amber-200">
                                {e.event}
                              </span>
                            ) : (
                              <span className="text-slate-400">-</span>
                            )}
                          </td>
                          <td className="px-2 py-1 font-mono">{e.matched_rule || '-'}</td>
                          <td className="px-2 py-1 font-mono">{e.command || e.path || '-'}</td>
                        </tr>
                        {expanded && (
                          <tr className="bg-indigo-50/40 border-t border-slate-100">
                            <td colSpan={9} className="px-2 py-2">
                              <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-[11px] text-slate-600 mb-2">
                                <div><span className="font-semibold text-slate-700">Agent:</span> {e.agent_id || 'Unknown'}</div>
                                <div><span className="font-semibold text-slate-700">Source:</span> {source}</div>
                                <div><span className="font-semibold text-slate-700">Tool:</span> {e.tool || '-'}</div>
                                <div><span className="font-semibold text-slate-700">Decision:</span> {decision}</div>
                                <div><span className="font-semibold text-slate-700">Event:</span> {e.event || '-'}</div>
                                <div><span className="font-semibold text-slate-700">Matched rule:</span> {e.matched_rule || '-'}</div>
                              </div>
                              {e.block_reason && (
                                <div className="mb-2 text-xs text-red-700 bg-red-50 border border-red-200 rounded p-2">
                                  <span className="font-semibold">Block reason:</span> {e.block_reason}
                                </div>
                              )}
                              <details>
                                <summary className="cursor-pointer text-xs text-slate-600">Show raw JSON</summary>
                                <pre className="mt-2 text-xs font-mono whitespace-pre-wrap break-all bg-[#0f1117] text-slate-100 p-3 rounded">{prettyJson}</pre>
                              </details>
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

  function PathLikeRow({ label, onEdit, onRemove, tint = 'white' }) {
    const [hovered, setHovered] = useState(false)
    const hoverBg = tint === '#fff8f8' ? '#fff2f2' : '#fafafa'
    return (
      <div
        onMouseEnter={() => setHovered(true)}
        onMouseLeave={() => setHovered(false)}
        style={{
          display: 'flex',
          alignItems: 'center',
          padding: '0 16px',
          borderBottom: '1px solid #f3f4f6',
          minHeight: 42,
          background: hovered ? hoverBg : tint,
        }}
      >
        <div style={{ flex: 1 }}>
          <span style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: '#374151' }}>{label}</span>
        </div>
        <div style={{ width: 175, flexShrink: 0 }} />
        <div
          style={{
            width: 44,
            flexShrink: 0,
            display: 'flex',
            gap: 2,
            justifyContent: 'flex-end',
            opacity: hovered ? 1 : 0,
            transition: 'opacity 0.15s',
          }}
        >
          <IconBtn icon={<PencilIcon />} variant="default" title="Edit" onClick={onEdit} />
          <IconBtn icon={<RemoveIcon />} variant="danger" title="Remove" onClick={onRemove} />
        </div>
      </div>
    )
  }

  function RulesPanel() {
    const blockedPaths = (draftPolicy?.blocked?.paths || []).slice().sort()
    const whitelistedPaths = (draftPolicy?.allowed?.paths_whitelist || []).slice().sort()
    const blockedExtensions = (draftPolicy?.blocked?.extensions || []).slice().sort()

    const editPath = (oldPath, tier) => {
      const next = window.prompt('Edit path', oldPath)
      if (next === null) return
      const normalized = normalizeAbsolutePath(next)
      if (!normalized || !isAbsolutePath(normalized)) {
        setMessage('Only absolute paths are allowed (must start with /)')
        return
      }
      setDraftPolicy((prev) => {
        const cleared = removePath(prev, oldPath)
        return setPathTier(cleared, normalized, tier)
      })
    }

    const addBlockedPath = () => {
      const raw = window.prompt('Add blocked absolute path', '')
      if (raw === null) return
      const normalized = normalizeAbsolutePath(raw)
      if (!normalized || !isAbsolutePath(normalized)) {
        setMessage('Only absolute paths are allowed (must start with /)')
        return
      }
      setDraftPolicy((prev) => setPathTier(prev, normalized, 'blocked'))
      setMessage(`Blocked path "${normalized}" added`)
    }

    const addAllowedPath = () => {
      const raw = window.prompt('Add allowed absolute path', '')
      if (raw === null) return
      const normalized = normalizeAbsolutePath(raw)
      if (!normalized || !isAbsolutePath(normalized)) {
        setMessage('Only absolute paths are allowed (must start with /)')
        return
      }
      setDraftPolicy((prev) => setPathTier(prev, normalized, 'allowed'))
      setMessage(`Allowed path "${normalized}" added`)
    }

    const addBlockedExtension = () => {
      const raw = window.prompt('Add blocked extension pattern', '')
      if (raw === null) return
      const value = String(raw || '').trim()
      if (!value) {
        setMessage('Extension value is required')
        return
      }
      setDraftPolicy((prev) => {
        const next = deepClone(prev)
        next.blocked = next.blocked || {}
        next.blocked.extensions = Array.from(new Set([...(next.blocked.extensions || []), value])).sort()
        return next
      })
      setMessage(`Extension "${value}" added`)
    }

    const editExtension = (oldExt) => {
      const raw = window.prompt('Edit extension pattern', oldExt)
      if (raw === null) return
      const value = String(raw || '').trim()
      if (!value) {
        setMessage('Extension value is required')
        return
      }
      setDraftPolicy((prev) => {
        const next = deepClone(prev)
        const list = (next.blocked?.extensions || []).filter((e) => e !== oldExt)
        list.push(value)
        next.blocked.extensions = Array.from(new Set(list)).sort()
        return next
      })
      setMessage(`Extension "${oldExt}" updated`)
    }

    const pathsIcon = (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4">
        <path d="M2.5 5h4l1.2 1.2h5.8v6H2.5z" />
        <path d="M2.5 5V3.5h4l1.2 1.2" />
      </svg>
    )
    const extensionsIcon = (
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4">
        <path d="M3 3h10v10H3z" />
        <path d="M5.5 6.5h5M5.5 9.5h3.5" />
      </svg>
    )

    return (
      <div className="space-y-3">
        <div className="bg-white border border-slate-200 rounded-[8px] overflow-hidden">
          <div style={{ display: 'flex', gap: 8, padding: '10px 16px', borderBottom: '1px solid #f0f0f0', background: '#fafafa' }}>
            <input
              value={newCommand}
              onChange={(e) => setNewCommand(e.target.value)}
              style={{ flex: 2, fontFamily: 'var(--font-mono)', fontSize: 12, padding: '6px 10px', border: '1px solid #94a3b8', borderRadius: 5, outline: 'none', background: '#ffffff' }}
              placeholder="Command pattern (e.g. rm -rf, git push --force)"
            />
            <input
              value={newComment}
              onChange={(e) => setNewComment(e.target.value)}
              style={{ flex: 1, fontSize: 12, padding: '6px 10px', border: '1px solid #94a3b8', borderRadius: 5, outline: 'none', background: '#ffffff' }}
              placeholder="Description (optional)"
            />
            <button
              onClick={onAddCommand}
              style={{
                background: '#4f46e5',
                color: 'white',
                border: 'none',
                borderRadius: 5,
                padding: '6px 14px',
                fontSize: 11,
                fontWeight: 500,
                cursor: 'pointer',
                whiteSpace: 'nowrap',
              }}
            >
              Add
            </button>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 16px', background: '#fafafa', borderBottom: '1px solid #f0f0f0' }}>
            <div style={{ flex: 1, position: 'relative' }}>
              <svg style={{ position: 'absolute', left: 8, top: 8, width: 12, height: 12, color: '#9ca3af' }} viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.5">
                <circle cx="6" cy="6" r="4" />
                <path d="M9.5 9.5L12.5 12.5" />
              </svg>
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                style={{ width: '100%', fontSize: 12, padding: '6px 10px 6px 28px', border: '1px solid #94a3b8', borderRadius: 5, outline: 'none', background: '#ffffff' }}
                placeholder="Search commands..."
              />
            </div>
            <span style={{ fontSize: 11, color: '#9ca3af', whiteSpace: 'nowrap' }}>{commandRows.length} rules</span>
          </div>

          <div style={{ display: 'flex', padding: '5px 16px', background: '#fafafa', borderBottom: '1px solid #f0f0f0' }}>
            <span style={{ flex: 1, fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', color: '#9ca3af' }}>Command</span>
            <span style={{ width: 175, textAlign: 'center', fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', color: '#9ca3af', flexShrink: 0 }}>Policy tier</span>
            <span style={{ width: 44, flexShrink: 0 }} />
          </div>

          {commandRows.map((cmd) => <CommandRow key={cmd} cmd={cmd} />)}
        </div>

        <CollapsibleSection
          icon={pathsIcon}
          title="Paths"
          badges={[
            { label: `${blockedPaths.length} blocked`, style: 'red' },
            { label: `${whitelistedPaths.length} whitelisted`, style: 'gray' },
          ]}
        >
          <div style={{ borderBottom: '1px solid #f3f4f6' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 16px', background: '#fafafa' }}>
              <span style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', color: '#6b7280' }}>Blocked paths</span>
              <button className="btn btn-ghost" onClick={addBlockedPath}>+ Add</button>
            </div>
            {blockedPaths.map((path) => (
              <PathLikeRow
                key={path}
                label={path}
                tint="#fff8f8"
                onEdit={() => editPath(path, 'blocked')}
                onRemove={() => setDraftPolicy((prev) => removePath(prev, path))}
              />
            ))}
            {!blockedPaths.length && <div className="px-4 py-3 text-xs text-slate-500">No blocked paths.</div>}
          </div>

          <div>
            <button
              type="button"
              onClick={() => setRulesWhitelistOpen((v) => !v)}
              style={{ display: 'flex', width: '100%', justifyContent: 'space-between', alignItems: 'center', padding: '8px 16px', background: '#fafafa' }}
            >
              <span style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', color: '#6b7280' }}>
                Allowed paths (whitelist)
              </span>
              <span className="text-xs text-slate-500">{rulesWhitelistOpen ? 'Hide' : 'Show'}</span>
            </button>
            {rulesWhitelistOpen && (
              <div style={{ borderTop: '1px solid #f3f4f6' }}>
                <div style={{ margin: '10px 16px', padding: '8px 12px', background: '#f0f9ff', border: '1px solid #bae6fd', borderRadius: 5, fontSize: 11, color: '#0369a1' }}>
                  Whitelisted paths allow access outside AIRG_WORKSPACE for file tools and shell containment checks. Only effective when shell workspace containment is set to enforce mode (Advanced Policy).
                </div>
                <div style={{ padding: '0 16px 12px' }}>
                  <button className="btn btn-ghost" onClick={addAllowedPath}>+ Add allowed path</button>
                </div>
                {whitelistedPaths.map((path) => (
                  <PathLikeRow
                    key={path}
                    label={path}
                    tint="white"
                    onEdit={() => editPath(path, 'allowed')}
                    onRemove={() => setDraftPolicy((prev) => removePath(prev, path))}
                  />
                ))}
                {!whitelistedPaths.length && <div className="px-4 pb-3 text-xs text-slate-500">No allowed paths.</div>}
              </div>
            )}
          </div>
        </CollapsibleSection>

        <CollapsibleSection
          icon={extensionsIcon}
          title="Extensions"
          badges={[{ label: `${blockedExtensions.length} blocked`, style: 'red' }]}
          defaultCollapsed={true}
        >
          <div style={{ borderBottom: '1px solid #f3f4f6' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 16px', background: '#fafafa' }}>
              <span style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', color: '#6b7280' }}>Blocked extensions</span>
              <button className="btn btn-ghost" onClick={addBlockedExtension}>+ Add</button>
            </div>
            {blockedExtensions.map((ext) => (
              <PathLikeRow
                key={ext}
                label={ext}
                tint="#fff8f8"
                onEdit={() => editExtension(ext)}
                onRemove={() => setDraftPolicy((prev) => {
                  const next = deepClone(prev)
                  next.blocked.extensions = (next.blocked?.extensions || []).filter((e) => e !== ext)
                  return next
                })}
              />
            ))}
            {!blockedExtensions.length && <div className="px-4 py-3 text-xs text-slate-500">No blocked extensions.</div>}
          </div>
        </CollapsibleSection>
      </div>
    )
  }

  function NetworkPanel() {
    const network = draftPolicy?.network || {}
    const commands = (network.commands || []).slice().sort()
    const allowedDomains = (network.allowed_domains || []).slice().sort()
    const blockedDomains = (network.blocked_domains || []).slice().sort()

    const updateNetwork = (patch) => {
      setDraftPolicy((prev) => {
        const next = deepClone(prev)
        next.network = { ...(next.network || {}), ...patch }
        return next
      })
    }

    const addNetworkCommand = (rawValue = newNetworkCommand) => {
      const cmd = normalizeListToken(rawValue)
      if (!cmd) {
        setMessage('Network command is required')
        return false
      }
      updateNetwork({ commands: Array.from(new Set([...(network.commands || []), cmd])).sort() })
      setNewNetworkCommand('')
      setMessage(`Network command "${cmd}" added`)
      return true
    }

    const removeNetworkCommand = (cmd) => {
      updateNetwork({ commands: (network.commands || []).filter((c) => c !== cmd) })
    }

    const addAllowedDomain = (rawValue) => {
      const domain = normalizeDomain(rawValue)
      if (!domain) {
        setMessage('Domain value is required')
        return false
      }
      updateNetwork({ allowed_domains: Array.from(new Set([...(network.allowed_domains || []), domain])).sort() })
      setMessage(`Domain "${domain}" added to allowlist`)
      return true
    }

    const removeAllowedDomain = (domain) => {
      updateNetwork({ allowed_domains: (network.allowed_domains || []).filter((x) => x !== domain) })
    }

    const addBlockedDomain = (rawValue) => {
      const domain = normalizeDomain(rawValue)
      if (!domain) {
        setMessage('Domain value is required')
        return false
      }
      updateNetwork({ blocked_domains: Array.from(new Set([...(network.blocked_domains || []), domain])).sort() })
      setMessage(`Domain "${domain}" added to blocklist`)
      return true
    }

    const removeBlockedDomain = (domain) => {
      updateNetwork({ blocked_domains: (network.blocked_domains || []).filter((x) => x !== domain) })
    }

    const codeStyle = {
      fontFamily: 'monospace',
      fontSize: 11,
      background: 'rgba(3,105,161,0.1)',
      padding: '0 4px',
      borderRadius: 3,
    }

    function DomainRow({ domain, onRemove }) {
      const [hovered, setHovered] = useState(false)
      return (
        <div
          onMouseEnter={() => setHovered(true)}
          onMouseLeave={() => setHovered(false)}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            padding: '7px 12px',
            borderBottom: '1px solid #f9fafb',
            fontSize: 12,
            fontFamily: 'monospace',
            color: '#374151',
            background: hovered ? '#fafafa' : 'white',
          }}
        >
          <span style={{ flex: 1 }}>{domain}</span>
          <button
            onClick={onRemove}
            style={{
              width: 20,
              height: 20,
              border: 'none',
              borderRadius: 3,
              background: hovered ? '#fee2e2' : 'transparent',
              color: hovered ? '#dc2626' : '#9ca3af',
              cursor: 'pointer',
              fontSize: 13,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              opacity: hovered ? 1 : 0,
              transition: 'all 0.15s',
            }}
          >
            ×
          </button>
        </div>
      )
    }

    function DomainColumn({
      title,
      titleColor,
      placeholder,
      domains,
      onAdd,
      onRemove,
      emptyText,
      addButtonStyle,
    }) {
      const [input, setInput] = useState('')
      const handleAdd = () => {
        const val = input.trim().toLowerCase()
        if (!val) return
        if (onAdd(val)) setInput('')
      }
      return (
        <div
          style={{
            border: '1px solid #e5e7eb',
            borderRadius: 7,
            overflow: 'hidden',
            display: 'flex',
            flexDirection: 'column',
          }}
        >
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '9px 12px',
              background: '#fafafa',
              borderBottom: '1px solid #f0f0f0',
            }}
          >
            <span style={{ fontSize: 11, fontWeight: 600, color: titleColor }}>
              {title}
            </span>
            <span style={{ fontSize: 10, color: '#9ca3af' }}>
              {domains.length} domain{domains.length !== 1 ? 's' : ''}
            </span>
          </div>

          <div
            style={{
              display: 'flex',
              gap: 6,
              padding: '8px 10px',
              borderBottom: '1px solid #f0f0f0',
            }}
          >
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleAdd()}
              placeholder={placeholder}
              style={{
                flex: 1,
                fontSize: 12,
                fontFamily: 'monospace',
                padding: '5px 8px',
                borderRadius: 5,
                border: '1px solid #d1d5db',
                outline: 'none',
              }}
            />
            <button
              onClick={handleAdd}
              style={{
                padding: '4px 10px',
                fontSize: 11,
                fontWeight: 500,
                borderRadius: 5,
                cursor: 'pointer',
                ...addButtonStyle,
              }}
            >
              Add
            </button>
          </div>

          <div style={{ minHeight: 80 }}>
            {domains.length === 0 ? (
              <div
                style={{
                  padding: '16px 12px',
                  fontSize: 11,
                  color: '#9ca3af',
                  fontStyle: 'italic',
                }}
              >
                {emptyText}
              </div>
            ) : (
              domains.map((domain) => (
                <DomainRow
                  key={domain}
                  domain={domain}
                  onRemove={() => onRemove(domain)}
                />
              ))
            )}
          </div>
        </div>
      )
    }

    return (
      <div className="space-y-3">
        <div style={{
          background: '#f0f9ff',
          border: '1px solid #bae6fd',
          borderRadius: 7,
          padding: '12px 14px',
          marginBottom: 12,
        }}>
          <div style={{
            fontSize: 11,
            fontWeight: 600,
            color: '#0369a1',
            textTransform: 'uppercase',
            letterSpacing: '0.06em',
            marginBottom: 6,
            display: 'flex',
            alignItems: 'center',
            gap: 6,
          }}>
            <svg width="12" height="12" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.3">
              <circle cx="7" cy="7" r="6" />
              <line x1="7" y1="5" x2="7" y2="5.5" />
              <line x1="7" y1="7" x2="7" y2="10" />
            </svg>
            Domain matching behaviour
          </div>
          <ul style={{ paddingLeft: 16 }}>
            {[
              <>Subdomains are matched — a rule for <span style={codeStyle}>example.com</span> also applies to <span style={codeStyle}>api.example.com</span></>,
              'Policy checks hostnames found in command arguments and URLs only',
              'Redirect chains and short-link expansion are not followed — checks apply to the visible domain',
              'Referral and tracking query parameters do not affect domain matching',
            ].map((item, i) => (
              <li key={i} style={{ fontSize: 11, color: '#0369a1', lineHeight: 1.7 }}>{item}</li>
            ))}
          </ul>
        </div>

        <div style={{
          background: 'white',
          border: '1px solid #e5e7eb',
          borderRadius: 8,
          marginBottom: 12,
          overflow: 'hidden',
        }}>
          <div style={{
            padding: '10px 16px',
            borderBottom: '1px solid #f3f4f6',
            display: 'flex',
            alignItems: 'center',
          }}>
            <span style={{
              fontSize: 11,
              fontWeight: 600,
              color: '#6b7280',
              textTransform: 'uppercase',
              letterSpacing: '0.06em',
            }}>
              Enforcement
            </span>
          </div>

          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: 16,
            padding: '11px 16px',
            borderBottom: '1px solid #f9fafb',
          }}>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 13, fontWeight: 500, color: '#374151' }}>
                Enforcement mode
              </div>
              <div style={{ fontSize: 11, color: '#9ca3af', marginTop: 2 }}>
                Off: no checks · Monitor: log violations, allow execution · Enforce: block domain rule violations
              </div>
            </div>
            <SegControl
              value={network.enforcement_mode || 'off'}
              onChange={(mode) => updateNetwork({ enforcement_mode: mode })}
              options={[
                { label: 'Off', value: 'off', activeClass: 'm-off' },
                { label: 'Monitor', value: 'monitor', activeClass: 'm-monitor' },
                { label: 'Enforce', value: 'enforce', activeClass: 'm-enforce' },
              ]}
            />
          </div>

          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: 16,
            padding: '11px 16px',
          }}>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 13, fontWeight: 500, color: '#374151' }}>
                Block unknown domains
              </div>
              <div style={{ fontSize: 11, color: '#9ca3af', marginTop: 2 }}>
                Block domains not present in either the allowed or blocked list (default-deny mode)
              </div>
            </div>
            <SegControl
              value={network.block_unknown_domains ? 'yes' : 'no'}
              onChange={(v) => updateNetwork({ block_unknown_domains: v === 'yes' })}
              options={[
                { label: 'Yes', value: 'yes', activeClass: 'yn-yes' },
                { label: 'No', value: 'no', activeClass: 'yn-no' },
              ]}
            />
          </div>
        </div>

        <div style={{
          background: 'white',
          border: '1px solid #e5e7eb',
          borderRadius: 8,
          marginBottom: 12,
          overflow: 'hidden',
        }}>
          <div style={{ padding: '10px 16px', borderBottom: '1px solid #f3f4f6' }}>
            <span style={{
              fontSize: 11,
              fontWeight: 600,
              color: '#6b7280',
              textTransform: 'uppercase',
              letterSpacing: '0.06em',
            }}>
              Network commands
            </span>
          </div>
          <div style={{ padding: '14px 16px' }}>
            <p style={{ fontSize: 11, color: '#9ca3af', marginBottom: 10, lineHeight: 1.5 }}>
              Commands that trigger network policy evaluation. Listing a command here does not block it — it determines whether domain rules are checked when the command runs.
            </p>

            <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
              <input
                value={newNetworkCommand}
                onChange={(e) => setNewNetworkCommand(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && addNetworkCommand()}
                placeholder="Add command (e.g. curl)"
                style={{
                  flex: 1,
                  fontSize: 12,
                  fontFamily: 'monospace',
                  padding: '6px 10px',
                  borderRadius: 5,
                  border: '1px solid #d1d5db',
                  outline: 'none',
                }}
              />
              <button
                onClick={() => addNetworkCommand()}
                style={{
                  background: '#4f46e5',
                  color: 'white',
                  border: 'none',
                  borderRadius: 5,
                  padding: '6px 14px',
                  fontSize: 11,
                  fontWeight: 500,
                  cursor: 'pointer',
                  flexShrink: 0,
                }}
              >
                Add
              </button>
            </div>

            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {commands.map((cmd) => (
                <div key={cmd} style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 5,
                  padding: '3px 8px',
                  borderRadius: 5,
                  border: '1px solid #e5e7eb',
                  background: '#fafafa',
                  fontSize: 12,
                  fontFamily: 'monospace',
                  color: '#374151',
                }}>
                  {cmd}
                  <button
                    onClick={() => removeNetworkCommand(cmd)}
                    style={{
                      width: 14,
                      height: 14,
                      border: 'none',
                      background: 'none',
                      cursor: 'pointer',
                      color: '#9ca3af',
                      fontSize: 13,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      borderRadius: 3,
                      padding: 0,
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.color = '#dc2626'
                      e.currentTarget.style.background = '#fee2e2'
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.color = '#9ca3af'
                      e.currentTarget.style.background = 'none'
                    }}
                  >
                    ×
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div style={{
          background: 'white',
          border: '1px solid #e5e7eb',
          borderRadius: 8,
          marginBottom: 12,
          overflow: 'hidden',
        }}>
          <div style={{ padding: '10px 16px', borderBottom: '1px solid #f3f4f6' }}>
            <span style={{
              fontSize: 11,
              fontWeight: 600,
              color: '#6b7280',
              textTransform: 'uppercase',
              letterSpacing: '0.06em',
            }}>
              Domain rules
            </span>
          </div>
          <div style={{
            padding: '8px 16px 10px',
            fontSize: 11,
            color: '#9ca3af',
            borderBottom: '1px solid #f3f4f6',
          }}>
            Blocklist takes precedence over allowlist when a domain appears in both.
          </div>

          <div style={{
            display: 'grid',
            gridTemplateColumns: '1fr 1fr',
            gap: 12,
            padding: '12px 16px',
          }}>
            <DomainColumn
              title="Allowed domains"
              titleColor="#15803d"
              placeholder="api.github.com"
              domains={allowedDomains}
              onAdd={addAllowedDomain}
              onRemove={removeAllowedDomain}
              emptyText="No allowed domains — all domains permitted by default"
              addButtonStyle={{ background: '#4f46e5', color: 'white', border: 'none' }}
            />

            <DomainColumn
              title="Blocked domains"
              titleColor="#dc2626"
              placeholder="malicious.example.com"
              domains={blockedDomains}
              onAdd={addBlockedDomain}
              onRemove={removeBlockedDomain}
              emptyText="No blocked domains"
              addButtonStyle={{
                background: 'white',
                color: '#dc2626',
                border: '1px solid #fecaca',
              }}
            />
          </div>
        </div>
      </div>
    )
  }

  function AdvancedPolicyPanel() {
    const confirmation = draftPolicy?.requires_confirmation || {}
    const approvalSecurity = confirmation?.approval_security || {}
    const execution = draftPolicy?.execution || {}
    const shellContainment = execution?.shell_workspace_containment || {}
    const backupAccess = draftPolicy?.backup_access || {}
    const restore = draftPolicy?.restore || {}
    const audit = draftPolicy?.audit || {}
    const reportsCfg = draftPolicy?.reports || {}
    const scriptSentinel = draftPolicy?.script_sentinel || {}

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

    const redactPatternsText = Array.isArray(audit.redact_patterns) ? audit.redact_patterns.join('\n') : ''
    const scanSizeMb = Math.max(1, Math.round((scriptSentinel.max_scan_bytes ?? 1048576) / 1048576))
    const scanModeValue = scriptSentinel.scan_mode || 'exec_context'
    const yesNoOptions = [
      { label: 'Yes', value: true, activeClass: 'yn-yes' },
      { label: 'No', value: false, activeClass: 'yn-no' },
    ]

    const rowClass = 'grid grid-cols-1 md:grid-cols-[1fr_260px] gap-3 items-center p-4 border-t border-slate-200'
    const titleClass = 'text-sm font-semibold text-slate-800'
    const helpClass = 'text-xs text-slate-400 mt-1'

    const CardHeader = ({ icon, iconBg, iconFg, title, subtitle, right = null }) => (
      <div className="flex items-center justify-between gap-3 p-4">
        <div className="flex items-center gap-3">
          <div
            style={{
              width: 28,
              height: 28,
              borderRadius: 6,
              background: iconBg,
              color: iconFg,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: 13,
              fontWeight: 700,
              flexShrink: 0,
            }}
          >
            {icon}
          </div>
          <div>
            <div className={titleClass}>{title}</div>
            <div className={helpClass}>{subtitle}</div>
          </div>
        </div>
        {right}
      </div>
    )

    const AdvancedToggle = ({ open, onToggle }) => (
      <button
        type="button"
        onClick={onToggle}
        className="w-full flex items-center gap-2 px-4 py-2 border-t border-slate-200 bg-slate-50/60 text-slate-400 hover:text-slate-500"
      >
        <span className={`text-xs transition ${open ? 'rotate-0' : '-rotate-90'}`}>▾</span>
        <span className="text-xs font-semibold tracking-[0.08em] uppercase">Advanced</span>
      </button>
    )

    return (
      <div className="space-y-3">
        <div className="bg-white border border-slate-200 rounded-[10px] shadow-sm overflow-hidden">
          <CardHeader
            icon="☑"
            iconBg="#e2e8f0"
            iconFg="#2563eb"
            title="Backup"
            subtitle="Automatic backups before destructive and overwrite operations"
            right={(
              <div style={{ width: 122 }}>
                <SegControl
                  value={Boolean(audit.backup_enabled)}
                  onChange={(enabled) => setAudit({ backup_enabled: Boolean(enabled) })}
                  options={yesNoOptions}
                />
              </div>
            )}
          />

          <div className={rowClass}>
            <div>
              <div className={titleClass}>Backup on content change only</div>
              <div className={helpClass}>Skip backup if file content hasn't changed (deduplication by SHA256)</div>
            </div>
            <div style={{ width: 122, justifySelf: 'end' }}>
              <SegControl
                value={Boolean(audit.backup_on_content_change_only)}
                onChange={(enabled) => setAudit({ backup_on_content_change_only: Boolean(enabled) })}
                options={yesNoOptions}
              />
            </div>
          </div>

          <div className={rowClass}>
            <div>
              <div className={titleClass}>Retention</div>
              <div className={helpClass}>Remove backups older than this</div>
            </div>
            <label className="flex items-center gap-2 justify-self-end w-full">
              <input
                type="number"
                min={0}
                className="w-full border border-slate-300 rounded-[8px] px-3 py-2 text-sm text-right font-mono"
                value={audit.backup_retention_days ?? 30}
                onChange={(e) => setAudit({ backup_retention_days: Math.max(0, parseInt(e.target.value, 10) || 0) })}
              />
              <span className="text-xs text-slate-400">days</span>
            </label>
          </div>

          <AdvancedToggle open={advancedBackupOpen} onToggle={() => setAdvancedBackupOpen((v) => !v)} />

          {advancedBackupOpen && (
            <>
              <div className={rowClass}>
                <div>
                  <div className={titleClass}>Max versions per file</div>
                </div>
                <label className="flex items-center gap-2 justify-self-end w-full">
                  <input
                    type="number"
                    min={1}
                    className="w-full border border-slate-300 rounded-[8px] px-3 py-2 text-sm text-right font-mono"
                    value={audit.max_versions_per_file ?? 5}
                    onChange={(e) => setAudit({ max_versions_per_file: Math.max(1, parseInt(e.target.value, 10) || 1) })}
                  />
                  <span className="text-xs text-slate-400">versions</span>
                </label>
              </div>

              <div className={rowClass}>
                <div>
                  <div className={titleClass}>Backup root</div>
                  <div className={helpClass}>Runtime backup directory for snapshots and restore operations</div>
                </div>
                <input
                  type="text"
                  className="w-full border border-slate-300 rounded-[8px] px-3 py-2 text-sm font-mono"
                  value={audit.backup_root ?? ''}
                  onChange={(e) => setAudit({ backup_root: e.target.value })}
                />
              </div>

              <div className={rowClass}>
                <div>
                  <div className={titleClass}>Protect backup storage from agents</div>
                  <div className={helpClass}>Block agent tools from accessing the backup directory</div>
                </div>
                <div style={{ width: 122, justifySelf: 'end' }}>
                  <SegControl
                    value={Boolean(backupAccess.block_agent_tools)}
                    onChange={(enabled) => setBackupAccess({ block_agent_tools: Boolean(enabled) })}
                    options={yesNoOptions}
                  />
                </div>
              </div>

              <div className={rowClass}>
                <div>
                  <div className={titleClass}>Require dry run before restore apply</div>
                  <div className={helpClass}>Apply step requires a valid token from a prior dry-run</div>
                </div>
                <div style={{ width: 122, justifySelf: 'end' }}>
                  <SegControl
                    value={Boolean(restore.require_dry_run_before_apply)}
                    onChange={(enabled) => setRestore({ require_dry_run_before_apply: Boolean(enabled) })}
                    options={yesNoOptions}
                  />
                </div>
              </div>

              <div className={rowClass}>
                <div>
                  <div className={titleClass}>Restore confirmation TTL</div>
                  <div className={helpClass}>Dry-run token expires after this period</div>
                </div>
                <label className="flex items-center gap-2 justify-self-end w-full">
                  <input
                    type="number"
                    min={30}
                    className="w-full border border-slate-300 rounded-[8px] px-3 py-2 text-sm text-right font-mono"
                    value={restore.confirmation_ttl_seconds ?? 300}
                    onChange={(e) => setRestore({ confirmation_ttl_seconds: Math.max(30, parseInt(e.target.value, 10) || 30) })}
                  />
                  <span className="text-xs text-slate-400">seconds</span>
                </label>
              </div>
            </>
          )}
        </div>

        <div className="bg-white border border-slate-200 rounded-[10px] shadow-sm overflow-hidden">
          <CardHeader
            icon="↳"
            iconBg="#dcfce7"
            iconFg="#15803d"
            title="Shell workspace containment"
            subtitle="Heuristic path guard for shell command arguments and redirection targets"
          />

          <div className={rowClass}>
            <div>
              <div className={titleClass}>Containment mode</div>
              <div className={helpClass}>Off: no containment · Monitor: log violations, allow execution · Enforce: block out-of-workspace shell paths</div>
            </div>
            <div style={{ width: 200, justifySelf: 'end' }}>
              <SegControl
                value={shellContainment.mode || 'off'}
                onChange={(mode) => setShellContainment({ mode })}
                options={[
                  { label: 'Off', value: 'off', activeClass: 'm-off' },
                  { label: 'Monitor', value: 'monitor', activeClass: 'm-monitor' },
                  { label: 'Enforce', value: 'enforce', activeClass: 'm-enforce' },
                ]}
              />
            </div>
          </div>

          <div className={rowClass}>
            <div>
              <div className={titleClass}>Log paths</div>
              <div className={helpClass}>Emit path observations to activity log even when mode is off</div>
            </div>
            <div style={{ width: 122, justifySelf: 'end' }}>
              <SegControl
                value={Boolean(shellContainment.log_paths)}
                onChange={(enabled) => setShellContainment({ log_paths: Boolean(enabled) })}
                options={yesNoOptions}
              />
            </div>
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-[10px] shadow-sm overflow-hidden">
          <CardHeader
            icon="◔"
            iconBg="#fef3c7"
            iconFg="#b45309"
            title="Command execution limits"
            subtitle="Safety caps on runtime duration and output size"
          />

          <div className={rowClass}>
            <div>
              <div className={titleClass}>Max command timeout</div>
              <div className={helpClass}>Hard limit before command is killed</div>
            </div>
            <label className="flex items-center gap-2 justify-self-end w-full">
              <input
                type="number"
                min={1}
                className="w-full border border-slate-300 rounded-[8px] px-3 py-2 text-sm text-right font-mono"
                value={execution.max_command_timeout_seconds ?? 30}
                onChange={(e) => setExecution({ max_command_timeout_seconds: Math.max(1, parseInt(e.target.value, 10) || 1) })}
              />
              <span className="text-xs text-slate-400">seconds</span>
            </label>
          </div>

          <div className={rowClass}>
            <div>
              <div className={titleClass}>Max output</div>
              <div className={helpClass}>Output truncated beyond this limit</div>
            </div>
            <label className="flex items-center gap-2 justify-self-end w-full">
              <input
                type="number"
                min={1024}
                className="w-full border border-slate-300 rounded-[8px] px-3 py-2 text-sm text-right font-mono"
                value={execution.max_output_chars ?? 200000}
                onChange={(e) => setExecution({ max_output_chars: Math.max(1024, parseInt(e.target.value, 10) || 1024) })}
              />
              <span className="text-xs text-slate-400">chars</span>
            </label>
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-[10px] shadow-sm overflow-hidden">
          <CardHeader
            icon="🔒"
            iconBg="#ede9fe"
            iconFg="#7c3aed"
            title="Command approval security"
            subtitle="Token security and failed-attempt throttling for confirmation-gated commands"
          />

          <div className={rowClass}>
            <div>
              <div className={titleClass}>Approval token TTL</div>
              <div className={helpClass}>Token expires after this period if unused</div>
            </div>
            <label className="flex items-center gap-2 justify-self-end w-full">
              <input
                type="number"
                min={0}
                className="w-full border border-slate-300 rounded-[8px] px-3 py-2 text-sm text-right font-mono"
                value={approvalSecurity.token_ttl_seconds ?? 600}
                onChange={(e) => setConfirmationSecurity({ token_ttl_seconds: Math.max(0, parseInt(e.target.value, 10) || 0) })}
              />
              <span className="text-xs text-slate-400">seconds</span>
            </label>
          </div>

          <div className={rowClass}>
            <div>
              <div className={titleClass}>Max failed attempts per token</div>
              <div className={helpClass}>Token is invalidated after this many failed attempts</div>
            </div>
            <label className="flex items-center gap-2 justify-self-end w-full">
              <input
                type="number"
                min={0}
                className="w-full border border-slate-300 rounded-[8px] px-3 py-2 text-sm text-right font-mono"
                value={approvalSecurity.max_failed_attempts_per_token ?? 5}
                onChange={(e) => setConfirmationSecurity({ max_failed_attempts_per_token: Math.max(0, parseInt(e.target.value, 10) || 0) })}
              />
              <span className="text-xs text-slate-400">attempts</span>
            </label>
          </div>

          <div className={rowClass}>
            <div>
              <div className={titleClass}>Failed attempt window</div>
              <div className={helpClass}>Failure count resets after this period of inactivity</div>
            </div>
            <label className="flex items-center gap-2 justify-self-end w-full">
              <input
                type="number"
                min={0}
                className="w-full border border-slate-300 rounded-[8px] px-3 py-2 text-sm text-right font-mono"
                value={approvalSecurity.failed_attempt_window_seconds ?? 600}
                onChange={(e) => setConfirmationSecurity({ failed_attempt_window_seconds: Math.max(0, parseInt(e.target.value, 10) || 0) })}
              />
              <span className="text-xs text-slate-400">seconds</span>
            </label>
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-[10px] shadow-sm overflow-hidden">
          <CardHeader
            icon="⛨"
            iconBg="#fee2e2"
            iconFg="#dc2626"
            title="Script sentinel"
            subtitle="Scans content written via write_file for blocked or approval-gated command patterns"
            right={(
              <div style={{ width: 122 }}>
                <SegControl
                  value={Boolean(scriptSentinel.enabled)}
                  onChange={(enabled) => setScriptSentinel({ enabled: Boolean(enabled) })}
                  options={yesNoOptions}
                />
              </div>
            )}
          />

          <div className={rowClass}>
            <div>
              <div className={titleClass}>Mode</div>
              <div className={helpClass}>What to do when a blocked pattern is detected in written file content</div>
            </div>
            <div style={{ width: 260, justifySelf: 'end' }}>
              <SegControl
                value={scriptSentinel.mode || 'match_original'}
                onChange={(mode) => setScriptSentinel({ mode })}
                options={[
                  { label: 'Match original', value: 'match_original', activeClass: 'm-blue' },
                  { label: 'Block', value: 'block', activeClass: 'active-block' },
                  { label: 'Confirm', value: 'requires_confirmation', activeClass: 'active-confirm' },
                ]}
              />
            </div>
          </div>

          <div className={rowClass}>
            <div>
              <div className={titleClass}>Scan mode</div>
              <div className={helpClass}>Choose executable-context only, or include mention-only audit hits</div>
            </div>
            <div style={{ width: 260, justifySelf: 'end' }}>
              <SegControl
                value={scanModeValue}
                onChange={(scan_mode) => setScriptSentinel({ scan_mode })}
                options={[
                  { label: 'Exec context', value: 'exec_context', activeClass: 'm-blue' },
                  { label: 'Exec + mentions', value: 'exec_context_plus_mentions', activeClass: 'active-confirm' },
                ]}
              />
            </div>
          </div>

          <div className={rowClass}>
            <div>
              <div className={titleClass}>Include common wrapper signatures</div>
              <div className={helpClass}>Extend detection to common shell wrapper patterns</div>
            </div>
            <div style={{ width: 122, justifySelf: 'end' }}>
              <SegControl
                value={Boolean(scriptSentinel.include_wrappers)}
                onChange={(enabled) => setScriptSentinel({ include_wrappers: Boolean(enabled) })}
                options={yesNoOptions}
              />
            </div>
          </div>

          <div className={rowClass}>
            <div>
              <div className={titleClass}>Max scan size</div>
              <div className={helpClass}>Files larger than this are skipped for write-time scanning</div>
            </div>
            <label className="flex items-center gap-2 justify-self-end w-full">
              <input
                type="number"
                min={1}
                className="w-full border border-slate-300 rounded-[8px] px-3 py-2 text-sm text-right font-mono"
                value={scanSizeMb}
                onChange={(e) => {
                  const mb = Math.max(1, parseInt(e.target.value, 10) || 1)
                  setScriptSentinel({ max_scan_bytes: mb * 1024 * 1024 })
                }}
              />
              <span className="text-xs text-slate-400">MB</span>
            </label>
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-[10px] shadow-sm overflow-hidden">
          <CardHeader
            icon="📊"
            iconBg="#e2e8f0"
            iconFg="#2563eb"
            title="Reports & logs"
            subtitle="Activity ingestion, retention, and log redaction patterns"
            right={(
              <div style={{ width: 122 }}>
                <SegControl
                  value={Boolean(reportsCfg.enabled)}
                  onChange={(enabled) => setReportsConfig({ enabled: Boolean(enabled) })}
                  options={yesNoOptions}
                />
              </div>
            )}
          />

          <div className={rowClass}>
            <div>
              <div className={titleClass}>Retention</div>
              <div className={helpClass}>Events older than this are pruned from reports.db</div>
            </div>
            <label className="flex items-center gap-2 justify-self-end w-full">
              <input
                type="number"
                min={1}
                className="w-full border border-slate-300 rounded-[8px] px-3 py-2 text-sm text-right font-mono"
                value={reportsCfg.retention_days ?? 30}
                onChange={(e) => setReportsConfig({ retention_days: Math.max(1, parseInt(e.target.value, 10) || 1) })}
              />
              <span className="text-xs text-slate-400">days</span>
            </label>
          </div>

          <div className={rowClass}>
            <div>
              <div className={titleClass}>Max database size</div>
              <div className={helpClass}>Oldest events pruned when size limit is reached</div>
            </div>
            <label className="flex items-center gap-2 justify-self-end w-full">
              <input
                type="number"
                min={10}
                className="w-full border border-slate-300 rounded-[8px] px-3 py-2 text-sm text-right font-mono"
                value={reportsCfg.max_db_size_mb ?? 200}
                onChange={(e) => setReportsConfig({ max_db_size_mb: Math.max(10, parseInt(e.target.value, 10) || 10) })}
              />
              <span className="text-xs text-slate-400">MB</span>
            </label>
          </div>

          <AdvancedToggle open={advancedReportsOpen} onToggle={() => setAdvancedReportsOpen((v) => !v)} />

          {advancedReportsOpen && (
            <>
              <div className={rowClass}>
                <div>
                  <div className={titleClass}>Ingest poll interval</div>
                  <div className={helpClass}>How often activity.log is checked for new events</div>
                </div>
                <label className="flex items-center gap-2 justify-self-end w-full">
                  <input
                    type="number"
                    min={1}
                    className="w-full border border-slate-300 rounded-[8px] px-3 py-2 text-sm text-right font-mono"
                    value={reportsCfg.ingest_poll_interval_seconds ?? 5}
                    onChange={(e) => setReportsConfig({ ingest_poll_interval_seconds: Math.max(1, parseInt(e.target.value, 10) || 1) })}
                  />
                  <span className="text-xs text-slate-400">seconds</span>
                </label>
              </div>

              <div className={rowClass}>
                <div>
                  <div className={titleClass}>Reconcile interval</div>
                  <div className={helpClass}>How often log rotation/truncation is checked</div>
                </div>
                <label className="flex items-center gap-2 justify-self-end w-full">
                  <input
                    type="number"
                    min={60}
                    className="w-full border border-slate-300 rounded-[8px] px-3 py-2 text-sm text-right font-mono"
                    value={reportsCfg.reconcile_interval_seconds ?? 3600}
                    onChange={(e) => setReportsConfig({ reconcile_interval_seconds: Math.max(60, parseInt(e.target.value, 10) || 60) })}
                  />
                  <span className="text-xs text-slate-400">seconds</span>
                </label>
              </div>

              <div className={rowClass}>
                <div>
                  <div className={titleClass}>Prune interval</div>
                  <div className={helpClass}>How often retention and size limits are enforced</div>
                </div>
                <label className="flex items-center gap-2 justify-self-end w-full">
                  <input
                    type="number"
                    min={300}
                    className="w-full border border-slate-300 rounded-[8px] px-3 py-2 text-sm text-right font-mono"
                    value={reportsCfg.prune_interval_seconds ?? 86400}
                    onChange={(e) => setReportsConfig({ prune_interval_seconds: Math.max(300, parseInt(e.target.value, 10) || 300) })}
                  />
                  <span className="text-xs text-slate-400">seconds</span>
                </label>
              </div>
            </>
          )}
        </div>

        <div className="bg-white border border-slate-200 rounded-[10px] shadow-sm overflow-hidden">
          <div className="px-4 py-2 border-b border-slate-200 bg-slate-50/60 text-xs font-semibold tracking-[0.06em] text-slate-400 uppercase">
            Log redaction — always active
          </div>
          <div className="p-4 space-y-3">
            <div className="text-sm text-blue-700 bg-blue-50 border border-blue-200 rounded-[6px] px-3 py-2">
              Redaction patterns apply to activity.log regardless of whether reports are enabled.
            </div>
            <label className="text-xs text-slate-600 block">
              Redact patterns
              <div className="text-[11px] text-slate-400 mt-1 mb-2">One regex per line. Matched values are replaced with &lt;redacted&gt; in activity.log</div>
              <textarea
                className="w-full border border-slate-300 rounded-[8px] px-3 py-2 text-xs font-mono h-28"
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

      </div>
    )
  }

  function AgentOverridesPanel() {
    const overrides = draftPolicy?.agent_overrides || {}
    const selectedPolicy = overrideAgentId ? (overrides?.[overrideAgentId]?.policy || {}) : {}
    const overrideCount = overrideAgentId ? AGENT_OVERRIDE_SECTIONS.filter((section) => Object.prototype.hasOwnProperty.call(selectedPolicy || {}, section)).length : 0

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

    const addTagValue = (section, field, raw, transform = (v) => v) => {
      const normalized = transform(String(raw || '').trim())
      if (!normalized) {
        setMessage('Value is required')
        return false
      }
      const current = sectionValue(section)
      const list = Array.isArray(current?.[field]) ? current[field] : []
      const next = { ...(current || {}), [field]: Array.from(new Set([...list, normalized])) }
      setSectionValue(section, next)
      return true
    }

    const removeTagValue = (section, field, item) => {
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
      setAgentOverridePolicy(overrideAgentId, (policy) => {
        const out = { ...(policy || {}) }
        out[section] = out[section] || {}
        return out
      })
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
      setOverrideBaselineModal({
        open: true,
        sectionLabel: AGENT_OVERRIDE_SECTION_LABELS[section],
        baselineData: baseline,
      })
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
      const lines = []

      const scalarText = (value) => {
        if (value === undefined) return 'undefined'
        if (value === null) return 'null'
        if (typeof value === 'string') return value
        return String(value)
      }

      const addListLine = (label, delta) => {
        delta.added.forEach((item) => lines.push({ type: 'added', text: `${label}: ${item}` }))
        delta.removed.forEach((item) => lines.push({ type: 'removed', text: `${label}: ${item}` }))
      }
      const addScalarLine = (label, baseValue, effectiveValue) => {
        if (JSON.stringify(baseValue) !== JSON.stringify(effectiveValue)) {
          lines.push({ type: 'removed', text: `${label}: ${scalarText(baseValue)}` })
          lines.push({ type: 'added', text: `${label}: ${scalarText(effectiveValue)}` })
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

      const allowedBase = draftPolicy?.allowed || {}
      const allowedEff = sectionValue('allowed')
      addListLine('Allowed paths whitelist', listDelta(allowedBase.paths_whitelist, allowedEff.paths_whitelist))
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

      setOverrideDiffModal({
        open: true,
        agentId: overrideAgentId,
        lines,
      })
    }

    const linkCodeStyle = {
      fontFamily: 'monospace',
      background: 'rgba(3,105,161,0.1)',
      padding: '0 4px',
      borderRadius: 3,
      fontSize: 11,
    }

    function SectionRow({ sectionKey, label, isOverridden, isOpen, onToggleOpen, onToggleOverride, onInfo }) {
      return (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            padding: '11px 16px',
            cursor: 'pointer',
            userSelect: 'none',
            transition: 'background 0.1s',
          }}
          onMouseEnter={(e) => { e.currentTarget.style.background = '#fafafa' }}
          onMouseLeave={(e) => { e.currentTarget.style.background = 'white' }}
          onClick={onToggleOpen}
        >
          <svg
            style={{
              width: 14,
              height: 14,
              color: '#9ca3af',
              flexShrink: 0,
              transform: isOpen ? 'rotate(90deg)' : 'none',
              transition: 'transform 0.2s',
            }}
            viewBox="0 0 10 10"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.5"
          >
            <path d="M3 2l3 3-3 3" />
          </svg>

          <span style={{ fontSize: 13, fontWeight: 600, color: '#111827', flex: 1 }}>
            {label}
          </span>

          <span style={{
            fontSize: 10,
            fontWeight: 600,
            padding: '2px 8px',
            borderRadius: 10,
            background: isOverridden ? '#eef2ff' : '#f3f4f6',
            color: isOverridden ? '#4f46e5' : '#6b7280',
          }}>
            {isOverridden ? 'Overridden' : 'Inherited'}
          </span>

          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }} onClick={(e) => e.stopPropagation()}>
            <button
              onClick={onInfo}
              title="View baseline"
              style={{
                width: 22,
                height: 22,
                borderRadius: 4,
                border: '1px solid #e5e7eb',
                background: 'white',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#9ca3af',
                fontSize: 11,
                fontWeight: 600,
                fontFamily: 'serif',
                fontStyle: 'italic',
                transition: 'all 0.15s',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.borderColor = '#c7d2fe'
                e.currentTarget.style.color = '#4f46e5'
                e.currentTarget.style.background = '#eef2ff'
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = '#e5e7eb'
                e.currentTarget.style.color = '#9ca3af'
                e.currentTarget.style.background = 'white'
              }}
            >
              i
            </button>

            <div style={{ display: 'flex', background: '#f3f4f6', borderRadius: 5, padding: 2 }}>
              {[
                { label: 'Inherit', active: !isOverridden, activeStyle: { background: 'white', color: '#374151' } },
                { label: 'Override', active: isOverridden, activeStyle: { background: 'white', color: '#4f46e5' } },
              ].map((option) => (
                <div
                  key={`${sectionKey}-${option.label}`}
                  onClick={() => {
                    if (option.label === 'Inherit' && isOverridden) onToggleOverride()
                    if (option.label === 'Override' && !isOverridden) onToggleOverride()
                  }}
                  style={{
                    fontSize: 10,
                    fontWeight: 500,
                    padding: '4px 10px',
                    borderRadius: 4,
                    cursor: 'pointer',
                    color: '#6b7280',
                    userSelect: 'none',
                    transition: 'all 0.15s',
                    boxShadow: option.active ? '0 1px 2px rgba(0,0,0,0.07)' : 'none',
                    ...(option.active ? option.activeStyle : {}),
                  }}
                >
                  {option.label}
                </div>
              ))}
            </div>
          </div>
        </div>
      )
    }

    function TagEditor({ sectionKey, field, tags, onAdd, onRemove, transform = (v) => v }) {
      const [input, setInput] = useState('')
      const handleAdd = () => {
        if (!input.trim()) return
        const ok = onAdd(sectionKey, field, input.trim(), transform)
        if (ok) setInput('')
      }
      return (
        <div style={{ marginBottom: 14 }}>
          <div
            style={{
              fontSize: 10,
              fontWeight: 600,
              textTransform: 'uppercase',
              letterSpacing: '0.06em',
              color: '#9ca3af',
              marginBottom: 8,
            }}
          >
            {field.replace(/_/g, ' ')}
          </div>
          <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleAdd()}
              placeholder={`Add ${field.replace(/_/g, ' ')}...`}
              style={{
                flex: 1,
                fontSize: 12,
                fontFamily: 'monospace',
                padding: '6px 10px',
                borderRadius: 5,
                border: '1px solid #d1d5db',
                outline: 'none',
              }}
              onFocus={(e) => {
                e.currentTarget.style.borderColor = '#4f46e5'
                e.currentTarget.style.boxShadow = '0 0 0 2px rgba(79,70,229,0.1)'
              }}
              onBlur={(e) => {
                e.currentTarget.style.borderColor = '#d1d5db'
                e.currentTarget.style.boxShadow = 'none'
              }}
            />
            <button
              onClick={handleAdd}
              style={{
                background: '#4f46e5',
                color: 'white',
                border: 'none',
                borderRadius: 5,
                padding: '6px 14px',
                fontSize: 11,
                fontWeight: 500,
                cursor: 'pointer',
                flexShrink: 0,
              }}
            >
              Add
            </button>
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, minHeight: 28 }}>
            {tags.length === 0 ? (
              <span style={{ fontSize: 11, color: '#d1d5db', fontStyle: 'italic' }}>
                No entries — inheriting baseline
              </span>
            ) : tags.map((tag, i) => (
              <div
                key={`${field}-${tag}-${i}`}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 4,
                  padding: '3px 8px',
                  borderRadius: 5,
                  border: '1px solid #e5e7eb',
                  background: '#fafafa',
                  fontSize: 12,
                  fontFamily: 'monospace',
                  color: '#374151',
                }}
              >
                {tag}
                <button
                  onClick={() => onRemove(sectionKey, field, tag)}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: '#9ca3af',
                    cursor: 'pointer',
                    fontSize: 14,
                    lineHeight: 1,
                    padding: '0 1px',
                    borderRadius: 2,
                    transition: 'all 0.12s',
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.color = '#dc2626'
                    e.currentTarget.style.background = '#fee2e2'
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.color = '#9ca3af'
                    e.currentTarget.style.background = 'none'
                  }}
                >
                  ×
                </button>
              </div>
            ))}
          </div>
        </div>
      )
    }

    return (
      <div className="space-y-3">
        <div className="bg-white border border-slate-200 rounded-[10px] p-3 shadow-sm space-y-3">
          <div className="text-sm font-semibold text-slate-800">Agent Overrides</div>
          <div
            style={{
              background: '#f0f9ff',
              border: '1px solid #bae6fd',
              borderRadius: 7,
              padding: '10px 14px',
              marginBottom: 12,
              fontSize: 11,
              color: '#0369a1',
              lineHeight: 1.6,
            }}
          >
            Baseline policy remains global. Agent overrides apply only to:{' '}
            {['blocked', 'requires_confirmation', 'allowed', 'network', 'execution'].map((section, i, arr) => (
              <span key={section}>
                <code style={linkCodeStyle}>{section}</code>
                {i < arr.length - 1 ? ', ' : '. '}
              </span>
            ))}
            Workspace remains controlled by MCP env (<code style={linkCodeStyle}>AIRG_WORKSPACE</code>), not policy overrides.
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12, flexWrap: 'wrap' }}>
            <div style={{ position: 'relative', maxWidth: 320, width: '100%' }}>
              <select
                value={overrideAgentId}
                onChange={(e) => setOverrideAgentId(e.target.value)}
                style={{
                  width: '100%',
                  fontSize: 13,
                  fontWeight: 500,
                  color: '#111827',
                  padding: '7px 32px 7px 12px',
                  borderRadius: 6,
                  border: '1px solid #d1d5db',
                  background: 'white',
                  appearance: 'none',
                  cursor: 'pointer',
                  outline: 'none',
                  fontFamily: 'inherit',
                }}
                onFocus={(e) => {
                  e.currentTarget.style.borderColor = '#4f46e5'
                  e.currentTarget.style.boxShadow = '0 0 0 2px rgba(79,70,229,0.1)'
                }}
                onBlur={(e) => {
                  e.currentTarget.style.borderColor = '#d1d5db'
                  e.currentTarget.style.boxShadow = 'none'
                }}
              >
                <option value="">Select agent…</option>
                {knownAgentIds.map((id) => (
                  <option key={id} value={id}>{id}</option>
                ))}
              </select>
              <svg
                style={{
                  position: 'absolute',
                  right: 10,
                  top: '50%',
                  transform: 'translateY(-50%)',
                  pointerEvents: 'none',
                  color: '#9ca3af',
                }}
                width="12"
                height="12"
                viewBox="0 0 14 14"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.5"
              >
                <path d="M3 5l4 4 4-4" />
              </svg>
            </div>

            <span style={{ fontSize: 11, color: '#9ca3af' }}>
              <strong style={{ color: '#4f46e5', fontWeight: 600 }}>{overrideCount}</strong>{' '}
              section{overrideCount !== 1 ? 's' : ''} overridden
            </span>

            <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
              <span
                onClick={() => {
                  setActiveRail('settings')
                  setActiveSettingsTab('agents')
                }}
                style={{ fontSize: 11, color: '#4f46e5', cursor: 'pointer', textDecoration: 'none' }}
                onMouseEnter={(e) => { e.currentTarget.style.textDecoration = 'underline' }}
                onMouseLeave={(e) => { e.currentTarget.style.textDecoration = 'none' }}
              >
                Manage profiles in Settings → Agents
              </span>
              <button
                onClick={summarizeQuickDiff}
                disabled={!overrideAgentId}
                className="btn btn-ghost disabled:opacity-50"
              >
                Quick Diff
              </button>
              <button
                onClick={resetAgentOverrides}
                disabled={!overrideAgentId}
                className="btn disabled:opacity-50"
                style={{ color: '#b45309', borderColor: '#fde68a' }}
              >
                Reset to Inherited
              </button>
            </div>
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
              const sectionData = sectionValue(section)
              return (
                <div key={section} className="bg-white border border-slate-200 rounded-[10px] shadow-sm overflow-hidden">
                  <SectionRow
                    sectionKey={section}
                    label={AGENT_OVERRIDE_SECTION_LABELS[section]}
                    isOverridden={enabled}
                    isOpen={expanded}
                    onToggleOpen={() => toggleExpanded(section)}
                    onToggleOverride={() => {
                      if (enabled) setInherit(section)
                      else setOverride(section)
                    }}
                    onInfo={() => showBaselineInfo(section)}
                  />

                  {expanded && enabled && (
                    <div style={{ padding: '12px 16px', borderTop: '1px solid #f3f4f6' }}>
                      {section === 'blocked' && (
                        ['commands', 'paths', 'extensions'].map((field) => (
                          <TagEditor
                            key={`${section}-${field}`}
                            sectionKey={section}
                            field={field}
                            tags={Array.isArray(sectionData?.[field]) ? sectionData[field] : []}
                            onAdd={addTagValue}
                            onRemove={removeTagValue}
                          />
                        ))
                      )}

                      {section === 'requires_confirmation' && (
                        ['commands', 'paths'].map((field) => (
                          <TagEditor
                            key={`${section}-${field}`}
                            sectionKey={section}
                            field={field}
                            tags={Array.isArray(sectionData?.[field]) ? sectionData[field] : []}
                            onAdd={addTagValue}
                            onRemove={removeTagValue}
                          />
                        ))
                      )}

                      {section === 'allowed' && (
                        <>
                          <TagEditor
                            sectionKey="allowed"
                            field="paths_whitelist"
                            tags={Array.isArray(sectionData?.paths_whitelist) ? sectionData.paths_whitelist : []}
                            onAdd={addTagValue}
                            onRemove={removeTagValue}
                          />
                          <label className="text-xs block">
                            Max directory depth
                            <input
                              type="number"
                              min={0}
                              className="mt-1 w-full border border-slate-300 rounded px-2 py-1 text-xs"
                              value={sectionData?.max_directory_depth ?? 0}
                              onChange={(e) => setSectionValue('allowed', {
                                ...sectionData,
                                max_directory_depth: Math.max(0, parseInt(e.target.value, 10) || 0),
                              })}
                            />
                          </label>
                        </>
                      )}

                      {section === 'network' && (
                        <>
                          <div style={{ maxWidth: 280, marginBottom: 12 }}>
                            <SegControl
                              value={sectionData?.enforcement_mode || 'off'}
                              onChange={(mode) => setSectionValue('network', { ...sectionData, enforcement_mode: mode })}
                              options={[
                                { label: 'Off', value: 'off', activeClass: 'm-off' },
                                { label: 'Monitor', value: 'monitor', activeClass: 'm-monitor' },
                                { label: 'Enforce', value: 'enforce', activeClass: 'm-enforce' },
                              ]}
                            />
                          </div>
                          <div style={{ maxWidth: 122, marginBottom: 12 }}>
                            <SegControl
                              value={Boolean(sectionData?.block_unknown_domains)}
                              onChange={(enabledValue) => setSectionValue('network', { ...sectionData, block_unknown_domains: Boolean(enabledValue) })}
                              options={[
                                { label: 'Yes', value: true, activeClass: 'yn-yes' },
                                { label: 'No', value: false, activeClass: 'yn-no' },
                              ]}
                            />
                          </div>
                          {['commands', 'allowed_domains', 'blocked_domains'].map((field) => (
                            <TagEditor
                              key={`${section}-${field}`}
                              sectionKey="network"
                              field={field}
                              tags={Array.isArray(sectionData?.[field]) ? sectionData[field] : []}
                              onAdd={addTagValue}
                              onRemove={removeTagValue}
                              transform={field.includes('domains') ? normalizeDomain : (v) => v}
                            />
                          ))}
                        </>
                      )}

                      {section === 'execution' && (
                        <>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 mb-3">
                            <label className="text-xs">
                              Max command timeout seconds
                              <input
                                type="number"
                                min={1}
                                className="mt-1 w-full border border-slate-300 rounded px-2 py-1 text-xs"
                                value={sectionData?.max_command_timeout_seconds ?? 30}
                                onChange={(e) => setSectionValue('execution', {
                                  ...sectionData,
                                  max_command_timeout_seconds: Math.max(1, parseInt(e.target.value, 10) || 1),
                                })}
                              />
                            </label>
                            <label className="text-xs">
                              Max output chars
                              <input
                                type="number"
                                min={1024}
                                className="mt-1 w-full border border-slate-300 rounded px-2 py-1 text-xs"
                                value={sectionData?.max_output_chars ?? 200000}
                                onChange={(e) => setSectionValue('execution', {
                                  ...sectionData,
                                  max_output_chars: Math.max(1024, parseInt(e.target.value, 10) || 1024),
                                })}
                              />
                            </label>
                          </div>

                          <div className="border border-slate-200 rounded-[10px] p-2 space-y-2">
                            <div className="text-xs font-semibold text-slate-700">shell_workspace_containment</div>
                            <div style={{ maxWidth: 280 }}>
                              <SegControl
                                value={sectionData?.shell_workspace_containment?.mode || 'off'}
                                onChange={(mode) => setSectionValue('execution', {
                                  ...sectionData,
                                  shell_workspace_containment: {
                                    ...(sectionData?.shell_workspace_containment || {}),
                                    mode,
                                  },
                                })}
                                options={[
                                  { label: 'Off', value: 'off', activeClass: 'm-off' },
                                  { label: 'Monitor', value: 'monitor', activeClass: 'm-monitor' },
                                  { label: 'Enforce', value: 'enforce', activeClass: 'm-enforce' },
                                ]}
                              />
                            </div>
                            <div style={{ maxWidth: 122 }}>
                              <SegControl
                                value={Boolean(sectionData?.shell_workspace_containment?.log_paths)}
                                onChange={(enabledValue) => setSectionValue('execution', {
                                  ...sectionData,
                                  shell_workspace_containment: {
                                    ...(sectionData?.shell_workspace_containment || {}),
                                    log_paths: Boolean(enabledValue),
                                  },
                                })}
                                options={[
                                  { label: 'Yes', value: true, activeClass: 'yn-yes' },
                                  { label: 'No', value: false, activeClass: 'yn-no' },
                                ]}
                              />
                            </div>
                            <TagEditor
                              sectionKey="execution"
                              field="exempt_commands"
                              tags={Array.isArray(sectionData?.shell_workspace_containment?.exempt_commands) ? sectionData.shell_workspace_containment.exempt_commands : []}
                              onAdd={(sectionKey, field, raw, transform) => {
                                const normalized = transform(String(raw || '').trim())
                                if (!normalized) return false
                                const current = sectionData?.shell_workspace_containment || {}
                                const list = Array.isArray(current.exempt_commands) ? current.exempt_commands : []
                                setSectionValue('execution', {
                                  ...sectionData,
                                  shell_workspace_containment: {
                                    ...current,
                                    exempt_commands: Array.from(new Set([...list, normalized])),
                                  },
                                })
                                return true
                              }}
                              onRemove={(_sectionKey, _field, value) => {
                                const current = sectionData?.shell_workspace_containment || {}
                                const list = Array.isArray(current.exempt_commands) ? current.exempt_commands : []
                                setSectionValue('execution', {
                                  ...sectionData,
                                  shell_workspace_containment: {
                                    ...current,
                                    exempt_commands: list.filter((item) => item !== value),
                                  },
                                })
                              }}
                            />
                          </div>
                        </>
                      )}
                    </div>
                  )}

                  {expanded && !enabled && (
                    <div
                      style={{
                        padding: '12px 16px',
                        borderTop: '1px solid #f3f4f6',
                        fontSize: 12,
                        color: '#9ca3af',
                        fontStyle: 'italic',
                      }}
                    >
                      This section inherits baseline values. Switch to Override to edit.
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
        {activePolicyTab === 'rules' && RulesPanel()}
        {activePolicyTab === 'network' && NetworkPanel()}
        {activePolicyTab === 'agent_overrides' && AgentOverridesPanel()}
        {activePolicyTab === 'advanced' && AdvancedPolicyPanel()}
        <div className="mt-4">
          <div
            onClick={() => setJsonOpen((x) => !x)}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              padding: '10px 16px',
              cursor: 'pointer',
              userSelect: 'none',
              background: 'white',
              border: '1px solid #e5e7eb',
              borderRadius: 8,
            }}
            onMouseEnter={(e) => { e.currentTarget.style.background = '#fafafa' }}
            onMouseLeave={(e) => { e.currentTarget.style.background = 'white' }}
          >
            <svg
              style={{
                width: 12,
                height: 12,
                color: '#9ca3af',
                transform: jsonOpen ? 'rotate(90deg)' : 'none',
                transition: 'transform 0.2s',
              }}
              viewBox="0 0 10 10"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
            >
              <path d="M3 2l3 3-3 3" />
            </svg>
            <span style={{ fontSize: 12, color: '#6b7280' }}>Advanced JSON</span>
          </div>
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
    const postureDiscovered = agentPosture?.discovered_unregistered || []
    const workspaceHints = Array.from(
      new Set(
        [runtimePaths.AIRG_WORKSPACE, ...agentProfiles.map((p) => p.workspace || '')]
          .map((v) => String(v || '').trim())
          .filter(Boolean)
      )
    )

    const updateProfile = (profileId, patch) => {
      setAgentProfiles((prev) =>
        prev.map((item) => {
          if (item.profile_id !== profileId) return item
          const candidate = { ...item, ...patch }
          const nextType = String(candidate?.agent_type || '').trim().toLowerCase()
          const nextScope = normalizeScopeForAgentType(nextType, candidate?.agent_scope)
          return { ...candidate, agent_scope: nextScope }
        })
      )
    }

    const profileComparable = (profile) => ({
      name: String(profile?.name || '').trim(),
      agent_type: String(profile?.agent_type || '').trim(),
      agent_scope: String(profile?.agent_scope || '').trim(),
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
      const next = emptyProfile()
      setAgentProfiles((prev) => [...prev, next])
      setSelectedSettingsProfileId(next.profile_id)
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
        const generated = await generateAgentConfig(profile.profile_id, true)
        setGeneratedCliByProfile((prev) => ({
          ...prev,
          [profileId]: {
            add: String(generated?.generated?.command_text || '').trim(),
            remove: String(generated?.generated?.remove_command || '').trim(),
          },
        }))
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
              const generated = await generateAgentConfig(profile.profile_id, true)
              setGeneratedCliByProfile((prev) => ({
                ...prev,
                [profileId]: {
                  add: String(generated?.generated?.command_text || '').trim(),
                  remove: String(generated?.generated?.remove_command || '').trim(),
                },
              }))
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
        setGeneratedCliByProfile((prev) => ({
          ...prev,
          [String(profile?.profile_id || '').trim()]: {
            add: String(payload?.generated?.command_text || '').trim(),
            remove: String(payload?.generated?.remove_command || '').trim(),
          },
        }))
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
        setGeneratedCliByProfile((prev) => ({
          ...prev,
          [String(profile?.profile_id || '').trim()]: {
            add: String(payload?.generated?.command_text || '').trim(),
            remove: String(payload?.generated?.remove_command || '').trim(),
          },
        }))
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
        setGeneratedCliByProfile((prev) => {
          const out = { ...prev }
          delete out[profile.profile_id]
          return out
        })
        setHardeningOptionsByProfile((prev) => {
          const out = { ...prev }
          delete out[profile.profile_id]
          return out
        })
        setHardeningPanelOpenByProfile((prev) => {
          const out = { ...prev }
          delete out[profile.profile_id]
          return out
        })
        setSelectedSettingsProfileId((prev) => (prev === profile.profile_id ? '' : prev))
        setMessage('Profile deleted')
      } catch (err) {
        const msg = String(err.message || err)
        if (msg.toLowerCase().includes('profile not found')) {
          setAgentProfiles((prev) => prev.filter((item) => item.profile_id !== profile.profile_id))
          setGeneratedCliByProfile((prev) => {
            const out = { ...prev }
            delete out[profile.profile_id]
            return out
          })
          setSelectedSettingsProfileId((prev) => (prev === profile.profile_id ? '' : prev))
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

    const setHardeningOption = (profileId, patch) => {
      setHardeningOptionsByProfile((prev) => ({
        ...prev,
        [profileId]: { ...(prev[profileId] || defaultHardeningOptionsForProfile(selectedProfile || {})), ...patch },
      }))
    }

    const setHardeningToolOption = (profileId, tool, enabled) => {
      setHardeningOptionsByProfile((prev) => {
        const current = prev[profileId] || defaultHardeningOptionsForProfile(selectedProfile || {})
        const currentTools = current?.native_tools || {}
        return {
          ...prev,
          [profileId]: {
            ...current,
            native_tools: {
              ...currentTools,
              [tool]: Boolean(enabled),
            },
          },
        }
      })
    }

    const applyHardeningForProfile = async (row, { autoAddMcp = false } = {}) => {
      const profileId = String(row?.profile_id || '').trim()
      if (!profileId) return
      setProfileActionLoading(profileId, true)
      setSettingsError('')
      const rawOptions = hardeningOptionsByProfile[profileId] || defaultHardeningOptionsForProfile(row || {})
      const toolToggles = rawOptions?.native_tools || {}
      const selectedTools = ['Bash', 'Glob', 'Grep', 'Read', 'Write', 'Edit', 'MultiEdit'].filter((tool) => Boolean(toolToggles?.[tool]))
      const optionsPayload = {
        ...rawOptions,
        scope: normalizeScopeForAgentType(row?.agent_type, rawOptions?.scope || row?.agent_scope),
        native_tools: selectedTools,
      }
      try {
        const payload = await applyAgentConfigHardening(profileId, { autoAddMcp, options: optionsPayload })
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
              const retry = await applyAgentConfigHardening(profileId, { autoAddMcp: true, options: optionsPayload })
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

    const postureForProfile = (profile) => {
      if (!profile) return null
      const profileId = String(profile?.profile_id || '')
      const profileAgentId = String(profile?.agent_id || '').trim()
      return (
        postureRows.find((row) => String(row?.profile_id || '') === profileId) ||
        postureRows.find((row) => String(row?.agent_id || '').trim() === profileAgentId) ||
        null
      )
    }

    const selectedProfile = agentProfiles.find((profile) => String(profile?.profile_id || '') === selectedSettingsProfileId) || agentProfiles[0] || null
    const selectedPosture = postureForProfile(selectedProfile)
    const selectedStatus = String(selectedPosture?.status || 'red').toLowerCase()
    const selectedStatusNormalized = ['green', 'yellow', 'red'].includes(selectedStatus) ? selectedStatus : 'red'
    const selectedAgentType = String(selectedProfile?.agent_type || '').toLowerCase()
    const selectedProfileId = String(selectedProfile?.profile_id || '').trim()
    const selectedScopeOptions = scopeOptionsForAgentType(selectedAgentType)
    const selectedScopeValue = normalizeScopeForAgentType(selectedAgentType, selectedProfile?.agent_scope || defaultScopeForAgentType(selectedAgentType))
    const selectedHardeningOptions = hardeningOptionsByProfile[selectedProfileId] || (selectedProfile ? defaultHardeningOptionsForProfile(selectedProfile) : null)
    const selectedHardeningOpen = Boolean(hardeningPanelOpenByProfile[selectedProfileId])
    const selectedSignalScopes = selectedPosture?.signal_scopes || {}
    const selectedSignals = selectedPosture?.signals || {}
    const selectedRecommendations = Array.isArray(selectedPosture?.recommended_actions) ? selectedPosture.recommended_actions : []

    const statusPillStyle = {
      red: { bg: '#fee2e2', fg: '#dc2626', label: 'Red' },
      yellow: { bg: '#fef3c7', fg: '#b45309', label: 'Yellow' },
      green: { bg: '#dcfce7', fg: '#15803d', label: 'Green' },
    }

    const postureCardTheme = {
      red: { border: '#fecaca', bg: '#fff5f5', iconBg: '#fee2e2', iconFg: '#dc2626', icon: '✕', label: 'Unprotected' },
      yellow: { border: '#fde68a', bg: '#fffdf0', iconBg: '#fef3c7', iconFg: '#b45309', icon: '◐', label: 'MCP-only enforcement' },
      green: { border: '#bbf7d0', bg: '#f0fdf4', iconBg: '#dcfce7', iconFg: '#15803d', icon: '✓', label: 'Fully hardened' },
    }

    const selectedTheme = postureCardTheme[selectedStatusNormalized]
    const selectedPill = statusPillStyle[selectedStatusNormalized]
    const isMcpOnlyCeiling = selectedAgentType !== 'claude_code'

    const ceilingNote = (() => {
      if (selectedAgentType === 'claude_code') return 'Can reach Green — hooks and permissions available for Claude Code.'
      if (selectedAgentType === 'cursor') return 'Maximum posture for this agent type is Yellow (MCP-layer controls only).'
      if (selectedAgentType === 'claude_desktop') return 'Review posture signals for this profile; MCP + hook/sandbox coverage depends on settings files.'
      return 'Posture coverage depends on this client’s support for hooks, permissions, and sandbox controls.'
    })()

    const mcpDetectedScopes = Array.isArray(selectedPosture?.mcp_detected_scopes)
      ? selectedPosture.mcp_detected_scopes.map((scope) => String(scope || '').trim()).filter(Boolean)
      : []
    const mcpScopeLabels = {
      project: 'project',
      local: 'local',
      user: 'user',
      managed: 'managed',
    }
    const mcpScopeSummary = mcpDetectedScopes.length
      ? `Configured in ${mcpDetectedScopes.map((scope) => mcpScopeLabels[scope] || scope).join(', ')} scope${mcpDetectedScopes.length === 1 ? '' : 's'}`
      : 'Configured'
    const expectedMcpScope = String(selectedPosture?.mcp_expected_scope || selectedScopeValue || '').trim()
    const mcpScopeMismatch = Boolean(selectedSignals?.airg_mcp_present) && Boolean(expectedMcpScope) && !mcpDetectedScopes.includes(expectedMcpScope)

    const signalRows = [
      { key: 'airg_mcp_present', label: 'AIRG MCP configured', failText: 'Not found in project/local/user/managed MCP config scopes' },
      { key: 'hook_active', label: 'airg-hook PreToolUse registered', failText: 'No hook entry in settings.local.json' },
      { key: 'native_tools_restricted', label: 'Native tools restricted', failText: 'Bash, Write, Edit, MultiEdit not denied' },
      { key: 'sandbox_enabled', label: 'Sandbox enabled', failText: 'sandbox: false in settings' },
      { key: 'sandbox_escape_closed', label: 'Sandbox escape closed', failText: 'Depends on sandbox being enabled' },
    ].map((row) => {
      const notSupported = isMcpOnlyCeiling && row.key !== 'airg_mcp_present'
      const rawValue = selectedSignals?.[row.key]
      const state = notSupported ? 'na' : (rawValue ? 'pass' : 'fail')
      const scopeList = Array.isArray(selectedSignalScopes?.[row.key]) ? selectedSignalScopes[row.key] : []
      const scopeDetail = scopeList.length
        ? `Configured in ${scopeList.map((scope) => mcpScopeLabels[scope] || scope).join(', ')} scope${scopeList.length === 1 ? '' : 's'}`
        : 'Configured'
      const detail = state === 'pass'
        ? (
          row.key === 'airg_mcp_present'
            ? mcpScopeSummary
            : row.key === 'native_tools_restricted'
              ? (
                Array.isArray(selectedPosture?.native_tools_denied) && selectedPosture.native_tools_denied.length
                  ? `Denied: ${selectedPosture.native_tools_denied.join(', ')} · ${scopeDetail}`
                  : scopeDetail
              )
              : scopeDetail
        )
        : state === 'na'
          ? 'Not supported by this client'
          : row.failText
      return { ...row, state, detail }
    })

    const canApplyHardening = Boolean(selectedProfile)
      && selectedAgentType === 'claude_code'

    const selectedDirty = selectedProfile ? isProfileDirty(selectedProfile) : false
    const selectedNeedsReconfigure = selectedProfile ? Boolean(settingsNeedsReconfigure[selectedProfile.profile_id]) : false

    const typeLabelFor = (profile) => {
      const id = String(profile?.agent_type || '').trim()
      const match = (agentTypes || []).find((option) => String(option?.id || '') === id)
      return match?.label || id || 'Unknown'
    }

    return (
      <div className="space-y-3">
        {settingsError && (
          <div className="bg-white border border-red-200 rounded-[10px] px-3 py-2 text-sm text-red-700">
            {settingsError}
          </div>
        )}

        <div style={{ display: 'grid', gridTemplateColumns: '260px minmax(0, 1fr)', gap: 12 }}>
          <div className="bg-white border border-slate-200 rounded-[10px] overflow-hidden shadow-sm">
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '10px 12px',
                borderBottom: '1px solid #e5e7eb',
                background: '#fafafa',
              }}
            >
              <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.08em', color: '#94a3b8' }}>
                AGENTS
              </div>
              <button
                onClick={addProfileRow}
                className="px-3 py-1.5 border border-slate-300 rounded-[10px] bg-white hover:bg-slate-50 text-sm font-semibold"
              >
                + Add
              </button>
            </div>

            <div style={{ maxHeight: 'calc(100vh - 220px)', overflowY: 'auto' }}>
              {!agentProfiles.length && (
                <div style={{ padding: '14px 12px', fontSize: 12, color: '#9ca3af' }}>
                  No configured agents.
                </div>
              )}
              {agentProfiles.map((profile) => {
                const posture = postureForProfile(profile)
                const status = ['green', 'yellow', 'red'].includes(String(posture?.status || '').toLowerCase())
                  ? String(posture?.status || '').toLowerCase()
                  : 'red'
                const pill = statusPillStyle[status]
                const isActive = String(profile?.profile_id || '') === String(selectedProfile?.profile_id || '')
                return (
                  <button
                    key={profile.profile_id}
                    type="button"
                    onClick={() => setSelectedSettingsProfileId(profile.profile_id)}
                    style={{
                      width: '100%',
                      textAlign: 'left',
                      border: 'none',
                      borderLeft: isActive ? '2px solid #4f46e5' : '2px solid transparent',
                      background: isActive ? '#f5f4ff' : 'white',
                      padding: '10px 12px',
                      display: 'flex',
                      alignItems: 'center',
                      gap: 10,
                      borderBottom: '1px solid #f1f5f9',
                      cursor: 'pointer',
                    }}
                  >
                    <span
                      style={{
                        width: 8,
                        height: 8,
                        borderRadius: '50%',
                        background: status === 'green' ? '#22c55e' : status === 'yellow' ? '#f59e0b' : '#ef4444',
                        flexShrink: 0,
                      }}
                    />
                    <div style={{ minWidth: 0, flex: 1 }}>
                      <div style={{ fontSize: 12, fontWeight: 600, color: '#1f2937' }}>
                        {profile.name || profile.agent_id || 'Unnamed Agent'}
                      </div>
                      <div style={{ fontSize: 10, color: '#94a3b8', marginTop: 1 }}>
                        {typeLabelFor(profile)}
                      </div>
                    </div>
                    <span
                      style={{
                        background: pill.bg,
                        color: pill.fg,
                        fontSize: 10,
                        fontWeight: 700,
                        borderRadius: 6,
                        padding: '1px 6px',
                        flexShrink: 0,
                      }}
                    >
                      {pill.label}
                    </span>
                  </button>
                )
              })}
            </div>

            <div style={{ padding: '8px 12px', borderTop: '1px solid #e5e7eb', fontSize: 10, color: '#64748b' }}>
              Profile storage: <span className="font-mono">{settingsConfigsDir || '-'}</span>
            </div>
          </div>

          <div style={{ minWidth: 0 }}>
            {!selectedProfile ? (
              <div className="bg-white border border-slate-200 rounded-[10px] p-4 text-sm text-slate-500 shadow-sm">
                Select an agent from the left panel to view configuration and posture.
              </div>
            ) : (
              <div className="space-y-3">
                <div className="bg-white border border-slate-200 rounded-[10px] p-3 shadow-sm">
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 0 }}>
                      <div
                        style={{
                          width: 32,
                          height: 32,
                          borderRadius: 8,
                          background: '#f3f4f6',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          color: '#6b7280',
                          fontSize: 12,
                          fontWeight: 700,
                          flexShrink: 0,
                        }}
                      >
                        ••
                      </div>
                      <div style={{ minWidth: 0 }}>
                        <div style={{ fontSize: 18, fontWeight: 700, color: '#111827', lineHeight: 1.2 }}>
                          {selectedProfile.name || selectedProfile.agent_id || selectedProfile.profile_id}
                        </div>
                        <div style={{ fontSize: 12, color: '#9ca3af', marginTop: 2 }}>
                          {typeLabelFor(selectedProfile)} · {selectedProfile.workspace || '-'}
                        </div>
                      </div>
                    </div>
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                      <button
                        onClick={() => fetchAgentPosture()}
                        className="px-3 py-1.5 rounded-[10px] border border-slate-300 text-xs bg-white hover:bg-slate-50"
                        disabled={agentPostureLoading}
                      >
                        {agentPostureLoading ? 'Refreshing…' : 'Refresh'}
                      </button>
                      <button
                        onClick={() => saveRow(selectedProfile)}
                        className="px-3 py-1.5 rounded-[10px] border border-slate-300 text-sm bg-white hover:bg-slate-50 font-semibold"
                        disabled={settingsLoading}
                      >
                        {settingsLoading ? 'Working…' : 'Regenerate'}
                      </button>
                    </div>
                  </div>
                </div>

                <div className="bg-white border border-slate-200 rounded-[10px] overflow-hidden shadow-sm">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', padding: '10px 14px', borderBottom: '1px solid #e5e7eb' }}>
                    <div style={{ fontSize: 12, fontWeight: 700, color: '#334155' }}>Configuration</div>
                    <div style={{ fontSize: 10, color: '#94a3b8' }}>
                      {selectedProfile.last_generated_at ? `Generated ${relativeTime(selectedProfile.last_generated_at)}` : 'Not generated yet'}
                    </div>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '170px minmax(0,1fr) 36px', gap: 8, padding: '10px 14px', borderBottom: '1px solid #f1f5f9', alignItems: 'center' }}>
                    <div style={{ fontSize: 12, color: '#94a3b8' }}>Agent type</div>
                    <select
                      value={selectedProfile.agent_type || 'claude_code'}
                      onChange={(e) => updateProfile(selectedProfile.profile_id, { agent_type: e.target.value })}
                      style={{ maxWidth: 240, fontSize: 12 }}
                    >
                      {agentTypes.map((opt) => <option key={opt.id} value={opt.id}>{opt.label}</option>)}
                    </select>
                    <div />
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '170px minmax(0,1fr) 36px', gap: 8, padding: '10px 14px', borderBottom: '1px solid #f1f5f9', alignItems: 'center' }}>
                    <div style={{ fontSize: 12, color: '#94a3b8' }}>Agent scope</div>
                    <select
                      value={selectedScopeValue}
                      onChange={(e) => updateProfile(selectedProfile.profile_id, { agent_scope: e.target.value })}
                      style={{ maxWidth: 240, fontSize: 12 }}
                    >
                      {selectedScopeOptions.map((opt) => (
                        <option key={opt.id} value={opt.id}>{opt.label}</option>
                      ))}
                    </select>
                    <button
                      title="Scope info"
                      style={{ width: 36, height: 36, borderRadius: 8, border: '1px solid #cbd5e1', background: 'white', cursor: 'pointer', fontSize: 12 }}
                      onClick={() => setSettingsInfoModal({
                        open: true,
                        title: 'Agent Scope',
                        content: [
                          'Scope controls where MCP and hardening settings are written.',
                          '',
                          'Claude Code:',
                          '- Project: .mcp.json and/or .claude/settings.json in workspace',
                          '- Local (default): ~/.claude.json project entry + .claude/settings.local.json',
                          '- User: ~/.claude.json mcpServers + ~/.claude/settings.json',
                          '',
                          'Codex:',
                          '- Global (default): ~/.codex/config.toml',
                          '- Project: .codex/config.toml in project',
                          '',
                          'Official docs:',
                          '- Claude settings/hooks/sandbox: https://docs.anthropic.com/en/docs/claude-code',
                          '- Codex MCP: https://platform.openai.com/docs/codex',
                        ].join('\n'),
                      })}
                    >
                      i
                    </button>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '170px minmax(0,1fr) 36px', gap: 8, padding: '10px 14px', borderBottom: '1px solid #f1f5f9', alignItems: 'center' }}>
                    <div style={{ fontSize: 12, color: '#94a3b8' }}>Agent ID</div>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: '#111827', wordBreak: 'break-all' }}>
                      {selectedProfile.agent_id || '-'}
                    </div>
                    <button
                      title="Edit agent ID"
                      style={{ width: 36, height: 36, borderRadius: 8, border: '1px solid #cbd5e1', background: 'white', cursor: 'pointer' }}
                      onClick={() => {
                        const next = window.prompt('Agent ID', String(selectedProfile.agent_id || ''))
                        if (next === null) return
                        updateProfile(selectedProfile.profile_id, { agent_id: next })
                      }}
                    >
                      ✎
                    </button>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '170px minmax(0,1fr) 36px', gap: 8, padding: '10px 14px', alignItems: 'center' }}>
                    <div style={{ fontSize: 12, color: '#94a3b8' }}>Workspace</div>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: '#111827', wordBreak: 'break-all' }}>
                      {selectedProfile.workspace || '-'}
                    </div>
                    <button
                      title="Edit workspace"
                      style={{ width: 36, height: 36, borderRadius: 8, border: '1px solid #cbd5e1', background: 'white', cursor: 'pointer' }}
                      onClick={() => {
                        const next = window.prompt('Workspace', String(selectedProfile.workspace || runtimePaths.AIRG_WORKSPACE || ''))
                        if (next === null) return
                        updateProfile(selectedProfile.profile_id, { workspace: next })
                      }}
                    >
                      ✎
                    </button>
                  </div>

                  <div style={{ padding: '12px 14px', borderTop: '1px solid #e5e7eb', display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                    <button
                      onClick={() => copyJson(selectedProfile)}
                      className="px-3 py-2 border border-slate-300 rounded-[10px] bg-white hover:bg-slate-50 text-sm font-semibold"
                      disabled={settingsLoading}
                    >
                      Copy MCP JSON
                    </button>
                    <button
                      onClick={() => copyCli(selectedProfile)}
                      className="px-3 py-2 border border-slate-300 rounded-[10px] bg-white hover:bg-slate-50 text-sm font-semibold"
                      disabled={settingsLoading}
                    >
                      Copy CLI command
                    </button>
                    <button
                      onClick={() => openConfig(selectedProfile)}
                      className="px-3 py-2 border border-slate-300 rounded-[10px] bg-white hover:bg-slate-50 text-sm"
                      disabled={!selectedProfile.last_saved_path || settingsLoading}
                    >
                      Open config
                    </button>
                    <button
                      onClick={() => deleteRow(selectedProfile)}
                      className="px-3 py-2 border border-red-300 text-red-700 rounded-[10px] bg-red-50 hover:bg-red-100 text-sm"
                      disabled={settingsLoading}
                    >
                      Delete
                    </button>
                  </div>
                </div>

                <div
                  className="rounded-[10px] border shadow-sm overflow-hidden"
                  style={{ borderColor: selectedTheme.border, background: selectedTheme.bg }}
                >
                  <div
                    style={{
                      display: 'grid',
                      gridTemplateColumns: '48px minmax(0,1fr) auto',
                      gap: 12,
                      alignItems: 'center',
                      padding: '12px 14px',
                      borderBottom: `1px solid ${selectedTheme.border}`,
                    }}
                  >
                    <div
                      style={{
                        width: 36,
                        height: 36,
                        borderRadius: '50%',
                        background: selectedTheme.iconBg,
                        color: selectedTheme.iconFg,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        fontSize: 16,
                        fontWeight: 700,
                      }}
                    >
                      {selectedTheme.icon}
                    </div>
                    <div>
                      <div style={{ fontSize: 16, fontWeight: 700, color: selectedTheme.iconFg }}>
                        {selectedTheme.label}
                      </div>
                      <div style={{ fontSize: 12, color: '#64748b', marginTop: 2 }}>{ceilingNote}</div>
                    </div>
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                      {canApplyHardening && (
                        <button
                          onClick={() => {
                            const pid = String(selectedProfile?.profile_id || '').trim()
                            if (!pid) return
                            if (!hardeningPanelOpenByProfile[pid]) {
                              setHardeningPanelOpenByProfile((prev) => ({ ...prev, [pid]: true }))
                              return
                            }
                            applyHardeningForProfile(selectedPosture || selectedProfile)
                          }}
                          className="px-3 py-2 rounded-[10px] bg-white border border-slate-300 text-sm font-semibold hover:bg-slate-50 disabled:opacity-50"
                          disabled={Boolean(agentConfigActionLoading[selectedProfile.profile_id])}
                        >
                          {agentConfigActionLoading[selectedProfile.profile_id]
                            ? 'Applying…'
                            : selectedHardeningOpen
                              ? 'Apply selected hardening'
                              : 'Apply hardening'}
                        </button>
                      )}
                      {canApplyHardening && (
                        <button
                          onClick={() => {
                            const pid = String(selectedProfile?.profile_id || '').trim()
                            if (!pid) return
                            setHardeningPanelOpenByProfile((prev) => ({ ...prev, [pid]: !prev[pid] }))
                          }}
                          className="px-3 py-2 rounded-[10px] bg-white border border-slate-300 text-sm hover:bg-slate-50"
                        >
                          {selectedHardeningOpen ? 'Hide options' : 'Show options'}
                        </button>
                      )}
                      <button
                        onClick={() => undoHardeningForProfile(selectedPosture || selectedProfile)}
                        className="px-3 py-2 rounded-[10px] bg-white border border-slate-300 text-sm hover:bg-slate-50 disabled:opacity-50"
                        disabled={Boolean(agentConfigActionLoading[selectedProfile.profile_id]) || !Boolean(selectedPosture?.undo_available)}
                      >
                        Undo last apply
                      </button>
                    </div>
                  </div>

                  {selectedHardeningOpen && selectedHardeningOptions && selectedAgentType === 'claude_code' && (
                    <div style={{ background: '#ffffff', borderBottom: `1px solid ${selectedTheme.border}`, padding: '12px 14px' }}>
                      <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.08em', color: '#94a3b8', marginBottom: 10 }}>
                        HARDENING OPTIONS
                      </div>

                      <div style={{ display: 'grid', gridTemplateColumns: '220px minmax(0,1fr)', gap: 8, alignItems: 'center', marginBottom: 10 }}>
                        <div style={{ fontSize: 12, color: '#64748b' }}>Config scope</div>
                        <div style={{ maxWidth: 280 }}>
                          <SegControl
                            value={normalizeScopeForAgentType(selectedAgentType, selectedHardeningOptions.scope || selectedScopeValue)}
                            onChange={(value) => setHardeningOption(selectedProfileId, { scope: value })}
                            options={selectedScopeOptions.map((opt) => ({ label: opt.label, value: opt.id, activeClass: 'm-blue' }))}
                          />
                        </div>
                      </div>

                      <div style={{ display: 'grid', gridTemplateColumns: '220px minmax(0,1fr) auto', gap: 8, alignItems: 'center', marginBottom: 10 }}>
                        <div style={{ fontSize: 12, color: '#64748b' }}>Register airg-hook</div>
                        <div style={{ maxWidth: 120 }}>
                          <SegControl
                            value={Boolean(selectedHardeningOptions.hook_enabled)}
                            onChange={(value) => setHardeningOption(selectedProfileId, { hook_enabled: Boolean(value) })}
                            options={[
                              { label: 'Yes', value: true, activeClass: 'yn-yes' },
                              { label: 'No', value: false, activeClass: 'yn-no' },
                            ]}
                          />
                        </div>
                        <button
                          className="px-2 py-1 text-xs border border-slate-300 rounded-[8px] bg-white hover:bg-slate-50"
                          onClick={() => setSettingsInfoModal({
                            open: true,
                            title: 'PreToolUse hooks',
                            content: [
                              'airg-hook runs before native tool execution and can redirect usage through AIRG MCP tools.',
                              '',
                              'Official docs:',
                              '- https://docs.anthropic.com/en/docs/claude-code/hooks',
                            ].join('\n'),
                          })}
                        >
                          Info
                        </button>
                      </div>

                      <div style={{ display: 'grid', gridTemplateColumns: '220px minmax(0,1fr)', gap: 8, alignItems: 'center', marginBottom: 10 }}>
                        <div style={{ fontSize: 12, color: '#64748b' }}>Restrict native tools</div>
                        <div style={{ maxWidth: 120 }}>
                          <SegControl
                            value={Boolean(selectedHardeningOptions.restrict_native_tools)}
                            onChange={(value) => setHardeningOption(selectedProfileId, { restrict_native_tools: Boolean(value) })}
                            options={[
                              { label: 'Yes', value: true, activeClass: 'yn-yes' },
                              { label: 'No', value: false, activeClass: 'yn-no' },
                            ]}
                          />
                        </div>
                      </div>

                      {Boolean(selectedHardeningOptions.restrict_native_tools) && (
                        <div style={{ margin: '-2px 0 12px 220px' }}>
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                            {['Bash', 'Glob', 'Grep', 'Read', 'Write', 'Edit', 'MultiEdit'].map((tool) => (
                              <div key={tool} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                                <label className="text-xs border border-slate-300 rounded px-2 py-1 bg-slate-50 flex items-center gap-1 cursor-pointer">
                                  <input
                                    type="checkbox"
                                    checked={Boolean(selectedHardeningOptions?.native_tools?.[tool])}
                                    onChange={(e) => setHardeningToolOption(selectedProfileId, tool, e.target.checked)}
                                  />
                                  <span>{tool}</span>
                                </label>
                                {['Read', 'Grep', 'Glob'].includes(tool) && (
                                  <button
                                    title={`${tool} warning`}
                                    className="w-5 h-5 rounded-full border border-amber-300 text-amber-700 text-[10px] bg-amber-50"
                                    onClick={() => setSettingsInfoModal({
                                      open: true,
                                      title: `${tool} Restriction Warning`,
                                      content: `${tool} is useful for agent context gathering. Blocking it can slow down agent workflows, but is recommended if you need stricter path access control via AIRG.`,
                                    })}
                                  >
                                    !
                                  </button>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      <div style={{ display: 'grid', gridTemplateColumns: '220px minmax(0,1fr)', gap: 8, alignItems: 'center', marginBottom: 10 }}>
                        <div style={{ fontSize: 12, color: '#64748b' }}>Sandbox enabled</div>
                        <div style={{ maxWidth: 120 }}>
                          <SegControl
                            value={Boolean(selectedHardeningOptions.sandbox_enabled)}
                            onChange={(value) => setHardeningOption(selectedProfileId, { sandbox_enabled: Boolean(value) })}
                            options={[
                              { label: 'Yes', value: true, activeClass: 'yn-yes' },
                              { label: 'No', value: false, activeClass: 'yn-no' },
                            ]}
                          />
                        </div>
                      </div>

                      <div style={{ display: 'grid', gridTemplateColumns: '220px minmax(0,1fr)', gap: 8, alignItems: 'center' }}>
                        <div style={{ fontSize: 12, color: '#64748b' }}>Sandbox escape closed</div>
                        <div style={{ maxWidth: 120 }}>
                          <SegControl
                            value={Boolean(selectedHardeningOptions.sandbox_escape_closed)}
                            onChange={(value) => setHardeningOption(selectedProfileId, { sandbox_escape_closed: Boolean(value) })}
                            options={[
                              { label: 'Yes', value: true, activeClass: 'yn-yes' },
                              { label: 'No', value: false, activeClass: 'yn-no' },
                            ]}
                          />
                        </div>
                      </div>
                    </div>
                  )}

                  <div style={{ background: 'white' }}>
                    {signalRows.map((row) => (
                      <div
                        key={row.key}
                        style={{
                          display: 'grid',
                          gridTemplateColumns: '20px minmax(0,1fr) minmax(0,220px)',
                          gap: 10,
                          alignItems: 'start',
                          padding: '10px 14px',
                          borderBottom: '1px solid #f1f5f9',
                        }}
                      >
                        <span
                          style={{
                            width: 18,
                            height: 18,
                            borderRadius: '50%',
                            display: 'inline-flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            fontSize: 11,
                            marginTop: 2,
                            background: row.state === 'pass' ? '#dcfce7' : row.state === 'na' ? '#f3f4f6' : '#fee2e2',
                            color: row.state === 'pass' ? '#15803d' : row.state === 'na' ? '#94a3b8' : '#dc2626',
                          }}
                        >
                          {row.state === 'pass' ? '✓' : row.state === 'na' ? '—' : '✕'}
                        </span>
                        <div style={{ fontSize: 12, color: '#1f2937', lineHeight: 1.3 }}>{row.label}</div>
                        <div style={{ fontSize: 12, color: '#94a3b8', lineHeight: 1.3 }}>{row.detail}</div>
                      </div>
                    ))}
                  </div>
                </div>

                {selectedRecommendations.length > 0 && selectedStatusNormalized !== 'green' && (
                  <div className="bg-white border border-slate-200 rounded-[10px] p-3 shadow-sm">
                    <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.08em', color: '#94a3b8', marginBottom: 8 }}>
                      RECOMMENDED NEXT ACTIONS
                    </div>
                    <ul style={{ paddingLeft: 16, margin: 0 }}>
                      {selectedRecommendations.map((line, idx) => (
                        <li key={`rec-${idx}`} style={{ fontSize: 12, color: '#334155', marginBottom: 6, lineHeight: 1.4 }}>
                          {line}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {(selectedDirty || selectedNeedsReconfigure) && (
                  <div className="bg-white border border-slate-200 rounded-[10px] px-3 py-2 text-xs text-slate-600 shadow-sm">
                    {selectedDirty && <div>Unsaved profile changes detected.</div>}
                    {selectedNeedsReconfigure && (
                      <div style={{ display: 'grid', gap: 4 }}>
                        <div>MCP reconfiguration required for this agent after profile changes.</div>
                        <div className="font-mono">
                          {String(generatedCliByProfile?.[selectedProfileId]?.remove || '').trim() || `${selectedAgentType === 'codex' ? 'codex' : 'claude'} mcp remove ai-runtime-guard`}
                        </div>
                        <div>Then re-add with the latest command from <span className="font-semibold">Copy CLI command</span>.</div>
                      </div>
                    )}
                    {mcpScopeMismatch && (
                      <div style={{ marginTop: 4, color: '#b45309' }}>
                        Scope mismatch: profile expects <span className="font-semibold">{expectedMcpScope}</span> but MCP is detected in {mcpDetectedScopes.join(', ')}.
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {postureDiscovered.length > 0 && (
          <div className="bg-white border border-slate-200 rounded-[10px] p-3 shadow-sm">
            <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.08em', color: '#94a3b8', marginBottom: 8 }}>
              UNREGISTERED AGENT CONFIGS DETECTED
            </div>
            <div className="space-y-1">
              {postureDiscovered.map((item, idx) => (
                <div key={`${item.path}-${idx}`} className="text-xs border border-slate-200 rounded px-2 py-1 bg-slate-50">
                  <span className="font-medium text-slate-700">{item.agent_type || 'agent'}</span>
                  <span className="text-slate-500"> ({item.scope || 'unknown'})</span>
                  <div className="font-mono text-[11px] text-slate-600 break-all">{item.path}</div>
                </div>
              ))}
            </div>
          </div>
        )}
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

  function SettingsInfoModal() {
    if (!settingsInfoModal.open) return null
    return (
      <div
        className="fixed inset-0 z-30 bg-slate-900/40 flex items-center justify-center p-4"
        onClick={() => setSettingsInfoModal({ open: false, title: '', content: '' })}
      >
        <div className="bg-white rounded-[10px] border border-slate-200 shadow-lg w-full max-w-2xl" onClick={(e) => e.stopPropagation()}>
          <div className="px-4 py-3 border-b border-slate-200 flex items-center justify-between">
            <div className="font-semibold text-slate-800">{settingsInfoModal.title || 'Info'}</div>
            <button className="text-slate-500 hover:text-slate-700" onClick={() => setSettingsInfoModal({ open: false, title: '', content: '' })}>✕</button>
          </div>
          <div className="p-4">
            <pre className="text-xs whitespace-pre-wrap break-words font-sans text-slate-700">
              {settingsInfoModal.content || ''}
            </pre>
          </div>
        </div>
      </div>
    )
  }

  function OverrideDiffModal() {
    if (!overrideDiffModal.open) return null
    return (
      <div
        className="fixed inset-0 z-30 flex items-center justify-center p-4"
        style={{ background: 'rgba(0,0,0,0.35)' }}
        onClick={() => setOverrideDiffModal({ open: false, agentId: '', lines: [] })}
      >
        <div
          className="bg-white border border-slate-200 rounded-[10px] p-4 w-full"
          style={{ minWidth: 380, maxWidth: 500, boxShadow: '0 20px 60px rgba(0,0,0,0.2)' }}
          onClick={(e) => e.stopPropagation()}
        >
          <div style={{ fontSize: 13, fontWeight: 600, color: '#111827', marginBottom: 4 }}>
            Policy diff — {overrideDiffModal.agentId}
          </div>
          <div style={{ fontSize: 11, color: '#9ca3af', marginBottom: 14 }}>
            Changes from baseline for this agent
          </div>

          {overrideDiffModal.lines.length === 0 ? (
            <div style={{ fontSize: 12, color: '#9ca3af', fontStyle: 'italic' }}>
              No differences from baseline.
            </div>
          ) : overrideDiffModal.lines.map((line, i) => (
            <div
              key={`diff-${i}-${line.text}`}
              style={{
                display: 'flex',
                alignItems: 'baseline',
                gap: 8,
                padding: '3px 8px',
                borderRadius: 4,
                marginBottom: 3,
                fontSize: 12,
                fontFamily: 'monospace',
                background: line.type === 'added' ? '#f0fdf4' : '#fff5f5',
                color: line.type === 'added' ? '#15803d' : '#dc2626',
              }}
            >
              <span style={{ fontWeight: 700, flexShrink: 0 }}>{line.type === 'added' ? '+' : '−'}</span>
              <span>{line.text}</span>
            </div>
          ))}

          <div style={{ marginTop: 16, display: 'flex', justifyContent: 'flex-end' }}>
            <button
              onClick={() => setOverrideDiffModal({ open: false, agentId: '', lines: [] })}
              style={{
                background: '#4f46e5',
                color: 'white',
                border: 'none',
                borderRadius: 5,
                padding: '6px 16px',
                fontSize: 11,
                fontWeight: 500,
                cursor: 'pointer',
              }}
            >
              Close
            </button>
          </div>
        </div>
      </div>
    )
  }

  function OverrideBaselineModal() {
    if (!overrideBaselineModal.open) return null
    const baselineData = isPlainObject(overrideBaselineModal.baselineData) ? overrideBaselineModal.baselineData : {}
    const fieldLabels = {
      commands: 'Commands',
      paths: 'Paths',
      extensions: 'Extensions',
      paths_whitelist: 'Paths whitelist',
      blocked_domains: 'Blocked domains',
      allowed_domains: 'Allowed domains',
      exempt_commands: 'Exempt commands',
    }
    const arrayEntries = Object.entries(baselineData).filter(([, values]) => Array.isArray(values) && values.length > 0)
    const scalarEntries = Object.entries(baselineData).filter(([, values]) => !Array.isArray(values) && (typeof values === 'string' || typeof values === 'number' || typeof values === 'boolean'))

    return (
      <div
        className="fixed inset-0 z-30 flex items-center justify-center p-4"
        style={{ background: 'rgba(0,0,0,0.35)' }}
        onClick={() => setOverrideBaselineModal({ open: false, sectionLabel: '', baselineData: {} })}
      >
        <div
          className="bg-white border border-slate-200 rounded-[10px] p-4 w-full"
          style={{ minWidth: 340, maxWidth: 460, boxShadow: '0 20px 60px rgba(0,0,0,0.2)' }}
          onClick={(e) => e.stopPropagation()}
        >
          <div style={{ fontSize: 13, fontWeight: 600, color: '#111827', marginBottom: 4 }}>
            {overrideBaselineModal.sectionLabel} — baseline
          </div>
          <div style={{ fontSize: 11, color: '#9ca3af', marginBottom: 14 }}>
            Current global policy values for this section
          </div>

          {arrayEntries.map(([field, values]) => (
            <div key={`baseline-array-${field}`} style={{ marginBottom: 12 }}>
              <div
                style={{
                  fontSize: 10,
                  fontWeight: 600,
                  textTransform: 'uppercase',
                  letterSpacing: '0.06em',
                  color: '#9ca3af',
                  marginBottom: 6,
                }}
              >
                {fieldLabels[field] || field}
              </div>
              <div style={{ fontFamily: 'monospace', fontSize: 12, color: '#374151', lineHeight: 1.8 }}>
                {values.map((value, i) => (
                  <div key={`baseline-item-${field}-${i}`} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span style={{ color: '#9ca3af' }}>·</span> {value}
                  </div>
                ))}
              </div>
            </div>
          ))}

          {scalarEntries.length > 0 && (
            <div style={{ marginBottom: 12 }}>
              <div
                style={{
                  fontSize: 10,
                  fontWeight: 600,
                  textTransform: 'uppercase',
                  letterSpacing: '0.06em',
                  color: '#9ca3af',
                  marginBottom: 6,
                }}
              >
                Settings
              </div>
              <div style={{ fontFamily: 'monospace', fontSize: 12, color: '#374151', lineHeight: 1.8 }}>
                {scalarEntries.map(([field, value]) => (
                  <div key={`baseline-scalar-${field}`} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span style={{ color: '#9ca3af' }}>·</span> {field}: {String(value)}
                  </div>
                ))}
              </div>
            </div>
          )}

          {arrayEntries.length === 0 && scalarEntries.length === 0 && (
            <div style={{ fontSize: 12, color: '#9ca3af', fontStyle: 'italic' }}>
              No baseline values configured for this section.
            </div>
          )}

          <div style={{ marginTop: 16, display: 'flex', justifyContent: 'flex-end' }}>
            <button
              onClick={() => setOverrideBaselineModal({ open: false, sectionLabel: '', baselineData: {} })}
              style={{
                background: '#4f46e5',
                color: 'white',
                border: 'none',
                borderRadius: 5,
                padding: '6px 16px',
                fontSize: 11,
                fontWeight: 500,
                cursor: 'pointer',
              }}
            >
              Close
            </button>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className='airg-app-shell relative min-h-screen bg-[var(--bg-app)] text-[var(--text-primary)] overflow-hidden'>
      <div className="relative z-10 mx-auto max-w-[1720px] border border-[var(--border-default)] overflow-hidden bg-[var(--bg-app)] shadow-sm h-screen grid grid-cols-[var(--sidebar-width)_1fr]">
        <aside className="airg-sidebar h-full min-h-0 border-r border-white/10 bg-[var(--bg-sidebar)] flex flex-col">
          <div className="h-[52px] px-4 border-b border-white/10 flex items-center sidebar-brand">
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
              Server active
            </div>
          </div>
        </aside>

        <div className="airg-content flex flex-col min-w-0 min-h-0 bg-[var(--bg-app)]">
          <div className="h-[52px] px-5 border-b border-[var(--border-default)] bg-[var(--bg-header-bar)] flex items-center justify-between gap-3 page-header sticky top-0 z-10">
            <div className="min-w-0">
              <div className="text-lg font-semibold text-[var(--text-primary)] title">{pageTitle}</div>
              <div className="text-xs text-[var(--text-secondary)] mt-0.5 flex flex-wrap items-center gap-3">
                {policyHash && <span className="font-mono hash">hash {String(policyHash).slice(0, 12)}</span>}
                {unsaved && (
                  <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 10, color: '#d97706' }}>
                    <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#f59e0b', flexShrink: 0 }} />
                    Unsaved changes
                  </span>
                )}
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
                <span className="text-[10px] text-[var(--text-secondary)] hidden xl:inline">
                  Changes take effect after Apply + server restart
                </span>
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
      {SettingsInfoModal()}
      {OverrideDiffModal()}
      {OverrideBaselineModal()}
    </div>
  )
}
