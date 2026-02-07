
import React, { useState, useEffect } from 'react';
import { createPortal } from 'react-dom';
import { 
  Activity, Database, Users, Shield, Globe, Cpu, RefreshCw, UserPlus, ShieldAlert, Key, Globe2, Monitor, Wifi, Palette, Bot, HardDrive, Server, Clock, Layers, FileText, X, Lock, Settings
} from 'lucide-react';
import { useOSStore, type ThemeMode } from '../../store';
import LoginSettingsModal from '../LoginSettingsModal';
import { getGeminiKeySet, saveGeminiKey } from '../../lib/ai';
import { BACKGROUND_PRESETS } from '../../lib/customization';
import { t, type Lang } from '../../lib/i18n';
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip } from 'recharts';

type TabID = 'general' | 'health' | 'users' | 'security' | 'display' | 'network' | 'update' | 'ai-assistant' | 'sftp' | 'system-log' | 'ports';

function FirewallModal({
  enabled,
  rules,
  onClose,
  onSave,
}: {
  enabled: boolean;
  rules: { type: string; value: string }[];
  onClose: () => void;
  onSave: (enabled: boolean, rules: { type: string; value: string }[]) => Promise<void>;
}) {
  const [enabledVal, setEnabledVal] = useState(enabled);
  const [rulesVal, setRulesVal] = useState<{ type: string; value: string }[]>(rules);
  const [newValue, setNewValue] = useState('');
  const [newType, setNewType] = useState<'allow' | 'block'>('block');
  const [saving, setSaving] = useState(false);
  useEffect(() => {
    setEnabledVal(Boolean(enabled));
    setRulesVal(Array.isArray(rules) ? rules : []);
  }, [enabled, rules]);
  const addRule = () => {
    const v = newValue.trim();
    if (!v) return;
    setRulesVal((prev) => [...prev, { type: newType, value: v }]);
    setNewValue('');
  };
  const removeRule = (i: number) => setRulesVal((prev) => prev.filter((_, idx) => idx !== i));
  const handleSave = async () => {
    setSaving(true);
    await onSave(enabledVal, rulesVal);
    setSaving(false);
  };
  const modal = (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50"
      style={{ top: 0, left: 0, right: 0, bottom: 0, minWidth: '100vw', minHeight: '100dvh' }}
      onClick={onClose}
      role="presentation"
    >
      <div className="bg-white rounded-2xl shadow-xl max-w-lg w-full max-h-[90vh] overflow-hidden flex flex-col" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between p-6 border-b border-slate-200">
          <h2 className="text-lg font-bold text-slate-800">Firewall Rules</h2>
          <button type="button" onClick={onClose} className="p-1 rounded hover:bg-slate-100"><X size={20} /></button>
        </div>
        <div className="p-6 overflow-y-auto space-y-4">
          <label className="flex items-center gap-2 cursor-pointer">
            <input type="checkbox" checked={enabledVal} onChange={(e) => setEnabledVal(e.target.checked)} className="rounded" />
            <span className="text-sm font-medium text-slate-700">Firewall enabled</span>
          </label>
          <p className="text-xs text-slate-500">Add IP or CIDR (e.g. 192.168.1.0/24). Block rules deny access; if any allow rules exist, only those IPs are allowed.</p>
          <div className="flex gap-2">
            <input
              value={newValue}
              onChange={(e) => setNewValue(e.target.value)}
              placeholder="IP or CIDR"
              className="flex-1 px-3 py-2 border border-slate-200 rounded-lg text-sm"
            />
            <select value={newType} onChange={(e) => setNewType(e.target.value as 'allow' | 'block')} className="px-3 py-2 border border-slate-200 rounded-lg text-sm">
              <option value="allow">Allow</option>
              <option value="block">Block</option>
            </select>
            <button type="button" onClick={addRule} className="px-4 py-2 bg-slate-100 rounded-lg text-sm font-medium hover:bg-slate-200">Add</button>
          </div>
          <ul className="space-y-2">
            {(Array.isArray(rulesVal) ? rulesVal : []).map((r, i) => (
              <li key={i} className="flex items-center justify-between py-2 px-3 bg-slate-50 rounded-lg text-sm">
                <span className="font-mono">{r.value}</span>
                <span className={`text-xs font-medium ${r.type === 'allow' ? 'text-green-600' : 'text-red-600'}`}>{r.type}</span>
                <button type="button" onClick={() => removeRule(i)} className="text-red-600 hover:underline text-xs">Remove</button>
              </li>
            ))}
          </ul>
        </div>
        <div className="p-6 border-t border-slate-200 flex justify-end gap-2">
          <button type="button" onClick={onClose} className="px-4 py-2 rounded-lg border border-slate-200 text-sm font-medium">Cancel</button>
          <button type="button" onClick={handleSave} disabled={saving} className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 disabled:opacity-50">Save</button>
        </div>
      </div>
    </div>
  );
  return createPortal(modal, document.body);
}

function TwoFaModal({
  enabled,
  verified,
  qrDataUrl,
  secret,
  onClose,
  onEnable,
  onDisable,
}: {
  enabled: boolean;
  verified: boolean;
  qrDataUrl: string | null;
  secret: string;
  onClose: () => void;
  onEnable: () => Promise<void>;
  onDisable: () => Promise<void>;
}) {
  const modal = (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50"
      style={{ top: 0, left: 0, right: 0, bottom: 0, minWidth: '100vw', minHeight: '100dvh' }}
      onClick={onClose}
      role="presentation"
    >
      <div className="bg-white rounded-2xl shadow-xl max-w-md w-full overflow-hidden" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between p-6 border-b border-slate-200">
          <h2 className="text-lg font-bold text-slate-800">2-Step Verification</h2>
          <button type="button" onClick={onClose} className="p-1 rounded hover:bg-slate-100"><X size={20} /></button>
        </div>
        <div className="p-6 space-y-4">
          {enabled ? (
            <>
              {qrDataUrl && (
                <div className="flex flex-col items-center gap-2">
                  <p className="text-sm text-slate-600">Scan with your authenticator app (Google Authenticator, etc.)</p>
                  <img src={qrDataUrl} alt="QR Code" className="w-48 h-48" />
                  {secret && <p className="text-xs font-mono text-slate-500 break-all">Or enter manually: {secret}</p>}
                </div>
              )}
              {verified && <p className="text-sm text-green-600 font-medium">You are verified for this session.</p>}
              <button type="button" onClick={onDisable} className="w-full py-2 rounded-lg border border-red-200 text-red-600 text-sm font-medium hover:bg-red-50">Disable 2-Step Verification</button>
            </>
          ) : (
            <button type="button" onClick={onEnable} className="w-full py-3 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700">Enable 2-Step Verification</button>
          )}
        </div>
      </div>
    </div>
  );
  return createPortal(modal, document.body);
}

const ControlPanel: React.FC = () => {
  const { addNotification, theme, background, backgroundCustomUrl, setTheme, setBackground, setBackgroundCustomUrl, setTimezone, setLanguage } = useOSStore();
  const language = useOSStore((s) => s.language) as Lang;
  const [activeTab, setActiveTab] = useState<TabID>('health');
  const [aiApiKeyInput, setAiApiKeyInput] = useState('');
  const [geminiKeySet, setGeminiKeySet] = useState<boolean | null>(null);
  const [cpuUsage, setCpuUsage] = useState<number | null>(null);
  const [ramUsageGb, setRamUsageGb] = useState<number | null>(null);
  const [ramTotalGb, setRamTotalGb] = useState<number | null>(null);
  const [storageUsedTb, setStorageUsedTb] = useState<number | null>(null);
  const [storageTotalTb, setStorageTotalTb] = useState<number | null>(null);
  const [diskSpaces, setDiskSpaces] = useState<
    { mount: string; used: number; avail: number; total: number | null; usedPercent: number | null; units?: string | null }[]
  >([]);
  const [diskIO, setDiskIO] = useState<
    { device: string; read: number; write: number; units?: string | null }[]
  >([]);
  const [systemUptimeSeconds, setSystemUptimeSeconds] = useState<number | null>(null);
  const [loadAverage, setLoadAverage] = useState<[number, number, number] | null>(null);
  const [raidArrays, setRaidArrays] = useState<{ name: string; level: string; summary: string; detail?: string }[]>([]);
  const [truenasPools, setTruenasPools] = useState<{
    name: string;
    status: string | null;
    healthy: boolean;
    topology?: { type: string; disks: string[] }[];
  }[]>([]);
  const [truenasDisks, setTruenasDisks] = useState<{
    name: string;
    devname?: string;
    size: number | null;
    model: string | null;
    serial: string | null;
    pool: string | null;
    type: string | null;
  }[]>([]);
  const [cpuModel, setCpuModel] = useState<string | null>(null);
  const [cpuCores, setCpuCores] = useState<number | null>(null);
  const [listeningPorts, setListeningPorts] = useState<{ port: number; name: string }[]>([]);
  const [dockerPorts, setDockerPorts] = useState<{ source: string; service: string; port: number; containerPort?: number | null }[]>([]);
  const [truenasPorts, setTruenasPorts] = useState<{ source: string; service: string; port: number }[]>([]);
  const [listeningPortsLoading, setListeningPortsLoading] = useState(false);
  const [systemSource, setSystemSource] = useState<string | null>(null);
  const [sftpConfig, setSftpConfig] = useState<{
    port: number;
    users: { name: string; password?: string; mount: string; enabled?: boolean }[];
    pending: { name: string; password?: string; mount: string; enabled?: boolean }[];
    delete_pending: string[];
  } | null>(null);
  const [sftpAddName, setSftpAddName] = useState('');
  const [sftpAddPassword, setSftpAddPassword] = useState('');
  const [sftpAddMount, setSftpAddMount] = useState('');
  const [networkData, setNetworkData] = useState<{
    hostname: string;
    interfaces: { name: string; address: string; family: string; mac?: string | null }[];
    dns: string[];
    source?: string;
    networkStats?: { byInterface: Record<string, number>; source: string };
  } | null>(null);
  const [networkLoading, setNetworkLoading] = useState(false);
  const [systemLogs, setSystemLogs] = useState<{ time: string; level: string; text: string }[]>([]);
  const [systemLogLoading, setSystemLogLoading] = useState(false);
  const [firewallEnabled, setFirewallEnabled] = useState(false);
  const [firewallRules, setFirewallRules] = useState<{ type: string; value: string }[]>([]);
  const [firewallLoading, setFirewallLoading] = useState(false);
  const [firewallModalOpen, setFirewallModalOpen] = useState(false);
  const [twoFaEnabled, setTwoFaEnabled] = useState(false);
  const [twoFaVerified, setTwoFaVerified] = useState(false);
  const [twoFaModalOpen, setTwoFaModalOpen] = useState(false);
  const [show2FAGate, setShow2FAGate] = useState(false);
  const [twoFaCode, setTwoFaCode] = useState('');
  const [twoFaVerifyError, setTwoFaVerifyError] = useState('');
  const [twoFaSetupQr, setTwoFaSetupQr] = useState<string | null>(null);
  const [twoFaSetupSecret, setTwoFaSetupSecret] = useState('');
  const [showLoginSettingsModal, setShowLoginSettingsModal] = useState(false);
  const [generalLoading, setGeneralLoading] = useState(false);
  const [generalSaving, setGeneralSaving] = useState(false);
  const [generalLanguage, setGeneralLanguage] = useState('en');
  const [generalTimezone, setGeneralTimezone] = useState('UTC');
  const [generalTruenasUrl, setGeneralTruenasUrl] = useState('');
  const [generalTruenasApiKey, setGeneralTruenasApiKey] = useState('');
  const [generalTruenasApiKeySet, setGeneralTruenasApiKeySet] = useState(false);
  const [generalMountPath, setGeneralMountPath] = useState('');
  const [generalAiKey, setGeneralAiKey] = useState('');
  useEffect(() => {
    const fetchSystem = async () => {
      try {
        const res = await fetch('/api/system');
        if (!res.ok) return;
        const data = await res.json();
        const cpu = data.cpu?.percent ?? null;
        const memTotal = data.memory?.totalBytes ?? null;
        const memUsed = data.memory?.usedBytes ?? null;
        const storTotal = data.storage?.totalBytes ?? null;
        const storUsed = data.storage?.usedBytes ?? null;

        if (cpu != null) setCpuUsage(cpu);
        if (data.cpu) {
          setCpuModel(data.cpu.model ?? null);
          setCpuCores(Number.isFinite(data.cpu.cores) ? data.cpu.cores : null);
        }
        if (memTotal && memUsed != null) {
          const gb = memUsed / (1024 ** 3);
          const totalGb = memTotal / (1024 ** 3);
          setRamUsageGb(gb);
          setRamTotalGb(totalGb);
        }
        if (storTotal && storUsed != null) {
          const usedTb = storUsed / (1024 ** 4);
          const totalTb = storTotal / (1024 ** 4);
          setStorageUsedTb(usedTb);
          setStorageTotalTb(totalTb);
        }
        if (data.source) setSystemSource(data.source);
        if (Array.isArray(data.disks)) setDiskSpaces(data.disks);
        if (Array.isArray(data.diskIO)) setDiskIO(data.diskIO);
        if (Number.isFinite(data.uptimeSeconds)) setSystemUptimeSeconds(data.uptimeSeconds);
        if (Array.isArray(data.loadAverage) && data.loadAverage.length >= 3) setLoadAverage(data.loadAverage.slice(0, 3) as [number, number, number]);
      } catch {
        // ignore; keep last values
      }
    };

    const fetchRaid = async () => {
      try {
        const res = await fetch('/api/raid');
        if (!res.ok) return;
        const data = await res.json();
        setRaidArrays(Array.isArray(data.arrays) ? data.arrays : []);
        setTruenasPools(Array.isArray(data.truenas_pools) ? data.truenas_pools : []);
        setTruenasDisks(Array.isArray(data.truenas_disks) ? data.truenas_disks : []);
      } catch {
        // ignore
      }
    };

    fetchSystem();
    fetchRaid();
    const interval = setInterval(() => {
      fetchSystem();
      fetchRaid();
    }, 10000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (activeTab === 'general') {
      setGeneralLoading(true);
      Promise.all([
        fetch('/api/settings/general', { credentials: 'include' }).then((r) => (r.ok ? r.json() : null)),
        getGeminiKeySet(),
      ])
        .then(([data, aiSet]) => {
          if (data) {
            setGeneralLanguage(data.language ?? 'en');
            setGeneralTimezone(data.timezone ?? 'UTC');
            setGeneralTruenasUrl(data.truenasUrl ?? '');
            setGeneralTruenasApiKeySet(!!data.truenasApiKeySet);
            setGeneralMountPath(data.mountPath ?? '');
          }
          setGeminiKeySet(!!aiSet);
        })
        .catch(() => {})
        .finally(() => setGeneralLoading(false));
    }
  }, [activeTab]);
  useEffect(() => {
    if (activeTab === 'ai-assistant') {
      getGeminiKeySet().then(setGeminiKeySet);
    }
  }, [activeTab]);

  useEffect(() => {
    if (activeTab === 'network') {
      setNetworkLoading(true);
      fetch('/api/network')
        .then((res) => (res.ok ? res.json() : null))
        .then((data) => {
          setNetworkData(data || null);
        })
        .catch(() => setNetworkData(null))
        .finally(() => setNetworkLoading(false));
    }
  }, [activeTab]);

  useEffect(() => {
    if (activeTab === 'sftp') {
      fetch('/api/sftp/config')
        .then((res) => (res.ok ? res.json() : null))
        .then((data) => {
          if (data?.ok) setSftpConfig({ port: data.port, users: data.users || [], pending: data.pending || [], delete_pending: data.delete_pending || [] });
          else setSftpConfig(null);
        })
        .catch(() => setSftpConfig(null));
    }
  }, [activeTab]);

  useEffect(() => {
    if (activeTab !== 'system-log') return;
    const fetchLogs = async () => {
      setSystemLogLoading(true);
      try {
        const res = await fetch('/api/logs?limit=300');
        if (!res.ok) return;
        const data = await res.json();
        setSystemLogs(Array.isArray(data.logs) ? data.logs : []);
      } catch {
        setSystemLogs([]);
      } finally {
        setSystemLogLoading(false);
      }
    };
    fetchLogs();
    const interval = setInterval(fetchLogs, 5000);
    return () => clearInterval(interval);
  }, [activeTab]);

  useEffect(() => {
    const check = async () => {
      try {
        const res = await fetch('/api/security/2fa/status', { credentials: 'include' });
        const d = await res.json().catch(() => ({}));
        if (!res.ok) return;
        if (d.enabled === true && d.verified !== true) setShow2FAGate(true);
      } catch (_) {}
    };
    check();
  }, []);

  useEffect(() => {
    if (activeTab !== 'security') return;
    let cancelled = false;
    setFirewallLoading(true);
    Promise.all([
      fetch('/api/security/firewall', { credentials: 'include' }),
      fetch('/api/security/2fa/status', { credentials: 'include' }),
    ])
      .then(async ([fwRes, faRes]) => {
        const fw = await fwRes.json().catch(() => ({}));
        const fa = await faRes.json().catch(() => ({}));
        return { fw, fa };
      })
      .then(({ fw, fa }) => {
        if (cancelled) return;
        setFirewallEnabled(Boolean(fw?.enabled));
        setFirewallRules(Array.isArray(fw?.rules) ? fw.rules : []);
        setTwoFaEnabled(Boolean(fa?.enabled));
        setTwoFaVerified(Boolean(fa?.verified));
      })
      .catch(() => {
        if (!cancelled) setFirewallRules([]);
      })
      .finally(() => {
        if (!cancelled) setFirewallLoading(false);
      });
    return () => { cancelled = true; };
  }, [activeTab]);

  useEffect(() => {
    if (activeTab !== 'ports') return;
    const fetchPorts = async () => {
      setListeningPortsLoading(true);
      try {
        const res = await fetch('/api/ports');
        if (!res.ok) return;
        const data = await res.json();
        const raw = Array.isArray(data.container) ? data.container : Array.isArray(data.ports) ? data.ports : [];
        setListeningPorts(raw.map((p) => (typeof p === 'object' && p != null && 'port' in p) ? { port: p.port, name: p.name ?? 'Internal' } : { port: Number(p), name: 'Internal' }));
        setDockerPorts(Array.isArray(data.docker) ? data.docker : []);
        setTruenasPorts(Array.isArray(data.truenas) ? data.truenas : []);
      } catch {
        setListeningPorts([]);
        setDockerPorts([]);
        setTruenasPorts([]);
      } finally {
        setListeningPortsLoading(false);
      }
    };
    fetchPorts();
    const interval = setInterval(fetchPorts, 10000);
    return () => clearInterval(interval);
  }, [activeTab]);

  const renderContent = () => {
    switch (activeTab) {
      case 'general': {
        const timezones = ['UTC', 'America/New_York', 'America/Los_Angeles', 'America/Chicago', 'Europe/London', 'Europe/Paris', 'Asia/Tokyo', 'Asia/Seoul', 'Asia/Shanghai', 'Australia/Sydney'];
        return (
          <div className="space-y-6">
            <h1 className="text-2xl font-bold text-slate-800">{t('general', language)}</h1>
            {generalLoading ? (
              <p className="text-slate-500 text-sm">{t('loading', language)}</p>
            ) : (
              <div className="space-y-6 w-full">
                <div className="bg-white p-6 rounded-2xl border border-slate-200">
                  <h3 className="font-bold text-slate-800 mb-3">{t('language', language)}</h3>
                  <select
                    value={generalLanguage}
                    onChange={(e) => setGeneralLanguage(e.target.value)}
                    className="w-full px-4 py-2 border border-slate-200 rounded-lg text-sm"
                  >
                    <option value="en">{t('english', language)}</option>
                    <option value="ko">{t('korean', language)}</option>
                  </select>
                </div>
                <div className="bg-white p-6 rounded-2xl border border-slate-200">
                  <h3 className="font-bold text-slate-800 mb-3">{t('timezone', language)}</h3>
                  <select
                    value={generalTimezone}
                    onChange={(e) => setGeneralTimezone(e.target.value)}
                    className="w-full px-4 py-2 border border-slate-200 rounded-lg text-sm"
                  >
                    {timezones.map((tz) => (
                      <option key={tz} value={tz}>{tz}</option>
                    ))}
                  </select>
                </div>
                <div className="bg-white p-6 rounded-2xl border border-slate-200">
                  <h3 className="font-bold text-slate-800 mb-3">{t('truenasApi', language)}</h3>
                  <p className="text-sm text-slate-500 mb-2">{t('truenasApiDesc', language)}</p>
                  <input
                    type="text"
                    value={generalTruenasUrl}
                    onChange={(e) => setGeneralTruenasUrl(e.target.value)}
                    placeholder="https://truenas.example.com"
                    className="w-full px-4 py-2 border border-slate-200 rounded-lg text-sm mb-2"
                  />
                  <input
                    type="password"
                    value={generalTruenasApiKey}
                    onChange={(e) => setGeneralTruenasApiKey(e.target.value)}
                    placeholder={generalTruenasApiKeySet ? t('apiKeyPlaceholderKeep', language) : t('apiKeyPlaceholder', language)}
                    className="w-full px-4 py-2 border border-slate-200 rounded-lg text-sm"
                  />
                </div>
                <div className="bg-white p-6 rounded-2xl border border-slate-200">
                  <h3 className="font-bold text-slate-800 mb-3">{t('aiAssistantApiKey', language)}</h3>
                  <p className="text-sm text-slate-500 mb-2">{t('aiAssistantApiKeyDesc', language)}</p>
                  <input
                    type="password"
                    value={generalAiKey}
                    onChange={(e) => setGeneralAiKey(e.target.value)}
                    placeholder={geminiKeySet ? t('apiKeyPlaceholderKeep', language) : t('apiKeyPlaceholder', language)}
                    className="w-full px-4 py-2 border border-slate-200 rounded-lg text-sm"
                  />
                </div>
                <div className="bg-white p-6 rounded-2xl border border-slate-200">
                  <h3 className="font-bold text-slate-800 mb-3">{t('mountPath', language)}</h3>
                  <p className="text-sm text-slate-500 mb-2">{t('mountPathDesc', language)}</p>
                  <input
                    type="text"
                    value={generalMountPath}
                    onChange={(e) => setGeneralMountPath(e.target.value)}
                    placeholder="/data"
                    className="w-full px-4 py-2 border border-slate-200 rounded-lg text-sm"
                  />
                </div>
                <button
                  type="button"
                  disabled={generalSaving}
                  onClick={async () => {
                    setGeneralSaving(true);
                    try {
                      const body: Record<string, unknown> = {
                        language: generalLanguage,
                        timezone: generalTimezone,
                        truenasUrl: generalTruenasUrl,
                        mountPath: generalMountPath,
                      };
                      if (generalTruenasApiKey) body.truenasApiKey = generalTruenasApiKey;
                      const res = await fetch('/api/settings/general', {
                        method: 'PUT',
                        credentials: 'include',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(body),
                      });
                      if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'Failed');
                      if (generalAiKey) {
                        await saveGeminiKey(generalAiKey);
                        setGeminiKeySet(true);
                        setGeneralAiKey('');
                      }
                      if (generalTruenasApiKey) {
                        setGeneralTruenasApiKeySet(true);
                        setGeneralTruenasApiKey('');
                      }
                      setTimezone(generalTimezone);
                      setLanguage(generalLanguage);
                      addNotification('Saved', 'General settings updated.', 'success');
                    } catch (e) {
                      addNotification('Error', e instanceof Error ? e.message : 'Failed to save.', 'error');
                    }
                    setGeneralSaving(false);
                  }}
                  className="px-6 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 disabled:opacity-50"
                >
                  {generalSaving ? t('saving', language) : t('save', language)}
                </button>
              </div>
            )}
          </div>
        );
      }
      case 'health':
        return (
          <div className="space-y-8 animate-in fade-in slide-in-from-bottom-2 duration-300">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <h1 className="text-2xl font-bold text-slate-800">System Overview</h1>
              <div className="flex items-center gap-2 flex-wrap">
                {systemSource === 'netdata' && (
                  <span className="bg-sky-100 text-sky-700 px-3 py-1 rounded-full text-xs font-bold">Netdata</span>
                )}
                <div className="flex items-center gap-2 bg-emerald-100 text-emerald-700 px-3 py-1 rounded-full text-xs font-bold">
                  <div className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse" />
                  System Healthy
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm col-span-1">
                <h3 className="text-sm font-bold text-slate-500 mb-4 flex items-center gap-2">
                  <Database size={16} /> Storage Utilization
                </h3>
                <div className="relative h-40">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={[
                          { name: 'Used', value: storageUsedTb != null && storageTotalTb != null ? storageUsedTb : 7.2 },
                          { name: 'Free', value: storageUsedTb != null && storageTotalTb != null ? Math.max(storageTotalTb - storageUsedTb, 0) : 2.8 },
                        ]}
                        cx="50%" cy="50%" innerRadius={50} outerRadius={65} paddingAngle={5} dataKey="value"
                      >
                        <Cell fill="#3b82f6" /><Cell fill="#e2e8f0" />
                      </Pie>
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
                    <span className="text-xl font-bold text-slate-700">
                      {storageUsedTb != null && storageTotalTb != null && storageTotalTb > 0
                        ? `${((storageUsedTb / storageTotalTb) * 100).toFixed(0)}%`
                        : '—'}
                    </span>
                  </div>
                </div>
                <div className="text-center font-bold text-slate-700">
                  {storageUsedTb && storageTotalTb
                    ? `${storageUsedTb.toFixed(1)} TB / ${storageTotalTb.toFixed(1)} TB`
                    : '7.2 TB / 10 TB'}
                </div>
              </div>

              <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm flex items-center gap-6">
                <div className="p-4 bg-orange-100 text-orange-600 rounded-2xl"><Cpu size={32} /></div>
                <div className="flex-1">
                  <div className="text-xs text-slate-400 font-bold mb-1">CPU Usage</div>
                  <div className="text-3xl font-black text-slate-800">
                    {(cpuUsage ?? 24).toFixed(1)}%
                  </div>
                  <div className="mt-2 w-full h-1.5 bg-slate-100 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-orange-500 transition-all duration-1000"
                      style={{ width: `${Math.max(0, Math.min(100, cpuUsage ?? 24))}%` }}
                    />
                  </div>
                </div>
              </div>

              <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm flex items-center gap-6">
                <div className="p-4 bg-blue-100 text-blue-600 rounded-2xl"><Database size={32} /></div>
                <div className="flex-1">
                  <div className="text-xs text-slate-400 font-bold mb-1">RAM Usage</div>
                  <div className="text-3xl font-black text-slate-800">
                    {(ramUsageGb ?? 4.1).toFixed(1)} GB
                  </div>
                  <div className="mt-2 w-full h-1.5 bg-slate-100 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-blue-500 transition-all duration-1000"
                      style={{
                        width: `${Math.max(
                          0,
                          Math.min(
                            100,
                            ((ramUsageGb ?? 4.1) / (ramTotalGb ?? 8)) * 100
                          )
                        )}%`,
                      }}
                    />
                  </div>
                </div>
              </div>
            </div>

            {(systemUptimeSeconds != null || loadAverage != null || raidArrays.length > 0 || truenasPools.length > 0) && (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                {systemUptimeSeconds != null && (
                  <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
                    <h3 className="text-sm font-bold text-slate-500 mb-3 flex items-center gap-2">
                      <Clock size={16} /> System Uptime
                    </h3>
                    <div className="text-2xl font-black text-slate-800">
                      {systemUptimeSeconds >= 86400
                        ? `${Math.floor(systemUptimeSeconds / 86400)}d ${Math.floor((systemUptimeSeconds % 86400) / 3600)}h`
                        : systemUptimeSeconds >= 3600
                          ? `${Math.floor(systemUptimeSeconds / 3600)}h ${Math.floor((systemUptimeSeconds % 3600) / 60)}m`
                          : systemUptimeSeconds >= 60
                            ? `${Math.floor(systemUptimeSeconds / 60)}m`
                            : `${Math.floor(systemUptimeSeconds)}s`}
                    </div>
                  </div>
                )}
                {loadAverage != null && (
                  <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
                    <h3 className="text-sm font-bold text-slate-500 mb-3 flex items-center gap-2">
                      <Activity size={16} /> Load Average
                    </h3>
                    <div className="flex flex-wrap gap-4">
                      <div>
                        <div className="text-[10px] font-bold text-slate-400 uppercase">1m</div>
                        <div className="text-xl font-black text-slate-800">{loadAverage[0].toFixed(2)}</div>
                      </div>
                      <div>
                        <div className="text-[10px] font-bold text-slate-400 uppercase">5m</div>
                        <div className="text-xl font-black text-slate-800">{loadAverage[1].toFixed(2)}</div>
                      </div>
                      <div>
                        <div className="text-[10px] font-bold text-slate-400 uppercase">15m</div>
                        <div className="text-xl font-black text-slate-800">{loadAverage[2].toFixed(2)}</div>
                      </div>
                    </div>
                  </div>
                )}
                {raidArrays.length > 0 && (
                  <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
                    <h3 className="text-sm font-bold text-slate-500 mb-3 flex items-center gap-2">
                      <Layers size={16} /> RAID (md)
                    </h3>
                    <div className="space-y-2">
                      {raidArrays.map((arr) => (
                        <div key={arr.name} className="p-2 rounded-lg bg-slate-50 border border-slate-100">
                          <div className="font-bold text-slate-800 text-sm">{arr.name}</div>
                          <div className="text-xs text-slate-500">{arr.level} · {arr.summary}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {truenasPools.length > 0 && (
                  <>
                    <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
                      <h3 className="text-sm font-bold text-slate-500 mb-3 flex items-center gap-2">
                        <Database size={16} /> TrueNAS Storage Pool
                      </h3>
                      <div className="space-y-2">
                        {truenasPools.map((p) => (
                          <div key={p.name} className="p-2 rounded-lg bg-slate-50 border border-slate-100 flex items-center justify-between gap-2">
                            <div className="font-bold text-slate-800 text-sm">{p.name}</div>
                            <span className={`text-xs font-medium px-2 py-0.5 rounded ${p.healthy ? 'bg-emerald-100 text-emerald-700' : 'bg-amber-100 text-amber-700'}`}>
                              {p.healthy ? 'Healthy' : 'Degraded'}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                    {(cpuModel != null || cpuCores != null || cpuUsage != null) && (
                      <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
                        <h3 className="text-sm font-bold text-slate-500 mb-3 flex items-center gap-2">
                          <Cpu size={16} /> CPU Info
                        </h3>
                        <div className="space-y-1.5">
                          {cpuModel != null && (
                            <div className="text-sm text-slate-800 truncate" title={cpuModel}>
                              {cpuModel}
                            </div>
                          )}
                          {(cpuCores != null || cpuUsage != null) && (
                            <div className="text-xs text-slate-500">
                              {cpuCores != null && `${cpuCores} cores`}
                              {cpuCores != null && cpuUsage != null && ' · '}
                              {cpuUsage != null && `${cpuUsage.toFixed(1)}% usage`}
                            </div>
                          )}
                        </div>
                      </div>
                    )}
{(truenasPools.some((p) => p.topology?.length) || truenasDisks.length > 0) && (
                      <div className="col-span-full bg-white p-6 rounded-2xl border border-slate-200 shadow-sm space-y-6">
                        {truenasPools.some((p) => p.topology?.length) && (
                          <div>
                            <h4 className="text-xs font-bold text-slate-400 uppercase mb-2 flex items-center gap-2">
                              <Layers size={14} /> RAID Configuration
                            </h4>
                            <div className="space-y-3">
                              {truenasPools.map((p) =>
                                (p.topology?.length ?? 0) > 0 ? (
                                  <div key={p.name} className="space-y-1.5">
                                    <div className="text-sm font-bold text-slate-700">{p.name}</div>
                                    {p.topology!.map((vdev, i) => (
                                      <div key={i} className="pl-3 text-sm text-slate-600">
                                        <span className="font-mono text-slate-500">{vdev.type}</span>
                                        {vdev.disks.length > 0 && (
                                          <span className="ml-2 text-slate-600">
                                            {vdev.disks.join(', ')}
                                          </span>
                                        )}
                                      </div>
                                    ))}
                                  </div>
                                ) : null
                              )}
                            </div>
                          </div>
                        )}
                        {truenasDisks.length > 0 && (
                          <div>
                            <h4 className="text-xs font-bold text-slate-400 uppercase mb-2 flex items-center gap-2">
                              <HardDrive size={14} /> Disk Info
                            </h4>
                            <div className="overflow-x-auto">
                              <table className="w-full text-sm">
                                <thead>
                                  <tr className="text-left text-slate-500 border-b border-slate-200">
                                    <th className="py-2 pr-3 font-medium">Name</th>
                                    <th className="py-2 pr-3 font-medium">Size</th>
                                    <th className="py-2 pr-3 font-medium">Model</th>
                                    <th className="py-2 font-medium">Pool</th>
                                  </tr>
                                </thead>
                                <tbody className="divide-y divide-slate-100">
                                  {truenasDisks.map((d) => (
                                    <tr key={d.name} className="text-slate-700">
                                      <td className="py-2 pr-3 font-mono text-slate-800">{d.devname || d.name}</td>
                                      <td className="py-2 pr-3">
                                        {d.size != null
                                          ? (d.size / (1024 ** 4)).toFixed(2) + ' TB'
                                          : '—'}
                                      </td>
                                      <td className="py-2 pr-3">{d.model ?? '—'}</td>
                                      <td className="py-2">{d.pool ?? '—'}</td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </>
                )}
                {raidArrays.length === 0 && truenasPools.length === 0 && (
                  <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
                    <h3 className="text-sm font-bold text-slate-500 mb-3 flex items-center gap-2">
                      <Layers size={16} /> RAID / Storage Pools
                    </h3>
                    <p className="text-sm text-slate-500">
                      Host RAID is not visible in Docker. To show <strong>TrueNAS</strong> storage pools, set <code className="text-xs bg-slate-100 px-1 rounded">TRUENAS_URL</code> and <code className="text-xs bg-slate-100 px-1 rounded">TRUENAS_API_KEY</code> in General settings or in docker-compose, then restart the container.
                    </p>
                  </div>
                )}
              </div>
            )}
          </div>
        );
      case 'users':
        return (
          <div className="space-y-6 animate-in fade-in duration-300">
             <div className="flex justify-between items-center mb-6">
                <h1 className="text-2xl font-bold text-slate-800">User & Groups</h1>
                <button className="flex items-center gap-2 bg-blue-600 text-white px-4 py-2 rounded-lg text-sm font-bold hover:bg-blue-700">
                  <UserPlus size={16} /> Create User
                </button>
             </div>
             <div className="bg-white rounded-2xl border border-slate-200">
                <table className="w-full text-left">
                  <thead className="bg-slate-50 border-b border-slate-200">
                    <tr>
                      <th className="px-6 py-3 text-xs font-bold text-slate-400 uppercase">Username</th>
                      <th className="px-6 py-3 text-xs font-bold text-slate-400 uppercase">Group</th>
                      <th className="px-6 py-3 text-xs font-bold text-slate-400 uppercase">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    <tr>
                      <td className="px-6 py-4 font-medium">admin</td>
                      <td className="px-6 py-4 text-sm text-slate-500">administrators</td>
                      <td className="px-6 py-4"><span className="text-xs bg-emerald-100 text-emerald-600 px-2 py-1 rounded-full font-bold">Enabled</span></td>
                    </tr>
                    <tr>
                      <td className="px-6 py-4 font-medium">guest</td>
                      <td className="px-6 py-4 text-sm text-slate-500">users</td>
                      <td className="px-6 py-4"><span className="text-xs bg-slate-100 text-slate-400 px-2 py-1 rounded-full font-bold">Disabled</span></td>
                    </tr>
                  </tbody>
                </table>
             </div>
          </div>
        );
      case 'security':
        return (
          <div className="space-y-6 overflow-y-auto min-h-full">
            <h1 className="text-2xl font-bold text-slate-800 mb-6">Security Advisor</h1>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-6 min-w-0">
              <div className="bg-white p-6 rounded-2xl border border-slate-200 min-w-0 overflow-hidden">
                <ShieldAlert className="text-amber-500 mb-4" size={32} />
                <h3 className="font-bold text-slate-800 mb-2">Firewall Status</h3>
                <p className="text-sm text-slate-500 mb-4">
                  {firewallLoading ? 'Loading…' : firewallEnabled ? `Firewall is enabled with ${(firewallRules?.length ?? 0)} active rule(s).` : 'Firewall is disabled.'}
                </p>
                <button type="button" onClick={() => setFirewallModalOpen(true)} className="text-sm font-bold text-blue-600 hover:underline">Edit Rules →</button>
              </div>
              <div className="bg-white p-6 rounded-2xl border border-slate-200 min-w-0 overflow-hidden">
                <Key className="text-emerald-500 mb-4" size={32} />
                <h3 className="font-bold text-slate-800 mb-2">Login Protection (2-Step Verification)</h3>
                <div className="flex items-center justify-between gap-4 mb-4 min-w-0">
                  <p className="text-sm text-slate-500 min-w-0">
                    {twoFaEnabled ? (twoFaVerified ? '2-Step verification is on. You are signed in.' : '2-Step verification is on. Enter code when prompted.') : '2-Step verification is off. Turn on to require a code when signing in.'}
                  </p>
                  <label className="flex items-center gap-2 shrink-0 cursor-pointer">
                    <span className="text-sm font-medium text-slate-700">OFF</span>
                    <button
                      type="button"
                      role="switch"
                      aria-checked={twoFaEnabled}
                      className={`relative inline-flex h-6 w-11 flex-shrink-0 rounded-full border-2 border-transparent transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 ${twoFaEnabled ? 'bg-blue-600' : 'bg-slate-200'}`}
                      onClick={async () => {
                        if (twoFaEnabled) {
                          try {
                            await fetch('/api/security/2fa/disable', { method: 'POST', credentials: 'include' });
                            setTwoFaEnabled(false);
                            setTwoFaVerified(false);
                            setTwoFaSetupQr(null);
                            setTwoFaSetupSecret('');
                            addNotification('2FA disabled', 'Login protection is now off.', 'success');
                          } catch {
                            addNotification('Error', 'Failed to disable 2FA.', 'error');
                          }
                        } else {
                          setTwoFaModalOpen(true);
                        }
                      }}
                    >
                      <span className={`pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow ring-0 transition-transform ${twoFaEnabled ? 'translate-x-5' : 'translate-x-1'}`} />
                    </button>
                    <span className="text-sm font-medium text-slate-700">ON</span>
                  </label>
                </div>
                <button type="button" onClick={() => setTwoFaModalOpen(true)} className="text-sm font-bold text-blue-600 hover:underline shrink-0">Settings →</button>
              </div>
            </div>

            {firewallModalOpen && (
              <FirewallModal
                enabled={firewallEnabled}
                rules={Array.isArray(firewallRules) ? firewallRules : []}
                onClose={() => setFirewallModalOpen(false)}
                onSave={async (enabled, rules) => {
                  try {
                    const res = await fetch('/api/security/firewall', {
                      method: 'PUT',
                      credentials: 'include',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({ enabled, rules }),
                    });
                    if (!res.ok) throw new Error();
                    const d = await res.json();
                    setFirewallEnabled(d.enabled);
                    setFirewallRules(d.rules || []);
                    addNotification('Saved', 'Firewall rules updated.', 'success');
                    setFirewallModalOpen(false);
                  } catch {
                    addNotification('Error', 'Failed to save firewall rules.', 'error');
                  }
                }}
              />
            )}
            {twoFaModalOpen && (
              <TwoFaModal
                enabled={twoFaEnabled}
                verified={twoFaVerified}
                qrDataUrl={twoFaSetupQr}
                secret={twoFaSetupSecret}
                onClose={() => {
                  setTwoFaModalOpen(false);
                  setTwoFaSetupQr(null);
                  setTwoFaSetupSecret('');
                }}
                onEnable={async () => {
                  try {
                    const res = await fetch('/api/security/2fa/setup', { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' } });
                    const d = await res.json();
                    if (d.qrDataUrl) setTwoFaSetupQr(d.qrDataUrl);
                    if (d.secret) setTwoFaSetupSecret(d.secret);
                    setTwoFaEnabled(true);
                    addNotification('2FA enabled', 'Scan the QR code with your authenticator app.', 'success');
                  } catch {
                    addNotification('Error', 'Failed to enable 2FA.', 'error');
                  }
                }}
                onDisable={async () => {
                  try {
                    await fetch('/api/security/2fa/disable', { method: 'POST', credentials: 'include' });
                    setTwoFaEnabled(false);
                    setTwoFaVerified(false);
                    setTwoFaSetupQr(null);
                    setTwoFaSetupSecret('');
                    addNotification('2FA disabled', 'Login protection has been turned off.', 'success');
                    setTwoFaModalOpen(false);
                  } catch {
                    addNotification('Error', 'Failed to disable 2FA.', 'error');
                  }
                }}
              />
            )}
          </div>
        );
      case 'display':
        return (
          <div className="space-y-6 animate-in fade-in duration-300">
            <h1 className="text-2xl font-bold text-slate-800 mb-6">Display & Theme</h1>

            <div className="bg-white p-6 rounded-2xl border border-slate-200">
              <h3 className="font-bold text-slate-800 mb-4 flex items-center gap-2"><Palette size={18} /> Theme</h3>
              <p className="text-sm text-slate-500 mb-4">Adjust desktop overlay and readability.</p>
              <div className="grid grid-cols-3 gap-4">
                {([
                  { id: 'light' as ThemeMode, label: 'Light', desc: 'Light overlay', className: 'bg-slate-200 text-slate-700 border-slate-300' },
                  { id: 'dark' as ThemeMode, label: 'Dark', desc: 'Dark overlay', className: 'bg-slate-800 text-white border-slate-600' },
                  { id: 'dynamic' as ThemeMode, label: 'Dynamic', desc: 'Follow system', className: 'bg-gradient-to-br from-blue-500 to-purple-600 text-white border-slate-400' },
                ]).map((opt) => (
                  <button
                    key={opt.id}
                    type="button"
                    onClick={() => { setTheme(opt.id); addNotification('Applied', `Theme: ${opt.label}`, 'success'); }}
                    className={`aspect-video rounded-xl border-2 flex flex-col items-center justify-center gap-1 transition-all hover:scale-[1.02] ${theme === opt.id ? 'ring-2 ring-blue-500 ring-offset-2 border-blue-500' : 'border-slate-300'} ${opt.className}`}
                  >
                    <span className="text-sm font-bold">{opt.label}</span>
                    <span className="text-[10px] opacity-90">{opt.desc}</span>
                  </button>
                ))}
              </div>
            </div>

            <div className="bg-white p-6 rounded-2xl border border-slate-200">
              <h3 className="font-bold text-slate-800 mb-4 flex items-center gap-2"><Monitor size={18} /> Background</h3>
              <p className="text-sm text-slate-500 mb-4">Choose desktop background.</p>
              <div className="grid grid-cols-4 gap-3">
                {BACKGROUND_PRESETS.map((preset) => (
                  <button
                    key={preset.id}
                    type="button"
                    onClick={() => { setBackground(preset.id); addNotification('Applied', `Background: ${preset.label}`, 'success'); }}
                    className={`rounded-xl h-16 border-2 overflow-hidden transition-all hover:scale-[1.03] ${background === preset.id ? 'ring-2 ring-blue-500 ring-offset-2 border-blue-500' : 'border-slate-200'}`}
                    style={preset.style}
                    title={preset.label}
                  >
                    <span className="text-xs font-bold drop-shadow-md text-white bg-black/30 px-1.5 py-0.5 rounded">{preset.label}</span>
                  </button>
                ))}
                <button
                  type="button"
                  onClick={() => setBackground('custom')}
                  className={`rounded-xl h-16 border-2 border-dashed flex flex-col items-center justify-center text-slate-500 text-xs font-medium transition-all hover:bg-slate-50 ${background === 'custom' ? 'ring-2 ring-blue-500 ring-offset-2 border-blue-500 bg-blue-50' : 'border-slate-300'}`}
                >
                  Custom URL
                </button>
              </div>
              {background === 'custom' && (
                <div className="mt-4 flex gap-2">
                  <input
                    type="url"
                    value={backgroundCustomUrl}
                    onChange={(e) => setBackgroundCustomUrl(e.target.value)}
                    placeholder="https://example.com/image.jpg"
                    className="flex-1 px-3 py-2 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                  />
                  <button
                    type="button"
                    onClick={() => { setBackgroundCustomUrl(backgroundCustomUrl); addNotification('Applied', 'Background URL has been applied.', 'success'); }}
                    className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700"
                  >
                    Apply
                  </button>
                </div>
              )}
            </div>
          </div>
        );
      case 'ai-assistant':
        return (
          <div className="space-y-6 animate-in fade-in duration-300">
            <h1 className="text-2xl font-bold text-slate-800 mb-6">AI Assistant</h1>
            <div className="bg-white p-6 rounded-2xl border border-slate-200">
              <h3 className="font-bold text-slate-800 mb-4 flex items-center gap-2">
                <Bot size={18} /> Gemini API Key
              </h3>
              <p className="text-sm text-slate-500 mb-4">
                Enter the API key from Google AI Studio for AI Assistant (Gemini). The key is stored encrypted on the server.
              </p>
              <div className="flex flex-col sm:flex-row gap-3">
                <input
                  type="password"
                  value={aiApiKeyInput}
                  onChange={(e) => setAiApiKeyInput(e.target.value)}
                  placeholder={geminiKeySet ? '••••••••••••••••' : 'API key'}
                  className="flex-1 px-4 py-2.5 border border-slate-200 rounded-xl text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                  autoComplete="off"
                />
                <button
                  type="button"
                  onClick={async () => {
                    try {
                      await saveGeminiKey(aiApiKeyInput);
                      setAiApiKeyInput('');
                      setGeminiKeySet(true);
                      addNotification('Saved', 'AI Assistant API key has been stored encrypted.', 'success');
                    } catch (e) {
                      addNotification('Save failed', e instanceof Error ? e.message : 'Failed to save', 'warning');
                    }
                  }}
                  className="px-4 py-2.5 bg-blue-600 text-white rounded-xl text-sm font-medium hover:bg-blue-700 transition-colors shrink-0"
                >
                  Save
                </button>
              </div>
              {geminiKeySet && (
                <p className="text-xs text-emerald-600 mt-2 font-medium">API key is set. Enter a new key above and save to replace.</p>
              )}
            </div>
          </div>
        );
      case 'sftp':
        return (
          <div className="space-y-6 animate-in fade-in duration-300">
            <h1 className="text-2xl font-bold text-slate-800 mb-6">SFTP</h1>

            <div className="bg-white p-6 rounded-2xl border border-slate-200">
              <h3 className="font-bold text-slate-800 mb-4 flex items-center gap-2"><Server size={18} /> Port</h3>
              <p className="text-sm text-slate-500 mb-4">Port for SFTP access (1–65535). Run Apply or Restart SFTP below to apply changes.</p>
              <div className="flex items-center gap-3">
                <input
                  type="number"
                  min={1}
                  max={65535}
                  value={sftpConfig?.port ?? 1014}
                  onChange={(e) => setSftpConfig((c) => (c ? { ...c, port: Math.max(1, Math.min(65535, Number(e.target.value) || 1014)) } : null))}
                  className="w-24 px-3 py-2 border border-slate-200 rounded-lg text-sm"
                />
                <button
                  type="button"
                  onClick={async () => {
                    const port = sftpConfig?.port ?? 1014;
                    try {
                      const res = await fetch('/api/sftp/config/port', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ port }) });
                      const data = await res.json();
                      if (data.ok) {
                        addNotification('Saved', `SFTP port set to ${port}.`, 'success');
                        const r = await fetch('/api/sftp/config');
                        const j = await r.json();
                        if (j?.ok) setSftpConfig((c) => (c ? { ...c, port: j.port } : null));
                      } else addNotification('Failed', data.error || 'Save failed', 'warning');
                    } catch (e) {
                      addNotification('Error', e instanceof Error ? e.message : 'Failed', 'warning');
                    }
                  }}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700"
                >
                  Save port
                </button>
              </div>
            </div>

            <div className="bg-white p-6 rounded-2xl border border-slate-200">
              <h3 className="font-bold text-slate-800 mb-4">Add user (Pending)</h3>
              <div className="flex flex-wrap gap-3 mb-4">
                <input
                  type="text"
                  placeholder="Username"
                  value={sftpAddName}
                  onChange={(e) => setSftpAddName(e.target.value)}
                  className="px-3 py-2 border border-slate-200 rounded-lg text-sm w-32"
                />
                <input
                  type="password"
                  placeholder="Password"
                  value={sftpAddPassword}
                  onChange={(e) => setSftpAddPassword(e.target.value)}
                  className="px-3 py-2 border border-slate-200 rounded-lg text-sm w-32"
                />
                <input
                  type="text"
                  placeholder="Mount path (e.g. TESTUSER or /mnt/...)"
                  value={sftpAddMount}
                  onChange={(e) => setSftpAddMount(e.target.value)}
                  className="px-3 py-2 border border-slate-200 rounded-lg text-sm flex-1 min-w-[180px]"
                />
                <button
                  type="button"
                  onClick={async () => {
                    if (!sftpAddName.trim() || !sftpAddMount.trim()) {
                      addNotification('Required', 'Enter username and mount path.', 'warning');
                      return;
                    }
                    try {
                      const res = await fetch('/api/sftp/pending/add', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: sftpAddName, password: sftpAddPassword, mount: sftpAddMount }) });
                      const data = await res.json();
                      if (data.ok) {
                        setSftpAddName(''); setSftpAddPassword(''); setSftpAddMount('');
                        addNotification('Added', `${sftpAddName} added to Pending. Run Apply to reflect.`, 'success');
                        const r = await fetch('/api/sftp/config');
                        const j = await r.json();
                        if (j?.ok) setSftpConfig({ port: j.port, users: j.users || [], pending: j.pending || [], delete_pending: j.delete_pending || [] });
                      } else addNotification('Failed', data.error || 'Add failed', 'warning');
                    } catch (e) {
                      addNotification('Error', e instanceof Error ? e.message : 'Failed', 'warning');
                    }
                  }}
                  className="px-4 py-2 bg-slate-700 text-white rounded-lg text-sm font-medium hover:bg-slate-800"
                >
                  Add to Pending
                </button>
              </div>
            </div>

            <div className="bg-white p-6 rounded-2xl border border-slate-200">
              <h3 className="font-bold text-slate-800 mb-4">User list</h3>
              <div className="space-y-2 mb-4">
                {sftpConfig?.pending?.map((u) => (
                  <div key={u.name} className="flex items-center justify-between py-2 border-b border-slate-100">
                    <span className="font-mono text-sm text-amber-700 bg-amber-50 px-2 py-1 rounded">Pending</span>
                    <span className="font-medium">{u.name}</span>
                    <span className="text-slate-500 text-sm truncate max-w-[200px]">{u.mount}</span>
                    <button type="button" onClick={async () => {
                      try {
                        await fetch('/api/sftp/pending/delete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: u.name }) });
                        const r = await fetch('/api/sftp/config');
                        const j = await r.json();
                        if (j?.ok) setSftpConfig({ port: j.port, users: j.users || [], pending: j.pending || [], delete_pending: j.delete_pending || [] });
                      } catch {}
                    }} className="text-red-600 text-sm hover:underline">Delete</button>
                  </div>
                ))}
                {sftpConfig?.users?.map((u) => (
                  <div key={u.name} className="flex items-center justify-between py-2 border-b border-slate-100">
                    <span className={`font-mono text-xs px-2 py-1 rounded ${(sftpConfig?.delete_pending || []).includes(u.name) ? 'bg-red-100 text-red-700' : 'bg-slate-100 text-slate-600'}`}>
                      {(sftpConfig?.delete_pending || []).includes(u.name) ? 'Delete pending' : (u.enabled !== false ? 'Active' : 'Inactive')}
                    </span>
                    <span className="font-medium">{u.name}</span>
                    <span className="text-slate-500 text-sm truncate max-w-[200px]">{u.mount}</span>
                    <div className="flex gap-2">
                      {!(sftpConfig?.delete_pending || []).includes(u.name) && (
                        <button type="button" onClick={async () => {
                          try {
                            await fetch('/api/sftp/users/toggle', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: u.name }) });
                            const r = await fetch('/api/sftp/config');
                            const j = await r.json();
                            if (j?.ok) setSftpConfig({ port: j.port, users: j.users || [], pending: j.pending || [], delete_pending: j.delete_pending || [] });
                            addNotification('Applied', `User ${u.name} state has been updated.`, 'success');
                          } catch (e) { addNotification('Error', e instanceof Error ? e.message : 'Failed', 'warning'); }
                        }} className="text-blue-600 text-sm hover:underline">{u.enabled !== false ? 'Deactivate' : 'Activate'}</button>
                      )}
                      {!(sftpConfig?.delete_pending || []).includes(u.name) ? (
                        <button type="button" onClick={async () => {
                          try {
                            await fetch('/api/sftp/users/mark-delete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: u.name }) });
                            const r = await fetch('/api/sftp/config');
                            const j = await r.json();
                            if (j?.ok) setSftpConfig({ port: j.port, users: j.users || [], pending: j.pending || [], delete_pending: j.delete_pending || [] });
                            addNotification('Delete pending', `${u.name} will be removed on Restart SFTP.`, 'info');
                          } catch {}
                        }} className="text-red-600 text-sm hover:underline">Mark delete</button>
                      ) : (
                        <button type="button" onClick={async () => {
                          try {
                            await fetch('/api/sftp/users/unmark-delete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: u.name }) });
                            const r = await fetch('/api/sftp/config');
                            const j = await r.json();
                            if (j?.ok) setSftpConfig({ port: j.port, users: j.users || [], pending: j.pending || [], delete_pending: j.delete_pending || [] });
                          } catch {}
                        }} className="text-slate-600 text-sm hover:underline">Cancel</button>
                      )}
                    </div>
                  </div>
                ))}
                {(!sftpConfig?.users?.length && !sftpConfig?.pending?.length) && (
                  <p className="text-slate-500 text-sm">No users registered. Add to Pending above, then run Apply.</p>
                )}
              </div>
              <div className="flex gap-3 pt-4 border-t border-slate-200">
                <button
                  type="button"
                  onClick={async () => {
                    try {
                      const res = await fetch('/api/sftp/apply', { method: 'POST' });
                      const data = await res.json();
                      if (data.ok) {
                        addNotification('Applied', 'Pending users applied and SFTP container updated.', 'success');
                        const r = await fetch('/api/sftp/config');
                        const j = await r.json();
                        if (j?.ok) setSftpConfig({ port: j.port, users: j.users || [], pending: j.pending || [], delete_pending: j.delete_pending || [] });
                      } else addNotification('Failed', data.error || 'Apply failed', 'warning');
                    } catch (e) {
                      addNotification('Error', e instanceof Error ? e.message : 'Apply failed', 'warning');
                    }
                  }}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700"
                >
                  Apply (Pending → active)
                </button>
                <button
                  type="button"
                  onClick={async () => {
                    if (!confirm('Apply delete-pending users and restart SFTP. Active sessions may be disconnected. Continue?')) return;
                    try {
                      const res = await fetch('/api/sftp/restart', { method: 'POST' });
                      const data = await res.json();
                      if (data.ok) {
                        addNotification('Restarted', 'SFTP restarted with delete-pending applied.', 'success');
                        const r = await fetch('/api/sftp/config');
                        const j = await r.json();
                        if (j?.ok) setSftpConfig({ port: j.port, users: j.users || [], pending: j.pending || [], delete_pending: j.delete_pending || [] });
                      } else addNotification('Failed', data.error || 'Restart failed', 'warning');
                    } catch (e) {
                      addNotification('Error', e instanceof Error ? e.message : 'Restart failed', 'warning');
                    }
                  }}
                  className="px-4 py-2 bg-amber-600 text-white rounded-lg text-sm font-medium hover:bg-amber-700"
                >
                  Restart SFTP
                </button>
              </div>
            </div>
          </div>
        );
      case 'network':
        return (
          <div className="space-y-6 animate-in fade-in duration-300">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <h1 className="text-2xl font-bold text-slate-800">Network Settings</h1>
              {networkData?.source === 'truenas' && (
                <span className="text-xs font-medium text-blue-600 bg-blue-50 px-2 py-1 rounded">From TrueNAS</span>
              )}
            </div>
            <div className="bg-white p-6 rounded-2xl border border-slate-200 space-y-4">
              {networkLoading && (
                <p className="text-sm text-slate-500">Loading...</p>
              )}
              {!networkLoading && networkData && (
                <>
                  <div className="flex justify-between items-center p-3 hover:bg-slate-50 rounded-xl transition-colors">
                    <div className="flex items-center gap-3">
                      <Wifi size={20} className="text-blue-500" />
                      <div>
                        <p className="font-bold">Hostname</p>
                        <p className="text-xs text-slate-400 font-mono">{networkData.hostname}</p>
                      </div>
                    </div>
                  </div>
                  {networkData.interfaces.length > 0 && (
                    <div className="p-3">
                      <p className="font-bold text-slate-800 mb-2">Network Interfaces</p>
                      <ul className="space-y-2">
                        {networkData.interfaces.map((iface, i) => (
                          <li key={`${iface.name}-${i}`} className="flex justify-between items-center py-2 border-b border-slate-100 last:border-0">
                            <span className="text-sm font-medium text-slate-700">{iface.name}</span>
                            <span className="text-xs font-mono text-slate-500">{iface.address}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  <div className="flex justify-between items-center p-3 hover:bg-slate-50 rounded-xl transition-colors">
                    <div className="flex items-center gap-3">
                      <Globe size={20} className="text-slate-400" />
                      <div>
                        <p className="font-bold">DNS Servers</p>
                        <p className="text-xs text-slate-400 font-mono">
                          {networkData.dns.length > 0 ? networkData.dns.join(', ') : '—'}
                        </p>
                      </div>
                    </div>
                  </div>
                  {networkData.networkStats?.byInterface && Object.keys(networkData.networkStats.byInterface).length > 0 && (
                    <div className="p-3 border-t border-slate-100">
                      <p className="font-bold text-slate-800 mb-2 flex items-center gap-2">
                        Traffic (Netdata)
                      </p>
                      <ul className="space-y-1.5">
                        {Object.entries(networkData.networkStats.byInterface).map(([label, value]) => (
                          <li key={label} className="flex justify-between items-center text-sm">
                            <span className="font-mono text-slate-600">{label}</span>
                            <span className="text-slate-500">{typeof value === 'number' ? value.toLocaleString() : value}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </>
              )}
              {!networkLoading && !networkData && (
                <p className="text-sm text-slate-500">Could not load network information from the server.</p>
              )}
            </div>
          </div>
        );
      case 'ports':
        return (
          <div className="space-y-6 animate-in fade-in duration-300">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <h1 className="text-2xl font-bold text-slate-800">Ports in Use</h1>
              <p className="text-sm text-slate-500">Container (CloudStation) and TrueNAS ports (refreshed every 10s)</p>
            </div>

            <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
              <div className="px-6 py-3 border-b border-slate-200 bg-slate-50">
                <h2 className="text-sm font-semibold text-slate-700">This Container (CloudStation) — LISTEN</h2>
                <p className="text-xs text-slate-500 mt-0.5">Ports listening inside this container (same as host if 1:1 mapping)</p>
              </div>
              {listeningPortsLoading && listeningPorts.length === 0 && dockerPorts.length === 0 && truenasPorts.length === 0 ? (
                <div className="p-8 text-center text-slate-500">Loading…</div>
              ) : listeningPorts.length === 0 ? (
                <div className="p-6 text-center text-slate-500">No ports in LISTEN state.</div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left">
                    <thead className="bg-slate-50 border-b border-slate-200">
                      <tr>
                        <th className="px-6 py-3 text-xs font-bold text-slate-500 uppercase tracking-wider">Name</th>
                        <th className="px-6 py-3 text-xs font-bold text-slate-500 uppercase tracking-wider">Port</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {listeningPorts.map((row) => (
                        <tr key={`c-${row.port}`} className="hover:bg-slate-50/50">
                          <td className="px-6 py-3 text-sm text-slate-700 font-medium">{row.name}</td>
                          <td className="px-6 py-3 font-mono text-slate-800 font-semibold">{row.port}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            {dockerPorts.length > 0 && (
              <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
                <div className="px-6 py-3 border-b border-slate-200 bg-slate-50">
                  <h2 className="text-sm font-semibold text-slate-700">Docker (Host Port Mapping)</h2>
                  <p className="text-xs text-slate-500 mt-0.5">Use host port to connect. Container port is for reference.</p>
                </div>
                <div className="overflow-x-auto max-h-[400px] overflow-y-auto">
                  <table className="w-full text-left">
                    <thead className="bg-white border-b border-slate-200 sticky top-0 z-10 shadow-[0_1px_0_0_rgba(0,0,0,0.05)]">
                      <tr>
                        <th className="px-6 py-3 text-xs font-bold text-slate-500 uppercase tracking-wider bg-white">Container</th>
                        <th className="px-6 py-3 text-xs font-bold text-slate-500 uppercase tracking-wider bg-white">Host Port</th>
                        <th className="px-6 py-3 text-xs font-bold text-slate-500 uppercase tracking-wider bg-white">Container (internal)</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {dockerPorts.map((row, i) => (
                        <tr key={`d-${row.service}-${row.port}-${i}`} className="hover:bg-slate-50/50">
                          <td className="px-6 py-2 text-sm text-slate-700 font-medium">{row.service}</td>
                          <td className="px-6 py-2 font-mono text-slate-800 font-semibold">{row.port}</td>
                          <td className="px-6 py-2 font-mono text-slate-600">{row.containerPort != null ? row.containerPort : '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {truenasPorts.length > 0 && (
              <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
                <div className="px-6 py-3 border-b border-slate-200 bg-slate-50">
                  <h2 className="text-sm font-semibold text-slate-700">TrueNAS System</h2>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left">
                    <thead className="bg-slate-50 border-b border-slate-200">
                      <tr>
                        <th className="px-6 py-3 text-xs font-bold text-slate-500 uppercase tracking-wider">Service</th>
                        <th className="px-6 py-3 text-xs font-bold text-slate-500 uppercase tracking-wider">Port</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {truenasPorts.map((row, i) => (
                        <tr key={`t-${row.service}-${row.port}-${i}`} className="hover:bg-slate-50/50">
                          <td className="px-6 py-3 text-sm text-slate-700 font-medium">{row.service}</td>
                          <td className="px-6 py-3 font-mono text-slate-800 font-semibold">{row.port}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        );
      case 'system-log':
        return (
          <div className="space-y-6 animate-in fade-in duration-300">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <h1 className="text-2xl font-bold text-slate-800">System Log</h1>
              <p className="text-sm text-slate-500">Logs from this container (refreshes every 5s)</p>
            </div>
            <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
              {systemLogLoading && systemLogs.length === 0 ? (
                <div className="p-8 text-center text-slate-500">Loading logs...</div>
              ) : systemLogs.length === 0 ? (
                <div className="p-8 text-center text-slate-500">No log entries yet.</div>
              ) : (
                <div className="p-4 font-mono text-xs overflow-auto max-h-[70vh] bg-slate-50 border-t border-slate-100">
                  {systemLogs.map((entry, i) => (
                    <div
                      key={i}
                      className={`py-1.5 px-2 rounded border-l-2 ${
                        entry.level === 'error'
                          ? 'border-red-400 bg-red-50/50 text-red-800'
                          : entry.level === 'warn'
                            ? 'border-amber-400 bg-amber-50/50 text-amber-800'
                            : 'border-slate-200 bg-white text-slate-700'
                      }`}
                    >
                      <span className="text-slate-400 shrink-0 mr-2">{entry.time}</span>
                      <span className="font-semibold text-slate-500 uppercase mr-2">[{entry.level}]</span>
                      <span className="break-all">{entry.text}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        );
      default:
        return (
          <div className="h-full flex flex-col items-center justify-center text-slate-400">
            <Globe2 size={48} className="opacity-10 mb-4" />
            <p>This module is currently in maintenance mode.</p>
          </div>
        );
    }
  };

  const menuGroups = [
    { titleKey: 'menuGeneral' as const, items: [{ id: 'general', labelKey: 'general' as const, icon: Settings }] },
    { titleKey: 'menuSystemInfo' as const, items: [{ id: 'health', labelKey: 'health', icon: Activity }, { id: 'ports', labelKey: 'ports', icon: Globe }, { id: 'system-log', labelKey: 'systemLog', icon: FileText }] },
    { titleKey: 'menuUserAccess' as const, items: [{ id: 'users', labelKey: 'userAndGroups', icon: Users }, { id: 'login-settings', labelKey: 'requireLogin', icon: Lock, openModal: true }, { id: 'security', labelKey: 'security', icon: Shield }] },
    { titleKey: 'menuPersonalization' as const, items: [{ id: 'display', labelKey: 'themeAndDisplay', icon: Monitor }, { id: 'network', labelKey: 'network', icon: Wifi }] },
    { titleKey: 'menuServices' as const, items: [{ id: 'sftp', labelKey: 'sftp', icon: Server }, { id: 'update', labelKey: 'updateRestore', icon: RefreshCw }, { id: 'ai-assistant', labelKey: 'aiAssistant', icon: Bot }] },
  ];

  return (
    <>
      {show2FAGate && createPortal(
        <div
          className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-slate-900/95"
          style={{ top: 0, left: 0, right: 0, bottom: 0, minWidth: '100vw', minHeight: '100dvh' }}
        >
          <div className="bg-white rounded-2xl shadow-xl p-8 max-w-sm w-full">
            <h2 className="text-lg font-bold text-slate-800 mb-2">2-Step Verification</h2>
            <p className="text-sm text-slate-500 mb-4">Enter the code from your authenticator app.</p>
            <input
              type="text"
              value={twoFaCode}
              onChange={(e) => { setTwoFaCode(e.target.value.replace(/\D/g, '').slice(0, 6)); setTwoFaVerifyError(''); }}
              placeholder="000000"
              className="w-full px-4 py-3 border border-slate-200 rounded-lg text-center text-lg font-mono tracking-widest mb-2"
              maxLength={6}
            />
            {twoFaVerifyError && <p className="text-sm text-red-600 mb-2">{twoFaVerifyError}</p>}
            <button
              type="button"
              onClick={async () => {
                const code = twoFaCode.trim();
                if (!code) { setTwoFaVerifyError('Enter a code'); return; }
                try {
                  const res = await fetch('/api/security/2fa/verify', {
                    method: 'POST',
                    credentials: 'include',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ code }),
                  });
                  const data = await res.json().catch(() => ({}));
                  if (res.ok && data.ok) {
                    setShow2FAGate(false);
                    setTwoFaVerified(true);
                    setTwoFaCode('');
                    setTwoFaVerifyError('');
                    addNotification('Verified', 'You are signed in.', 'success');
                  } else {
                    setTwoFaVerifyError(data.error || 'Invalid code');
                  }
                } catch {
                  setTwoFaVerifyError('Request failed');
                }
              }}
              className="w-full py-3 bg-blue-600 text-white rounded-lg font-medium hover:bg-blue-700"
            >
              Verify
            </button>
            <p className="mt-4 text-center">
              <button
                type="button"
                onClick={async () => {
                  try {
                    await fetch('/api/security/2fa/disable', { method: 'POST', credentials: 'include' });
                    setShow2FAGate(false);
                    setTwoFaEnabled(false);
                    setTwoFaVerified(false);
                    setTwoFaCode('');
                    setTwoFaVerifyError('');
                    addNotification('2FA disabled', 'You can turn it on again in Security settings.', 'success');
                  } catch {
                    addNotification('Error', 'Could not disable 2FA.', 'error');
                  }
                }}
                className="text-sm text-slate-500 hover:text-slate-700 underline"
              >
                Don’t have a code? Turn off 2-Step Verification
              </button>
            </p>
          </div>
        </div>,
        document.body
      )}
      <div className="flex h-full bg-slate-50 text-slate-700">
      <div className="w-64 border-r border-slate-200 bg-white p-4 space-y-6 shrink-0 overflow-y-auto">
        {menuGroups.map((group, idx) => (
          <div key={idx} className="space-y-1">
            <h2 className="text-[10px] font-bold text-slate-400 uppercase px-3 tracking-widest mb-1">{t(group.titleKey, language)}</h2>
            {group.items.map((item) => {
              const isModalItem = 'openModal' in item && item.openModal;
              return (
                <button
                  key={item.id}
                  onClick={() => isModalItem ? setShowLoginSettingsModal(true) : setActiveTab(item.id as TabID)}
                  className={`w-full flex items-center gap-3 px-4 py-2 rounded-xl transition-all font-medium text-sm ${
                    (!isModalItem && activeTab === item.id) || (isModalItem && showLoginSettingsModal)
                      ? 'bg-blue-600 text-white shadow-lg shadow-blue-500/30'
                      : 'text-slate-600 hover:bg-slate-100'
                  }`}
                >
                  <item.icon size={18} /> {t(item.labelKey, language)}
                </button>
              );
            })}
          </div>
        ))}
      </div>

      <div className="flex-1 overflow-auto p-8 bg-[#f8fafc] min-h-0">
        {renderContent()}
      </div>
      {showLoginSettingsModal && (
        <LoginSettingsModal onClose={() => setShowLoginSettingsModal(false)} />
      )}
    </div>
    </>
  );
};

export default ControlPanel;
