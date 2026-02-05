
import React, { useState, useEffect } from 'react';
import { 
  Activity, Database, Users, Shield, Globe, Cpu, RefreshCw, UserPlus, ShieldAlert, Key, Globe2, Monitor, Wifi, Palette, Bot
} from 'lucide-react';
import { useOSStore } from '../../store';
import { getGeminiKeySet, saveGeminiKey } from '../../lib/ai';
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip } from 'recharts';

type TabID = 'health' | 'users' | 'security' | 'display' | 'network' | 'update' | 'ai-assistant';

const ControlPanel: React.FC = () => {
  const { addNotification } = useOSStore();
  const [activeTab, setActiveTab] = useState<TabID>('health');
  const [aiApiKeyInput, setAiApiKeyInput] = useState('');
  const [geminiKeySet, setGeminiKeySet] = useState<boolean | null>(null);
  const [cpuUsage, setCpuUsage] = useState<number | null>(null);
  const [ramUsageGb, setRamUsageGb] = useState<number | null>(null);
  const [ramTotalGb, setRamTotalGb] = useState<number | null>(null);
  const [storageUsedTb, setStorageUsedTb] = useState<number | null>(null);
  const [storageTotalTb, setStorageTotalTb] = useState<number | null>(null);
  const [raidArrays, setRaidArrays] = useState<{ name: string; level: string; summary: string; detail?: string }[]>([]);
  const [networkData, setNetworkData] = useState<{
    hostname: string;
    interfaces: { name: string; address: string; family: string; mac?: string | null }[];
    dns: string[];
  } | null>(null);
  const [networkLoading, setNetworkLoading] = useState(false);

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

  const renderContent = () => {
    switch (activeTab) {
      case 'health':
        return (
          <div className="space-y-8 animate-in fade-in slide-in-from-bottom-2 duration-300">
            <div className="flex items-center justify-between">
              <h1 className="text-2xl font-bold text-slate-800">System Overview</h1>
              <div className="flex items-center gap-2 bg-emerald-100 text-emerald-700 px-3 py-1 rounded-full text-xs font-bold">
                <div className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse" />
                System Healthy
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm col-span-1">
                <h3 className="text-sm font-bold text-slate-500 mb-4 flex items-center gap-2">
                  <Database size={16} /> Storage Utilization
                </h3>
                <div className="h-40">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={[
                          { name: 'Used', value: storageUsedTb && storageTotalTb ? storageUsedTb : 7.2 },
                          { name: 'Free', value: storageUsedTb && storageTotalTb ? Math.max(storageTotalTb - storageUsedTb, 0) : 2.8 },
                        ]}
                        cx="50%" cy="50%" innerRadius={50} outerRadius={65} paddingAngle={5} dataKey="value"
                      >
                        <Cell fill="#3b82f6" /><Cell fill="#e2e8f0" />
                      </Pie>
                    </PieChart>
                  </ResponsiveContainer>
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
          <div className="space-y-6 animate-in fade-in duration-300">
             <h1 className="text-2xl font-bold text-slate-800 mb-6">Security Advisor</h1>
             <div className="grid grid-cols-2 gap-6">
               <div className="bg-white p-6 rounded-2xl border border-slate-200">
                 <ShieldAlert className="text-amber-500 mb-4" size={32} />
                 <h3 className="font-bold text-slate-800 mb-2">Firewall Status</h3>
                 <p className="text-sm text-slate-500 mb-4">Firewall is currently enabled with 3 active rules.</p>
                 <button className="text-sm font-bold text-blue-600 hover:underline">Edit Rules →</button>
               </div>
               <div className="bg-white p-6 rounded-2xl border border-slate-200">
                 <Key className="text-emerald-500 mb-4" size={32} />
                 <h3 className="font-bold text-slate-800 mb-2">Login Protection</h3>
                 <p className="text-sm text-slate-500 mb-4">2-Step verification is active for administrative accounts.</p>
                 <button className="text-sm font-bold text-blue-600 hover:underline">Settings →</button>
               </div>
             </div>
          </div>
        );
      case 'display':
        return (
          <div className="space-y-6 animate-in fade-in duration-300">
             <h1 className="text-2xl font-bold text-slate-800 mb-6">Display & Theme</h1>
             <div className="bg-white p-6 rounded-2xl border border-slate-200">
               <h3 className="font-bold text-slate-800 mb-4 flex items-center gap-2"><Palette size={18} /> Theme Settings</h3>
               <div className="grid grid-cols-3 gap-4">
                 <div className="aspect-video rounded-xl bg-slate-800 border-4 border-blue-500 cursor-pointer flex items-center justify-center text-white text-xs font-bold">Dark Mode</div>
                 <div className="aspect-video rounded-xl bg-slate-200 border border-slate-300 cursor-pointer flex items-center justify-center text-slate-500 text-xs font-bold">Light Mode</div>
                 <div className="aspect-video rounded-xl bg-gradient-to-br from-blue-500 to-purple-500 border border-slate-300 cursor-pointer flex items-center justify-center text-white text-xs font-bold">Dynamic</div>
               </div>
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
                AI Assistant(Gemini) 사용을 위해 Google AI Studio에서 발급한 API Key를 입력하세요. 키는 서버에 AES-256-GCM으로 암호화되어 저장됩니다.
              </p>
              <div className="flex flex-col sm:flex-row gap-3">
                <input
                  type="password"
                  value={aiApiKeyInput}
                  onChange={(e) => setAiApiKeyInput(e.target.value)}
                  placeholder={geminiKeySet ? '••••••••••••••••' : 'API Key 입력'}
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
                      addNotification('저장됨', 'AI Assistant API Key가 서버에 암호화되어 저장되었습니다.', 'success');
                    } catch (e) {
                      addNotification('저장 실패', e instanceof Error ? e.message : 'Failed to save', 'warning');
                    }
                  }}
                  className="px-4 py-2.5 bg-blue-600 text-white rounded-xl text-sm font-medium hover:bg-blue-700 transition-colors shrink-0"
                >
                  저장
                </button>
              </div>
              {geminiKeySet && (
                <p className="text-xs text-emerald-600 mt-2 font-medium">API Key가 설정되어 있습니다. 새 키로 바꾸려면 위에 입력 후 저장하세요.</p>
              )}
            </div>
          </div>
        );
      case 'network':
        return (
          <div className="space-y-6 animate-in fade-in duration-300">
            <h1 className="text-2xl font-bold text-slate-800 mb-6">Network Settings</h1>
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
                </>
              )}
              {!networkLoading && !networkData && (
                <p className="text-sm text-slate-500">서버에서 네트워크 정보를 불러올 수 없습니다.</p>
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
    {
      title: 'System Information',
      items: [
        { id: 'health', label: 'Health', icon: Activity },
      ]
    },
    {
      title: 'User & Access',
      items: [
        { id: 'users', label: 'User & Groups', icon: Users },
        { id: 'security', label: 'Security', icon: Shield },
      ]
    },
    {
      title: 'Personalization',
      items: [
        { id: 'display', label: 'Theme & Display', icon: Monitor },
        { id: 'network', label: 'Network', icon: Wifi },
      ]
    },
    {
      title: 'Services',
      items: [
        { id: 'update', label: 'Update & Restore', icon: RefreshCw },
        { id: 'ai-assistant', label: 'AI Assistant', icon: Bot },
      ]
    }
  ];

  return (
    <div className="flex h-full bg-slate-50 text-slate-700">
      <div className="w-64 border-r border-slate-200 bg-white p-4 space-y-6 shrink-0 overflow-y-auto">
        {menuGroups.map((group, idx) => (
          <div key={idx} className="space-y-1">
            <h2 className="text-[10px] font-bold text-slate-400 uppercase px-3 tracking-widest mb-1">{group.title}</h2>
            {group.items.map((item) => (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id as TabID)}
                className={`w-full flex items-center gap-3 px-4 py-2 rounded-xl transition-all font-medium text-sm ${
                  activeTab === item.id 
                    ? 'bg-blue-600 text-white shadow-lg shadow-blue-500/30' 
                    : 'text-slate-600 hover:bg-slate-100'
                }`}
              >
                <item.icon size={18} /> {item.label}
              </button>
            ))}
          </div>
        ))}
      </div>

      <div className="flex-1 overflow-auto p-8 bg-[#f8fafc]">
        {renderContent()}
      </div>
    </div>
  );
};

export default ControlPanel;
