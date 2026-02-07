
import React, { useState, useEffect } from 'react';
import { 
  Activity, Database, Users, Shield, Globe, Cpu, RefreshCw, UserPlus, ShieldAlert, Key, Globe2, Monitor, Wifi, Palette, Bot, HardDrive, Server, Clock, Layers, FileText
} from 'lucide-react';
import { useOSStore, type ThemeMode } from '../../store';
import { getGeminiKeySet, saveGeminiKey } from '../../lib/ai';
import { BACKGROUND_PRESETS } from '../../lib/customization';
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip } from 'recharts';

type TabID = 'health' | 'users' | 'security' | 'display' | 'network' | 'update' | 'ai-assistant' | 'sftp' | 'system-log' | 'ports';

const ControlPanel: React.FC = () => {
  const { addNotification, theme, background, backgroundCustomUrl, setTheme, setBackground, setBackgroundCustomUrl } = useOSStore();
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
  const [listeningPorts, setListeningPorts] = useState<number[]>([]);
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
    networkStats?: { byInterface: Record<string, number>; source: string };
  } | null>(null);
  const [networkLoading, setNetworkLoading] = useState(false);
  const [systemLogs, setSystemLogs] = useState<{ time: string; level: string; text: string }[]>([]);
  const [systemLogLoading, setSystemLogLoading] = useState(false);

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
    if (activeTab !== 'ports') return;
    const fetchPorts = async () => {
      setListeningPortsLoading(true);
      try {
        const res = await fetch('/api/ports');
        if (!res.ok) return;
        const data = await res.json();
        setListeningPorts(Array.isArray(data.container) ? data.container : Array.isArray(data.ports) ? data.ports : []);
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

            {(systemUptimeSeconds != null || loadAverage != null || raidArrays.length > 0 || truenasPools.length > 0) && (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                {systemUptimeSeconds != null && (
                  <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
                    <h3 className="text-sm font-bold text-slate-500 mb-3 flex items-center gap-2">
                      <Clock size={16} /> 시스템 가동 시간
                    </h3>
                    <div className="text-2xl font-black text-slate-800">
                      {systemUptimeSeconds >= 86400
                        ? `${Math.floor(systemUptimeSeconds / 86400)}일 ${Math.floor((systemUptimeSeconds % 86400) / 3600)}시간`
                        : systemUptimeSeconds >= 3600
                          ? `${Math.floor(systemUptimeSeconds / 3600)}시간 ${Math.floor((systemUptimeSeconds % 3600) / 60)}분`
                          : systemUptimeSeconds >= 60
                            ? `${Math.floor(systemUptimeSeconds / 60)}분`
                            : `${Math.floor(systemUptimeSeconds)}초`}
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
                        <div className="text-[10px] font-bold text-slate-400 uppercase">1분</div>
                        <div className="text-xl font-black text-slate-800">{loadAverage[0].toFixed(2)}</div>
                      </div>
                      <div>
                        <div className="text-[10px] font-bold text-slate-400 uppercase">5분</div>
                        <div className="text-xl font-black text-slate-800">{loadAverage[1].toFixed(2)}</div>
                      </div>
                      <div>
                        <div className="text-[10px] font-bold text-slate-400 uppercase">15분</div>
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
                        <Database size={16} /> TrueNAS 스토리지 풀
                      </h3>
                      <div className="space-y-2">
                        {truenasPools.map((p) => (
                          <div key={p.name} className="p-2 rounded-lg bg-slate-50 border border-slate-100 flex items-center justify-between gap-2">
                            <div className="font-bold text-slate-800 text-sm">{p.name}</div>
                            <span className={`text-xs font-medium px-2 py-0.5 rounded ${p.healthy ? 'bg-emerald-100 text-emerald-700' : 'bg-amber-100 text-amber-700'}`}>
                              {p.healthy ? '정상' : '이상'}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                    {(cpuModel != null || cpuCores != null || cpuUsage != null) && (
                      <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm">
                        <h3 className="text-sm font-bold text-slate-500 mb-3 flex items-center gap-2">
                          <Cpu size={16} /> CPU 정보
                        </h3>
                        <div className="space-y-1.5">
                          {cpuModel != null && (
                            <div className="text-sm text-slate-800 truncate" title={cpuModel}>
                              {cpuModel}
                            </div>
                          )}
                          {(cpuCores != null || cpuUsage != null) && (
                            <div className="text-xs text-slate-500">
                              {cpuCores != null && `${cpuCores}코어`}
                              {cpuCores != null && cpuUsage != null && ' · '}
                              {cpuUsage != null && `사용률 ${cpuUsage.toFixed(1)}%`}
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
                              <Layers size={14} /> RAID 구성
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
                              <HardDrive size={14} /> 디스크 정보
                            </h4>
                            <div className="overflow-x-auto">
                              <table className="w-full text-sm">
                                <thead>
                                  <tr className="text-left text-slate-500 border-b border-slate-200">
                                    <th className="py-2 pr-3 font-medium">이름</th>
                                    <th className="py-2 pr-3 font-medium">용량</th>
                                    <th className="py-2 pr-3 font-medium">모델</th>
                                    <th className="py-2 font-medium">풀</th>
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
                      <Layers size={16} /> RAID / 스토리지 풀
                    </h3>
                    <p className="text-sm text-slate-500">
                      Docker 환경에서는 호스트 RAID가 보이지 않습니다. <strong>TrueNAS</strong> 스토리지 풀을 표시하려면 <code className="text-xs bg-slate-100 px-1 rounded">TRUENAS_URL</code>, <code className="text-xs bg-slate-100 px-1 rounded">TRUENAS_API_KEY</code>를 docker-compose 환경 변수에 설정한 뒤 컨테이너를 재시작하세요.
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
              <h3 className="font-bold text-slate-800 mb-4 flex items-center gap-2"><Palette size={18} /> Theme</h3>
              <p className="text-sm text-slate-500 mb-4">데스크톱 오버레이와 가독성을 조정합니다.</p>
              <div className="grid grid-cols-3 gap-4">
                {([
                  { id: 'light' as ThemeMode, label: 'Light', desc: '밝은 오버레이', className: 'bg-slate-200 text-slate-700 border-slate-300' },
                  { id: 'dark' as ThemeMode, label: 'Dark', desc: '어두운 오버레이', className: 'bg-slate-800 text-white border-slate-600' },
                  { id: 'dynamic' as ThemeMode, label: 'Dynamic', desc: '시스템 설정 따름', className: 'bg-gradient-to-br from-blue-500 to-purple-600 text-white border-slate-400' },
                ]).map((opt) => (
                  <button
                    key={opt.id}
                    type="button"
                    onClick={() => { setTheme(opt.id); addNotification('적용됨', `테마: ${opt.label}`, 'success'); }}
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
              <p className="text-sm text-slate-500 mb-4">데스크톱 배경을 선택하세요.</p>
              <div className="grid grid-cols-4 gap-3">
                {BACKGROUND_PRESETS.map((preset) => (
                  <button
                    key={preset.id}
                    type="button"
                    onClick={() => { setBackground(preset.id); addNotification('적용됨', `배경: ${preset.label}`, 'success'); }}
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
                    onClick={() => { setBackgroundCustomUrl(backgroundCustomUrl); addNotification('적용됨', '배경 URL이 적용되었습니다.', 'success'); }}
                    className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700"
                  >
                    적용
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
      case 'sftp':
        return (
          <div className="space-y-6 animate-in fade-in duration-300">
            <h1 className="text-2xl font-bold text-slate-800 mb-6">SFTP</h1>

            <div className="bg-white p-6 rounded-2xl border border-slate-200">
              <h3 className="font-bold text-slate-800 mb-4 flex items-center gap-2"><Server size={18} /> 포트</h3>
              <p className="text-sm text-slate-500 mb-4">SFTP 서버에 접속할 때 사용할 포트(1–65535). 변경 후 적용하려면 아래 Apply 또는 Restart SFTP를 실행하세요.</p>
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
                        addNotification('저장됨', `SFTP 포트가 ${port}(으)로 저장되었습니다.`, 'success');
                        const r = await fetch('/api/sftp/config');
                        const j = await r.json();
                        if (j?.ok) setSftpConfig((c) => (c ? { ...c, port: j.port } : null));
                      } else addNotification('실패', data.error || '저장 실패', 'warning');
                    } catch (e) {
                      addNotification('오류', e instanceof Error ? e.message : 'Failed', 'warning');
                    }
                  }}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700"
                >
                  포트 저장
                </button>
              </div>
            </div>

            <div className="bg-white p-6 rounded-2xl border border-slate-200">
              <h3 className="font-bold text-slate-800 mb-4">사용자 추가 (Pending)</h3>
              <div className="flex flex-wrap gap-3 mb-4">
                <input
                  type="text"
                  placeholder="사용자명"
                  value={sftpAddName}
                  onChange={(e) => setSftpAddName(e.target.value)}
                  className="px-3 py-2 border border-slate-200 rounded-lg text-sm w-32"
                />
                <input
                  type="password"
                  placeholder="비밀번호"
                  value={sftpAddPassword}
                  onChange={(e) => setSftpAddPassword(e.target.value)}
                  className="px-3 py-2 border border-slate-200 rounded-lg text-sm w-32"
                />
                <input
                  type="text"
                  placeholder="마운트 경로 (예: KJEFILM 또는 /mnt/...)"
                  value={sftpAddMount}
                  onChange={(e) => setSftpAddMount(e.target.value)}
                  className="px-3 py-2 border border-slate-200 rounded-lg text-sm flex-1 min-w-[180px]"
                />
                <button
                  type="button"
                  onClick={async () => {
                    if (!sftpAddName.trim() || !sftpAddMount.trim()) {
                      addNotification('입력 필요', '사용자명과 마운트 경로를 입력하세요.', 'warning');
                      return;
                    }
                    try {
                      const res = await fetch('/api/sftp/pending/add', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: sftpAddName, password: sftpAddPassword, mount: sftpAddMount }) });
                      const data = await res.json();
                      if (data.ok) {
                        setSftpAddName(''); setSftpAddPassword(''); setSftpAddMount('');
                        addNotification('추가됨', `${sftpAddName}이(가) Pending에 추가되었습니다. Apply로 반영하세요.`, 'success');
                        const r = await fetch('/api/sftp/config');
                        const j = await r.json();
                        if (j?.ok) setSftpConfig({ port: j.port, users: j.users || [], pending: j.pending || [], delete_pending: j.delete_pending || [] });
                      } else addNotification('실패', data.error || '추가 실패', 'warning');
                    } catch (e) {
                      addNotification('오류', e instanceof Error ? e.message : 'Failed', 'warning');
                    }
                  }}
                  className="px-4 py-2 bg-slate-700 text-white rounded-lg text-sm font-medium hover:bg-slate-800"
                >
                  Pending 추가
                </button>
              </div>
            </div>

            <div className="bg-white p-6 rounded-2xl border border-slate-200">
              <h3 className="font-bold text-slate-800 mb-4">사용자 목록</h3>
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
                    }} className="text-red-600 text-sm hover:underline">삭제</button>
                  </div>
                ))}
                {sftpConfig?.users?.map((u) => (
                  <div key={u.name} className="flex items-center justify-between py-2 border-b border-slate-100">
                    <span className={`font-mono text-xs px-2 py-1 rounded ${(sftpConfig?.delete_pending || []).includes(u.name) ? 'bg-red-100 text-red-700' : 'bg-slate-100 text-slate-600'}`}>
                      {(sftpConfig?.delete_pending || []).includes(u.name) ? '삭제 예정' : (u.enabled !== false ? '활성' : '비활성')}
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
                            addNotification('적용됨', `사용자 ${u.name} 상태가 반영되었습니다.`, 'success');
                          } catch (e) { addNotification('오류', e instanceof Error ? e.message : 'Failed', 'warning'); }
                        }} className="text-blue-600 text-sm hover:underline">{u.enabled !== false ? '비활성' : '활성'}</button>
                      )}
                      {!(sftpConfig?.delete_pending || []).includes(u.name) ? (
                        <button type="button" onClick={async () => {
                          try {
                            await fetch('/api/sftp/users/mark-delete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: u.name }) });
                            const r = await fetch('/api/sftp/config');
                            const j = await r.json();
                            if (j?.ok) setSftpConfig({ port: j.port, users: j.users || [], pending: j.pending || [], delete_pending: j.delete_pending || [] });
                            addNotification('삭제 예정', `Restart SFTP 시 ${u.name}이(가) 제거됩니다.`, 'info');
                          } catch {}
                        }} className="text-red-600 text-sm hover:underline">삭제 예정</button>
                      ) : (
                        <button type="button" onClick={async () => {
                          try {
                            await fetch('/api/sftp/users/unmark-delete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: u.name }) });
                            const r = await fetch('/api/sftp/config');
                            const j = await r.json();
                            if (j?.ok) setSftpConfig({ port: j.port, users: j.users || [], pending: j.pending || [], delete_pending: j.delete_pending || [] });
                          } catch {}
                        }} className="text-slate-600 text-sm hover:underline">취소</button>
                      )}
                    </div>
                  </div>
                ))}
                {(!sftpConfig?.users?.length && !sftpConfig?.pending?.length) && (
                  <p className="text-slate-500 text-sm">등록된 사용자가 없습니다. 위에서 Pending 추가 후 Apply하세요.</p>
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
                        addNotification('적용됨', 'Pending이 반영되고 SFTP 컨테이너가 갱신되었습니다.', 'success');
                        const r = await fetch('/api/sftp/config');
                        const j = await r.json();
                        if (j?.ok) setSftpConfig({ port: j.port, users: j.users || [], pending: j.pending || [], delete_pending: j.delete_pending || [] });
                      } else addNotification('실패', data.error || 'Apply 실패', 'warning');
                    } catch (e) {
                      addNotification('오류', e instanceof Error ? e.message : 'Apply failed', 'warning');
                    }
                  }}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700"
                >
                  Apply (Pending → 반영)
                </button>
                <button
                  type="button"
                  onClick={async () => {
                    if (!confirm('삭제 예정 사용자를 반영하고 SFTP를 재시작합니다. 접속 중인 세션이 끊길 수 있습니다. 계속할까요?')) return;
                    try {
                      const res = await fetch('/api/sftp/restart', { method: 'POST' });
                      const data = await res.json();
                      if (data.ok) {
                        addNotification('재시작됨', 'SFTP가 삭제 예정 반영 후 재시작되었습니다.', 'success');
                        const r = await fetch('/api/sftp/config');
                        const j = await r.json();
                        if (j?.ok) setSftpConfig({ port: j.port, users: j.users || [], pending: j.pending || [], delete_pending: j.delete_pending || [] });
                      } else addNotification('실패', data.error || 'Restart 실패', 'warning');
                    } catch (e) {
                      addNotification('오류', e instanceof Error ? e.message : 'Restart failed', 'warning');
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
                <p className="text-sm text-slate-500">서버에서 네트워크 정보를 불러올 수 없습니다.</p>
              )}
            </div>
          </div>
        );
      case 'ports':
        return (
          <div className="space-y-6 animate-in fade-in duration-300">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <h1 className="text-2xl font-bold text-slate-800">사용 중인 포트</h1>
              <p className="text-sm text-slate-500">컨테이너(CloudStation) 및 TrueNAS 시스템 포트 (10초마다 갱신)</p>
            </div>

            <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
              <div className="px-6 py-3 border-b border-slate-200 bg-slate-50">
                <h2 className="text-sm font-semibold text-slate-700">이 컨테이너 (CloudStation) — LISTEN</h2>
                <p className="text-xs text-slate-500 mt-0.5">이 컨테이너 내부에서 리스닝 중인 포트 (호스트와 1:1 매핑이면 동일 번호)</p>
              </div>
              {listeningPortsLoading && listeningPorts.length === 0 && dockerPorts.length === 0 && truenasPorts.length === 0 ? (
                <div className="p-8 text-center text-slate-500">불러오는 중...</div>
              ) : listeningPorts.length === 0 ? (
                <div className="p-6 text-center text-slate-500">LISTEN 중인 포트가 없습니다.</div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left">
                    <thead className="bg-slate-50/70 border-b border-slate-200">
                      <tr>
                        <th className="px-6 py-3 text-xs font-bold text-slate-500 uppercase tracking-wider">#</th>
                        <th className="px-6 py-3 text-xs font-bold text-slate-500 uppercase tracking-wider">Port</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {listeningPorts.map((port, i) => (
                        <tr key={`c-${port}`} className="hover:bg-slate-50/50">
                          <td className="px-6 py-3 text-sm text-slate-500 font-medium">{i + 1}</td>
                          <td className="px-6 py-3 font-mono text-slate-800 font-semibold">{port}</td>
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
                  <h2 className="text-sm font-semibold text-slate-700">Docker (호스트 포트 매핑)</h2>
                  <p className="text-xs text-slate-500 mt-0.5">접속 시 사용하는 건 호스트 포트입니다. 컨테이너 내부 포트는 참고용.</p>
                </div>
                <div className="overflow-x-auto max-h-[400px] overflow-y-auto">
                  <table className="w-full text-left">
                    <thead className="bg-slate-50/70 border-b border-slate-200 sticky top-0">
                      <tr>
                        <th className="px-6 py-3 text-xs font-bold text-slate-500 uppercase tracking-wider">컨테이너</th>
                        <th className="px-6 py-3 text-xs font-bold text-slate-500 uppercase tracking-wider">호스트 포트</th>
                        <th className="px-6 py-3 text-xs font-bold text-slate-500 uppercase tracking-wider">컨테이너(내부)</th>
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
                  <h2 className="text-sm font-semibold text-slate-700">TrueNAS 시스템</h2>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left">
                    <thead className="bg-slate-50/70 border-b border-slate-200">
                      <tr>
                        <th className="px-6 py-3 text-xs font-bold text-slate-500 uppercase tracking-wider">서비스</th>
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
    {
      title: 'System Information',
      items: [
        { id: 'health', label: 'Health', icon: Activity },
        { id: 'ports', label: 'Ports', icon: Globe },
        { id: 'system-log', label: 'System Log', icon: FileText },
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
        { id: 'sftp', label: 'SFTP', icon: Server },
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

      <div className="flex-1 overflow-auto p-8 bg-[#f8fafc]" key={activeTab}>
        {renderContent()}
      </div>
    </div>
  );
};

export default ControlPanel;
