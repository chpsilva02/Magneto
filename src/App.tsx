import React, { useState, useEffect, useRef } from 'react';
import {
  Upload, Search, Download, Network, Layers, Terminal,
  ChevronDown, ChevronUp, FileText, AlertCircle, CheckCircle2,
  Copy, XCircle, Zap, Server, Shield, Globe, GitBranch,
  Activity, Settings, Eye, EyeOff, Sun, Moon, Monitor
} from 'lucide-react';

// ─────────────────────────────────────────────────────────────────────────────
// TINY UTILITIES
// ─────────────────────────────────────────────────────────────────────────────
function cn(...classes: (string | boolean | undefined | null)[]): string {
  return classes.filter(Boolean).join(' ');
}

// ─────────────────────────────────────────────────────────────────────────────
// TYPES
// ─────────────────────────────────────────────────────────────────────────────
type Tab    = 'discovery' | 'upload';
type Theme  = 'light' | 'dark';

// ─────────────────────────────────────────────────────────────────────────────
// STATIC DATA
// ─────────────────────────────────────────────────────────────────────────────
const VENDORS = [
  { value: 'cisco_ios',    label: 'Cisco IOS-XE' },
  { value: 'cisco_nxos',  label: 'Cisco NX-OS' },
  { value: 'aruba_os',    label: 'HP/HPE Aruba' },
  { value: 'hpe_comware', label: 'HPE Comware' },
  { value: 'juniper_junos', label: 'Juniper JunOS' },
  { value: 'huawei_vrp',  label: 'Huawei VRP' },
];

// ─────────────────────────────────────────────────────────────────────────────
// SHARED INPUT STYLES
// ─────────────────────────────────────────────────────────────────────────────
const inputCls = [
  'w-full rounded-lg border border-slate-300 dark:border-slate-700',
  'bg-white dark:bg-slate-900',
  'px-4 py-2.5 text-sm text-slate-900 dark:text-slate-100',
  'focus:outline-none focus:ring-2 focus:ring-cyan-500 dark:focus:ring-cyan-400',
  'focus:border-transparent transition-all placeholder:text-slate-400',
].join(' ');

const labelCls = 'block text-xs font-semibold tracking-widest uppercase text-slate-500 dark:text-slate-400 mb-1.5';

// ─────────────────────────────────────────────────────────────────────────────
// SUB-COMPONENTS
// ─────────────────────────────────────────────────────────────────────────────

function LayerPill({ label, color }: { label: string; color: string }) {
  return (
    <span className={`inline-flex items-center gap-1 text-xs font-bold px-2.5 py-0.5 rounded-full ${color}`}>
      {label}
    </span>
  );
}

function StatCard({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return (
    <div className="flex items-center gap-3 bg-slate-50 dark:bg-slate-800/60 rounded-xl px-4 py-3 border border-slate-200 dark:border-slate-700">
      <div className="text-cyan-500 dark:text-cyan-400">{icon}</div>
      <div>
        <p className="text-xs text-slate-500 dark:text-slate-400 font-medium">{label}</p>
        <p className="text-sm font-bold text-slate-900 dark:text-slate-100">{value}</p>
      </div>
    </div>
  );
}

function SectionTitle({ icon, children }: { icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <h3 className="flex items-center gap-2 text-sm font-bold tracking-wider uppercase text-slate-600 dark:text-slate-300 mb-3">
      <span className="text-cyan-500">{icon}</span>
      {children}
    </h3>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN APP
// ─────────────────────────────────────────────────────────────────────────────
export default function App() {
  // ── state ──────────────────────────────────────────────────────────
  const [activeTab,      setActiveTab]      = useState<Tab>('discovery');
  const [vendor,         setVendor]         = useState('cisco_ios');
  const [ip,             setIp]             = useState('');
  const [username,       setUsername]       = useState('');
  const [password,       setPassword]       = useState('');
  const [showPw,         setShowPw]         = useState(false);
  const [files,          setFiles]          = useState<FileList | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [loading,        setLoading]        = useState(false);
  const [resultXml,      setResultXml]      = useState<string | null>(null);
  const [rawOutputs,     setRawOutputs]     = useState<Record<string, string> | null>(null);
  const [errorMsg,       setErrorMsg]       = useState<string | null>(null);
  const [profiles,       setProfiles]       = useState<Record<string, any> | null>(null);
  const [showCommands,   setShowCommands]   = useState(false);
  const [showRawOutputs, setShowRawOutputs] = useState(false);
  const [topology,       setTopology]       = useState<any | null>(null);
  const [theme,          setTheme]          = useState<Theme>(() => {
    if (typeof window !== 'undefined') {
      const saved = localStorage.getItem('theme');
      if (saved === 'light' || saved === 'dark') return saved as Theme;
    }
    return 'dark';
  });
  const [commandText, setCommandText] = useState({ l1: '', l2: '', l3: '', hardware: '' });

  // ── effects ─────────────────────────────────────────────────────────
  useEffect(() => {
    document.documentElement.classList.remove('light', 'dark');
    document.documentElement.classList.add(theme);
    localStorage.setItem('theme', theme);
  }, [theme]);

  useEffect(() => {
    fetch('/api/profiles')
      .then(r => r.json())
      .then(data => {
        setProfiles(data);
        const saved = localStorage.getItem('magneto_commands_cisco_ios');
        if (saved) {
          setCommandText(JSON.parse(saved));
        } else if (data['cisco_ios']) {
          const p = data['cisco_ios'];
          setCommandText({ l1: p.l1.join('\n'), l2: p.l2.join('\n'), l3: p.l3.join('\n'), hardware: p.hardware.join('\n') });
        }
      })
      .catch(() => {});
  }, []);

  // ── handlers ────────────────────────────────────────────────────────
  const handleVendorChange = (v: string) => {
    setVendor(v);
    const saved = localStorage.getItem(`magneto_commands_${v}`);
    if (saved) {
      setCommandText(JSON.parse(saved));
    } else if (profiles?.[v]) {
      const p = profiles[v];
      setCommandText({ l1: p.l1.join('\n'), l2: p.l2.join('\n'), l3: p.l3.join('\n'), hardware: p.hardware.join('\n') });
    }
  };

  const handleSaveCommands = () => {
    localStorage.setItem(`magneto_commands_${vendor}`, JSON.stringify(commandText));
  };

  const handleClear = () => {
    setIp(''); setUsername(''); setPassword('');
    setFiles(null); setResultXml(null); setRawOutputs(null);
    setErrorMsg(null); setTopology(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const handleDiscovery = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true); setErrorMsg(null); setResultXml(null); setRawOutputs(null); setTopology(null);
    const customCommands = {
      l1: commandText.l1.split('\n').filter(c => c.trim()),
      l2: commandText.l2.split('\n').filter(c => c.trim()),
      l3: commandText.l3.split('\n').filter(c => c.trim()),
      hardware: commandText.hardware.split('\n').filter(c => c.trim()),
    };
    try {
      const res  = await fetch('/api/discovery', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, username, password, vendor, customCommands }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Erro desconhecido');
      setResultXml(data.xml); setRawOutputs(data.rawOutputs); setTopology(data.topology);
    } catch (err: any) { setErrorMsg(err.message); }
    finally { setLoading(false); }
  };

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!files || files.length === 0) return;
    setLoading(true); setErrorMsg(null); setResultXml(null); setRawOutputs(null); setTopology(null);
    try {
      const fd = new FormData();
      fd.append('vendor', vendor);
      Array.from(files).forEach(f => fd.append('files', f));
      const res  = await fetch('/api/upload', { method: 'POST', body: fd });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Erro desconhecido');
      setResultXml(data.xml); setTopology(data.topology);
    } catch (err: any) { setErrorMsg(err.message); }
    finally { setLoading(false); }
  };

  const downloadDrawio = () => {
    if (!resultXml) return;
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([resultXml], { type: 'application/xml' }));
    a.download = 'topology.drawio';
    a.click();
  };

  const downloadRawOutputs = () => {
    if (!rawOutputs) return;
    let text = '';
    for (const [cmd, out] of Object.entries(rawOutputs))
      text += `${'='.repeat(64)}\nCOMMAND: ${cmd}\n${'='.repeat(64)}\n${out}\n\n`;
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
    a.download = `raw_outputs_${ip.replace(/\./g,'_')}.txt`;
    a.click();
  };

  const copyToClipboard = async () => {
    if (!rawOutputs) return;
    let text = '';
    for (const [cmd, out] of Object.entries(rawOutputs))
      text += `${'='.repeat(64)}\nCOMMAND: ${cmd}\n${'='.repeat(64)}\n${out}\n\n`;
    try { await navigator.clipboard.writeText(text); } catch {}
  };

  // ── topology stats ────────────────────────────────────────────────
  const nodeCount = topology?.nodes?.length ?? 0;
  const linkCount = topology?.links?.length ?? 0;
  const l1Count   = topology?.links?.filter((l: any) => l.layer === 'L1').length ?? 0;
  const l2Count   = topology?.links?.filter((l: any) => l.layer === 'L2').length ?? 0;
  const l3Count   = topology?.links?.filter((l: any) => l.layer === 'L3').length ?? 0;

  // ─────────────────────────────────────────────────────────────────
  // RENDER
  // ─────────────────────────────────────────────────────────────────
  return (
    <div className="min-h-screen bg-slate-100 dark:bg-slate-950 text-slate-900 dark:text-slate-100 font-sans transition-colors duration-300">

      {/* ── HEADER ────────────────────────────────────────────────── */}
      <header className="sticky top-0 z-20 border-b border-slate-200 dark:border-slate-800 bg-white/80 dark:bg-slate-950/90 backdrop-blur-md">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center gap-4">
          {/* Logo mark */}
          <div className="flex items-center gap-2.5 flex-shrink-0">
            <div className="w-8 h-8 rounded-lg bg-cyan-500 flex items-center justify-center shadow-lg shadow-cyan-500/30">
              <Zap className="w-5 h-5 text-white" />
            </div>
            <span className="text-xl font-black tracking-tight text-slate-900 dark:text-white">
              Magn<span className="text-cyan-500">eto</span>
            </span>
          </div>

          <div className="hidden sm:flex items-center gap-2 ml-2 pl-4 border-l border-slate-200 dark:border-slate-700">
            <LayerPill label="L1 Física"      color="bg-emerald-100 dark:bg-emerald-900/40 text-emerald-700 dark:text-emerald-300" />
            <LayerPill label="L2 Lógica"      color="bg-blue-100 dark:bg-blue-900/40 text-blue-700 dark:text-blue-300" />
            <LayerPill label="L3 Roteamento"  color="bg-purple-100 dark:bg-purple-900/40 text-purple-700 dark:text-purple-300" />
          </div>

          {/* spacer */}
          <div className="flex-1" />

          {/* Theme toggle */}
          <button
            onClick={() => setTheme(t => t === 'dark' ? 'light' : 'dark')}
            className="p-2 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors text-slate-500 dark:text-slate-400"
            title="Alternar tema"
          >
            {theme === 'dark' ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
          </button>
        </div>
      </header>

      {/* ── MAIN ──────────────────────────────────────────────────── */}
      <main className="max-w-6xl mx-auto px-6 py-10 space-y-8">

        {/* ── HERO ───────────────────────────────────────────────── */}
        <div className="text-center space-y-2 pb-2">
          <h1 className="text-3xl font-black tracking-tight text-slate-900 dark:text-white">
            Network Topology Generator
          </h1>
          <p className="text-slate-500 dark:text-slate-400 text-sm max-w-xl mx-auto">
            Gere diagramas draw.io com 3 camadas (L1 Física · L2 Lógica · L3 Roteamento) a partir de SSH ou arquivos de coleta.
          </p>
        </div>

        {/* ── CARD ───────────────────────────────────────────────── */}
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm overflow-hidden">

          {/* TABS */}
          <div className="flex border-b border-slate-200 dark:border-slate-800">
            {([
              { id: 'discovery', icon: <Search className="w-4 h-4" />, label: 'Discovery Ativo (SSH)' },
              { id: 'upload',    icon: <Upload  className="w-4 h-4" />, label: 'Upload Offline' },
            ] as const).map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={cn(
                  'flex-1 py-4 px-6 text-sm font-semibold flex items-center justify-center gap-2 transition-all',
                  activeTab === tab.id
                    ? 'border-b-2 border-cyan-500 text-cyan-600 dark:text-cyan-400 bg-cyan-50/50 dark:bg-cyan-900/10'
                    : 'text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800/50'
                )}
              >
                {tab.icon} {tab.label}
              </button>
            ))}
          </div>

          <div className="p-8">
            {/* ERROR */}
            {errorMsg && (
              <div className="mb-6 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-700 rounded-xl p-4 flex items-start gap-3 text-red-700 dark:text-red-300 animate-in fade-in slide-in-from-top-2">
                <AlertCircle className="w-5 h-5 flex-shrink-0 mt-0.5" />
                <div>
                  <p className="font-bold text-sm mb-0.5">Erro na Execução</p>
                  <p className="text-sm opacity-80">{errorMsg}</p>
                </div>
              </div>
            )}

            {/* ── DISCOVERY FORM ──────────────────────────────────── */}
            {activeTab === 'discovery' && (
              <form onSubmit={handleDiscovery} className="space-y-6 max-w-2xl">

                {/* Vendor / OS — only in Discovery */}
                <div className="max-w-xs">
                  <label className={labelCls}>Vendor / OS</label>
                  <select
                    value={vendor}
                    onChange={e => handleVendorChange(e.target.value)}
                    className={inputCls}
                  >
                    {VENDORS.map(v => <option key={v.value} value={v.value}>{v.label}</option>)}
                  </select>
                </div>

                {/* IP */}
                <div>
                  <label className={labelCls}>Endereço(s) IP Seed</label>
                  <input
                    type="text" required value={ip}
                    onChange={e => setIp(e.target.value)}
                    placeholder="10.0.0.1, 10.0.0.2"
                    className={inputCls}
                  />
                  <p className="mt-1 text-xs text-slate-400">Separe múltiplos IPs por vírgula ou espaço.</p>
                </div>

                {/* Credentials */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className={labelCls}>Usuário</label>
                    <input
                      type="text" required value={username}
                      onChange={e => setUsername(e.target.value)}
                      placeholder="admin"
                      className={inputCls}
                    />
                  </div>
                  <div>
                    <label className={labelCls}>Senha</label>
                    <div className="relative">
                      <input
                        type={showPw ? 'text' : 'password'} required value={password}
                        onChange={e => setPassword(e.target.value)}
                        placeholder="••••••••"
                        className={cn(inputCls, 'pr-10')}
                      />
                      <button
                        type="button" onClick={() => setShowPw(p => !p)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
                      >
                        {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>
                </div>

                {/* Commands accordion */}
                <div className="border border-slate-200 dark:border-slate-700 rounded-xl overflow-hidden">
                  <button
                    type="button"
                    onClick={() => setShowCommands(s => !s)}
                    className="w-full flex items-center justify-between px-5 py-3.5 bg-slate-50 dark:bg-slate-800/50 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors text-sm font-semibold text-slate-600 dark:text-slate-300"
                  >
                    <span className="flex items-center gap-2">
                      <Settings className="w-4 h-4" />
                      Command Profiles — Personalizar Comandos
                    </span>
                    {showCommands ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                  </button>

                  {showCommands && (
                    <div className="p-5 border-t border-slate-200 dark:border-slate-700 grid grid-cols-1 sm:grid-cols-2 gap-4 bg-white dark:bg-slate-900 animate-in slide-in-from-top-2">
                      {([
                        { key: 'l1', label: 'Layer 1 — Física', pill: 'bg-emerald-100 dark:bg-emerald-900/40 text-emerald-700 dark:text-emerald-300' },
                        { key: 'l2', label: 'Layer 2 — Lógica', pill: 'bg-blue-100 dark:bg-blue-900/40 text-blue-700 dark:text-blue-300' },
                        { key: 'l3', label: 'Layer 3 — Roteamento', pill: 'bg-purple-100 dark:bg-purple-900/40 text-purple-700 dark:text-purple-300' },
                        { key: 'hardware', label: 'Hardware / OS', pill: 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300' },
                      ] as const).map(({ key, label, pill }) => (
                        <div key={key}>
                          <label className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-1.5">
                            <LayerPill label={label} color={pill} />
                          </label>
                          <textarea
                            rows={4}
                            value={commandText[key]}
                            onChange={e => setCommandText({ ...commandText, [key]: e.target.value })}
                            className={cn(inputCls, 'font-mono text-xs resize-none')}
                            placeholder="Um comando por linha"
                          />
                        </div>
                      ))}
                      <div className="sm:col-span-2 flex justify-end">
                        <button
                          type="button" onClick={handleSaveCommands}
                          className="text-xs font-semibold bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 px-4 py-2 rounded-lg transition-colors"
                        >
                          Salvar Perfil
                        </button>
                      </div>
                    </div>
                  )}
                </div>

                {/* Submit */}
                <button
                  type="submit"
                  disabled={loading || !ip || !username || !password}
                  className="w-full sm:w-auto bg-cyan-500 hover:bg-cyan-600 disabled:opacity-50 disabled:cursor-not-allowed text-white font-bold py-3 px-8 rounded-xl transition-all shadow-lg shadow-cyan-500/20 flex items-center justify-center gap-2"
                >
                  {loading ? (
                    <><Activity className="w-5 h-5 animate-pulse" /> Analisando rede...</>
                  ) : (
                    <><Search className="w-5 h-5" /> Iniciar Discovery</>
                  )}
                </button>
              </form>
            )}

            {/* ── UPLOAD FORM ─────────────────────────────────────── */}
            {activeTab === 'upload' && (
              <form onSubmit={handleUpload} className="space-y-6 max-w-xl">
                <div
                  onClick={() => fileInputRef.current?.click()}
                  className="border-2 border-dashed border-slate-300 dark:border-slate-700 rounded-2xl p-12 text-center hover:border-cyan-400 dark:hover:border-cyan-500 hover:bg-cyan-50/30 dark:hover:bg-cyan-900/10 transition-all cursor-pointer group"
                >
                  <div className="w-14 h-14 rounded-2xl bg-slate-100 dark:bg-slate-800 group-hover:bg-cyan-100 dark:group-hover:bg-cyan-900/30 flex items-center justify-center mx-auto mb-4 transition-colors">
                    <Server className="w-7 h-7 text-slate-400 group-hover:text-cyan-500 transition-colors" />
                  </div>
                  <p className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-1">
                    Arraste uma pasta ou clique para selecionar arquivos
                  </p>
                  <p className="text-xs text-slate-400">Pastas .txt, .log de coleta de comandos</p>

                  <input
                    type="file" multiple
                    {...{ webkitdirectory: '', directory: '' } as any}
                    ref={fileInputRef}
                    onChange={e => setFiles(e.target.files)}
                    className="hidden"
                  />
                </div>

                {files && files.length > 0 && (
                  <div className="flex items-center gap-2 text-sm font-medium text-emerald-600 dark:text-emerald-400">
                    <CheckCircle2 className="w-4 h-4" />
                    {files.length} arquivo(s) selecionado(s)
                  </div>
                )}

                <button
                  type="submit"
                  disabled={loading || !files || files.length === 0}
                  className="w-full sm:w-auto bg-cyan-500 hover:bg-cyan-600 disabled:opacity-50 disabled:cursor-not-allowed text-white font-bold py-3 px-8 rounded-xl transition-all shadow-lg shadow-cyan-500/20 flex items-center justify-center gap-2"
                >
                  {loading ? (
                    <><Layers className="w-5 h-5 animate-bounce" /> Processando...</>
                  ) : (
                    <><Layers className="w-5 h-5" /> Gerar Topologia</>
                  )}
                </button>
              </form>
            )}
          </div>
        </div>

        {/* ── RESULTS ──────────────────────────────────────────────── */}
        {resultXml && (
          <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">

            {/* Success banner */}
            <div className="bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-700/50 rounded-2xl p-6">
              <div className="flex items-start gap-4">
                <div className="w-12 h-12 rounded-xl bg-emerald-100 dark:bg-emerald-900/50 flex items-center justify-center flex-shrink-0">
                  <CheckCircle2 className="w-6 h-6 text-emerald-600 dark:text-emerald-400" />
                </div>
                <div className="flex-1">
                  <h2 className="font-black text-lg text-emerald-900 dark:text-emerald-100 mb-1">
                    Topologia Gerada com Sucesso
                  </h2>
                  <p className="text-sm text-emerald-700/70 dark:text-emerald-300/70">
                    O arquivo contém 3 páginas — L1 Física, L2 Lógica e L3 Roteamento — com swim lanes hierárquicas e ícones Cisco 19 mapeados automaticamente.
                  </p>
                </div>
              </div>
            </div>

            {/* Stats row */}
            {topology && (
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
                <StatCard icon={<Server className="w-4 h-4" />}     label="Dispositivos"   value={String(nodeCount)} />
                <StatCard icon={<GitBranch className="w-4 h-4" />}  label="Links Totais"   value={String(linkCount)} />
                <StatCard icon={<Shield className="w-4 h-4" />}     label="Links L1"       value={String(l1Count)} />
                <StatCard icon={<Network className="w-4 h-4" />}    label="Links L2"       value={String(l2Count)} />
                <StatCard icon={<Globe className="w-4 h-4" />}      label="Links L3"       value={String(l3Count)} />
              </div>
            )}

            {/* Action buttons */}
            <div className="flex flex-wrap gap-3">
              <button
                onClick={downloadDrawio}
                className="flex items-center gap-2 bg-cyan-500 hover:bg-cyan-600 text-white font-bold py-2.5 px-5 rounded-xl transition-all shadow-md shadow-cyan-500/20 text-sm"
              >
                <Download className="w-4 h-4" /> Baixar .drawio
              </button>

              {rawOutputs && (<>
                <button
                  onClick={() => setShowRawOutputs(s => !s)}
                  className="flex items-center gap-2 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 font-bold py-2.5 px-5 rounded-xl transition-colors text-sm border border-slate-200 dark:border-slate-700"
                >
                  <Terminal className="w-4 h-4" />
                  {showRawOutputs ? 'Ocultar Logs' : 'Ver Logs Brutos'}
                </button>
                <button
                  onClick={downloadRawOutputs}
                  className="flex items-center gap-2 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 font-bold py-2.5 px-5 rounded-xl transition-colors text-sm border border-slate-200 dark:border-slate-700"
                >
                  <FileText className="w-4 h-4" /> Baixar (.txt)
                </button>
                <button
                  onClick={copyToClipboard}
                  className="flex items-center gap-2 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 font-bold py-2.5 px-5 rounded-xl transition-colors text-sm border border-slate-200 dark:border-slate-700"
                >
                  <Copy className="w-4 h-4" /> Copiar Logs
                </button>
              </>)}

              <button
                onClick={handleClear}
                className="flex items-center gap-2 bg-slate-100 dark:bg-slate-800 hover:bg-red-50 dark:hover:bg-red-900/20 text-slate-500 hover:text-red-600 dark:hover:text-red-400 font-bold py-2.5 px-5 rounded-xl transition-colors text-sm border border-slate-200 dark:border-slate-700"
              >
                <XCircle className="w-4 h-4" /> Limpar
              </button>
            </div>


            {/* Raw logs terminal */}
            {showRawOutputs && rawOutputs && (
              <div className="bg-slate-950 rounded-2xl overflow-hidden border border-slate-800 shadow-2xl animate-in slide-in-from-top-4">
                <div className="bg-slate-900 px-5 py-3 border-b border-slate-800 flex items-center gap-3">
                  <div className="flex gap-1.5">
                    <div className="w-3 h-3 rounded-full bg-red-500" />
                    <div className="w-3 h-3 rounded-full bg-yellow-500" />
                    <div className="w-3 h-3 rounded-full bg-green-500" />
                  </div>
                  <span className="text-slate-400 text-xs font-mono ml-2 flex items-center gap-2">
                    <Terminal className="w-3.5 h-3.5" /> terminal — raw output
                  </span>
                </div>
                <div className="p-5 max-h-96 overflow-y-auto font-mono text-xs text-emerald-400 whitespace-pre-wrap">
                  {Object.entries(rawOutputs).map(([cmd, output], idx) => (
                    <div key={idx} className="mb-6 last:mb-0">
                      <div className="text-slate-500 select-none mb-1">$ {cmd}</div>
                      <div className="text-slate-200">{output || '<sem saída>'}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </main>

      {/* FOOTER */}
      <footer className="border-t border-slate-200 dark:border-slate-800 mt-16 py-6 text-center text-xs text-slate-400 dark:text-slate-600">
        Magneto · Network Topology Generator · L1 · L2 · L3
      </footer>
    </div>
  );
}
