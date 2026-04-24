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
type Tab    = 'discovery' | 'upload' | 'risk' | 'assessment' | 'dashboard';
type Theme  = 'light' | 'dark';

// ─────────────────────────────────────────────────────────────────────────────
// STATIC DATA
// ─────────────────────────────────────────────────────────────────────────────
const VENDORS = [
  { value: 'cisco_ios',      label: 'Cisco IOS-XE' },
  { value: 'cisco_nxos',    label: 'Cisco NX-OS' },
  { value: 'aruba_os',      label: 'HP/HPE Aruba' },
  { value: 'hpe_comware',   label: 'HPE Comware' },
  { value: 'juniper_junos', label: 'Juniper JunOS' },
  { value: 'huawei_vrp',    label: 'Huawei VRP' },
  { value: 'arista_eos',    label: 'Arista EOS' },
  { value: 'dell_os10',     label: 'Dell OS10' },
  { value: 'fortinet',      label: 'Fortinet FortiOS' },
  { value: 'paloalto',      label: 'Palo Alto PAN-OS' },
  { value: 'extreme',       label: 'Extreme Networks' },
];

// ─────────────────────────────────────────────────────────────────────────────
// SHARED INPUT STYLES
// ─────────────────────────────────────────────────────────────────────────────
const inputCls = [
  'w-full rounded-lg border border-slate-700',
  'bg-[#0d1117]',
  'px-4 py-2.5 text-sm text-slate-100',
  'focus:outline-none focus:ring-2 focus:ring-cyan-500',
  'focus:border-transparent transition-all placeholder:text-slate-600',
].join(' ');

const labelCls = 'block text-xs font-semibold tracking-widest uppercase text-slate-500 mb-1.5';

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
    <div className="flex items-center gap-3 bg-slate-800/60 rounded-xl px-4 py-3 border border-slate-700">
      <div className="text-cyan-400">{icon}</div>
      <div>
        <p className="text-xs text-slate-500 font-medium">{label}</p>
        <p className="text-sm font-bold text-slate-100">{value}</p>
      </div>
    </div>
  );
}

function SectionTitle({ icon, children }: { icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <h3 className="flex items-center gap-2 text-xs font-bold tracking-widest uppercase text-cyan-400 mb-4">
      <span>{icon}</span>
      {children}
    </h3>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// RISK ASSESSMENT PANEL — professional redesign
// ─────────────────────────────────────────────────────────────────────────────
interface RiskItem { status: string; item: string; risco?: string; obs?: string; }
interface DeviceResult {
  hostname: string; ip: string; vendor: string; model: string;
  osVersion: string; items: RiskItem[];
}

// ── Vendor badge pill ────────────────────────────────────────────────────────
function VendorPill({ vendor }: { vendor: string }) {
  const map: Record<string, [string, string]> = {
    cisco_ios:   ['IOS',     'bg-blue-900/50 text-blue-300 border-blue-700'],
    cisco_nxos:  ['NX-OS',   'bg-blue-900/50 text-blue-300 border-blue-700'],
    dell_os10:   ['OS10',    'bg-cyan-900/50 text-cyan-300 border-cyan-700'],
    hpe_comware: ['Comware', 'bg-indigo-900/50 text-indigo-300 border-indigo-700'],
    huawei_vrp:  ['VRP',     'bg-rose-900/50 text-rose-300 border-rose-700'],
  };
  const VNAME: Record<string, string> = {
    cisco_ios: 'Cisco', cisco_nxos: 'Cisco', dell_os10: 'Dell',
    hpe_comware: 'HP',  huawei_vrp: 'Huawei',
  };
  const [os, cls] = map[vendor] ?? ['?', 'bg-slate-800 text-slate-400 border-slate-700'];
  return (
    <span className={cn('inline-flex items-center gap-1 text-xs font-bold px-2 py-0.5 rounded border', cls)}>
      {VNAME[vendor] ?? vendor} <span className="opacity-60 font-normal">{os}</span>
    </span>
  );
}

// ── Risco icon ────────────────────────────────────────────────────────────────
function RiscoIcon({ risco }: { risco?: string }) {
  const r = risco || '';
  if (r.includes('✕') || /ALTO/i.test(r))   return <span className="text-red-400 text-sm font-black">✕</span>;
  if (r.includes('⚠') || /MÉDIA/i.test(r))  return <span className="text-amber-400 text-sm">⚠</span>;
  if (r.includes('✔') || /BAIXA/i.test(r))  return <span className="text-emerald-400 text-sm">✔</span>;
  return <span className="text-slate-500 text-xs">N/A</span>;
}

// ── Status badge ──────────────────────────────────────────────────────────────
function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    'SIM':     'bg-emerald-500/20 text-emerald-400 border-emerald-500/40',
    'NÃO':    'bg-red-500/20 text-red-400 border-red-500/40',
    'PARCIAL': 'bg-amber-500/20 text-amber-400 border-amber-500/40',
    'N/A':     'bg-slate-700/40 text-slate-500 border-slate-600/40',
    'N/D':     'bg-slate-700/40 text-slate-500 border-slate-600/40',
  };
  return (
    <span className={cn('inline-block text-xs font-bold px-2.5 py-0.5 rounded border', map[status] ?? map['N/A'])}>
      {status}
    </span>
  );
}

// ── Conformidade badge ────────────────────────────────────────────────────────
function ConformBadge({ pct }: { pct: number }) {
  const cls = pct >= 80 ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
            : pct >= 50 ? 'bg-amber-500/20 text-amber-400 border-amber-500/40'
                        : 'bg-red-500/20 text-red-400 border-red-500/40';
  return (
    <span className={cn('inline-block text-xs font-black px-2.5 py-0.5 rounded border', cls)}>
      {pct}%
    </span>
  );
}

// ── Collapsible section header (Matriz) ──────────────────────────────────────
function SectionRow({
  label, open, onToggle, count,
}: { label: string; open: boolean; onToggle: () => void; count: number }) {
  return (
    <tr
      onClick={onToggle}
      className="cursor-pointer select-none group"
    >
      <td colSpan={4} className="py-0">
        <div className="flex items-center justify-between px-4 py-2.5 bg-gradient-to-r from-purple-900/60 to-slate-900/40 border-y border-purple-800/50 group-hover:from-purple-900/80 transition-colors">
          <span className="text-xs font-bold uppercase tracking-widest text-purple-300 flex items-center gap-2">
            <span className={cn('inline-block w-3.5 h-3.5 text-center leading-none text-purple-400 transition-transform duration-200', open ? 'rotate-90' : '')}>▶</span>
            {label}
          </span>
          <span className="text-xs text-slate-500 flex items-center gap-2">
            <span className="bg-purple-800/50 text-purple-300 px-2 py-0.5 rounded-full text-xs font-semibold">{count} itens</span>
            <span className="text-purple-400 text-xs">{open ? 'Minimizar' : 'Expandir'}</span>
          </span>
        </div>
      </td>
    </tr>
  );
}

function RiskAssessmentPanel({
  defaultView = 'matrix',
  sharedDevices, setSharedDevices,
  sharedView, setSharedView,
  sharedActiveDevice, setSharedActiveDevice,
}: {
  defaultView?: 'matrix' | 'assessment';
  sharedDevices: DeviceResult[];
  setSharedDevices: (d: DeviceResult[]) => void;
  sharedView: 'upload' | 'assessment' | 'detail';
  setSharedView: (v: 'upload' | 'assessment' | 'detail') => void;
  sharedActiveDevice: number;
  setSharedActiveDevice: (i: number) => void;
}) {
  const riskFileRef = useRef<HTMLInputElement>(null);
  const [riskFiles,   setRiskFiles]   = useState<FileList | null>(null);
  const [riskLoading, setRiskLoading] = useState(false);
  const [exporting,   setExporting]   = useState(false);
  const [errorMsg,    setErrorMsg]    = useState<string | null>(null);
  const [filter,      setFilter]      = useState<'all' | 'NÃO' | 'PARCIAL' | 'SIM'>('all');
  const [collapsedSections, setCollapsedSections] = useState<Record<string, boolean>>({});

  // Use shared state
  const riskDevices   = sharedDevices;
  const view          = sharedView;
  const activeDevice  = sharedActiveDevice;
  const setView       = setSharedView;
  const setActiveDevice = setSharedActiveDevice;

  function clearHistory() {
    setSharedDevices([]);
    setSharedView('upload');
    setSharedActiveDevice(0);
    setRiskFiles(null);
    setFilter('all');
    setCollapsedSections({});
    setErrorMsg(null);
    if (riskFileRef.current) riskFileRef.current.value = '';
  }

  const VENDOR_LABEL: Record<string, string> = {
    cisco_ios: 'Cisco IOS', cisco_nxos: 'Cisco NX-OS', dell_os10: 'Dell OS10',
    hpe_comware: 'HP Comware', huawei_vrp: 'Huawei VRP',
  };

  async function handleRiskUpload() {
    if (!riskFiles?.length) return;
    setRiskLoading(true); setErrorMsg(null);
    try {
      const fd = new FormData();
      Array.from(riskFiles as FileList).forEach(f => fd.append('logs', f as File, (f as File).name));
      const res = await fetch('/api/risk-upload', { method: 'POST', body: fd });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? 'Erro no servidor');
      setSharedDevices(data.devices ?? []);
      setSharedActiveDevice(0);
      setFilter('all');
      setCollapsedSections({});
      // Matriz de Riscos: vai direto para o detalhe do primeiro dispositivo
      // Assessment Network: vai para o dashboard consolidado
      setView(defaultView === 'assessment' ? 'assessment' : 'detail');
    } catch (e: any) {
      setErrorMsg(e.message);
    } finally {
      setRiskLoading(false);
    }
  }

  async function handleExportExcel() {
    if (!riskDevices.length) return;
    setExporting(true);
    try {
      const endpoint = defaultView === 'assessment' ? '/api/assessment-excel' : '/api/risk-excel';
      const filename = defaultView === 'assessment'
        ? `Assessment_${new Date().toISOString().slice(0,10)}.xlsx`
        : `Matriz_Riscos_${new Date().toISOString().slice(0,10)}.xlsx`;
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ devices: riskDevices, label: 'Magneto NTG' }),
      });
      if (!res.ok) {
        let msg = 'Erro ao gerar Excel';
        try { const j = await res.json(); msg = j.error || msg; } catch {}
        throw new Error(msg);
      }
      const blob = await res.blob();
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement('a');
      a.href = url; a.download = filename; a.click();
      URL.revokeObjectURL(url);
    } catch (e: any) {
      setErrorMsg(e.message);
    } finally {
      setExporting(false);
    }
  }

  // Computed stats
  const dev = riskDevices[activeDevice];
  const dataItems = dev?.items.filter(i => i.status !== 'SECTION') ?? [];
  const stats = {
    total:   dataItems.length,
    sim:     dataItems.filter(i => i.status === 'SIM').length,
    nao:     dataItems.filter(i => i.status === 'NÃO').length,
    parcial: dataItems.filter(i => i.status === 'PARCIAL').length,
    altos:   dataItems.filter(i => (i.risco ?? '').includes('✕')).length,
    pct:     dataItems.length > 0 ? Math.round(dataItems.filter(i => i.status === 'SIM').length / dataItems.length * 100) : 0,
  };

  const assessRows = riskDevices.map(d => {
    const it = d.items.filter(i => i.status !== 'SECTION');
    const sim = it.filter(i => i.status === 'SIM').length;
    const tot = it.length;
    return { ...d, tot, sim, nao: it.filter(i => i.status === 'NÃO').length,
             par: it.filter(i => i.status === 'PARCIAL').length,
             alt: it.filter(i => (i.risco ?? '').includes('✕')).length,
             pct: tot > 0 ? Math.round(sim / tot * 100) : 0 };
  });

  // Grand totals
  const gt = assessRows.reduce((a,r) => ({ tot:a.tot+r.tot, sim:a.sim+r.sim, nao:a.nao+r.nao, par:a.par+r.par, alt:a.alt+r.alt }), {tot:0,sim:0,nao:0,par:0,alt:0});
  const gPct = gt.tot > 0 ? Math.round(gt.sim/gt.tot*100) : 0;

  // Section-grouped items for collapsible matriz
  const sections = (() => {
    const result: { label: string; items: RiskItem[] }[] = [];
    let cur: { label: string; items: RiskItem[] } | null = null;
    for (const item of (dev?.items ?? [])) {
      if (item.status === 'SECTION') {
        cur = { label: item.item, items: [] };
        result.push(cur);
      } else if (cur) {
        cur.items.push(item);
      }
    }
    return result;
  })();

  const visibleItems = sections.flatMap(s =>
    filter === 'all' ? s.items : s.items.filter(i => i.status === filter)
  );

  // ── UPLOAD SCREEN ─────────────────────────────────────────────────────────
  const uploadScreen = (
    <div className="space-y-5">
      <SectionTitle icon={<Shield className="w-4 h-4" />}>
        {defaultView === 'assessment' ? 'Assessment Network' : 'Matriz de Riscos'}
      </SectionTitle>
      <div
        onClick={() => riskFileRef.current?.click()}
        className="border-2 border-dashed border-slate-700 rounded-2xl p-14 text-center hover:border-purple-500 hover:bg-purple-900/10 transition-all cursor-pointer group"
      >
        <div className="w-14 h-14 rounded-2xl bg-slate-800 group-hover:bg-purple-900/40 flex items-center justify-center mx-auto mb-5 transition-colors">
          <Shield className="w-7 h-7 text-slate-400 group-hover:text-purple-400 transition-colors" />
        </div>
        <p className="text-sm font-semibold text-slate-300 mb-1">Arraste uma pasta ou clique para selecionar arquivos</p>
        <p className="text-xs text-slate-500">Pastas .txt, .log de coleta de comandos</p>
        <input type="file" multiple ref={riskFileRef}
          {...{ webkitdirectory: '', directory: '' } as any}
          onChange={e => setRiskFiles(e.target.files)} className="hidden" />
      </div>
      {riskFiles && riskFiles.length > 0 && (
        <p className="text-sm text-emerald-400 font-medium flex items-center gap-1.5">
          <CheckCircle2 className="w-4 h-4" /> {riskFiles.length} arquivo(s) selecionado(s)
        </p>
      )}
      {errorMsg && (
        <div className="flex items-center gap-2 text-sm text-red-400 bg-red-900/20 border border-red-800 rounded-xl p-3">
          <AlertCircle className="w-4 h-4 flex-shrink-0" /> {errorMsg}
        </div>
      )}
      <div className="flex gap-3 flex-wrap items-center">
        <button onClick={handleRiskUpload} disabled={riskLoading || !riskFiles?.length}
          className="bg-purple-600 hover:bg-purple-700 disabled:opacity-40 disabled:cursor-not-allowed text-white font-bold py-3 px-8 rounded-xl flex items-center gap-2 transition-all text-sm">
          {riskLoading ? <><Activity className="w-5 h-5 animate-pulse" /> Analisando...</>
                       : <><Shield className="w-5 h-5" /> {defaultView === 'assessment' ? 'Analisar Assessment' : 'Analisar Riscos'}</>}
        </button>
        {riskDevices.length > 0 && (
          <>
            <button onClick={() => setView(defaultView === 'assessment' ? 'assessment' : 'detail')}
              className="bg-slate-700 hover:bg-slate-600 text-white font-bold py-3 px-5 rounded-xl flex items-center gap-2 transition-all text-sm border border-slate-600">
              <Activity className="w-4 h-4" /> Ver Resultados
              <span className="bg-purple-700 text-purple-200 text-xs px-2 py-0.5 rounded-full font-semibold">{riskDevices.length}</span>
            </button>
            <button onClick={handleExportExcel} disabled={exporting}
              className="bg-emerald-700 hover:bg-emerald-600 disabled:opacity-40 text-white font-bold py-3 px-5 rounded-xl flex items-center gap-2 transition-all text-sm">
              {exporting ? <><Activity className="w-4 h-4 animate-pulse" /> Gerando...</> : <><Download className="w-4 h-4" /> Exportar Excel</>}
            </button>
            <button onClick={clearHistory}
              className="text-red-400 hover:text-red-300 bg-red-900/20 hover:bg-red-900/40 font-bold py-3 px-4 rounded-xl flex items-center gap-2 transition-all text-sm border border-red-800/50"
              title="Limpar histórico">
              <XCircle className="w-4 h-4" /> Limpar Histórico
            </button>
          </>
        )}
      </div>
    </div>
  );

  // ── ASSESSMENT DASHBOARD ──────────────────────────────────────────────────
  const assessmentScreen = (
    <div className="space-y-5 animate-in fade-in duration-300">
      {/* Header row */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <button onClick={() => setView('upload')}
            className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors bg-slate-800 hover:bg-slate-700 px-3 py-1.5 rounded-lg border border-slate-700">
            ← Voltar
          </button>
          <SectionTitle icon={<Activity className="w-4 h-4" />}>
            Assessment Network — Visão Consolidada
          </SectionTitle>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={clearHistory}
              className="text-xs text-red-400 hover:text-red-300 bg-red-900/20 hover:bg-red-900/40 px-3 py-1.5 rounded-lg border border-red-800/50 flex items-center gap-1.5 transition-all"
              title="Limpar histórico">
              <XCircle className="w-3.5 h-3.5" /> Limpar
            </button>
          <button onClick={() => setView('upload')}
            className="text-xs text-purple-400 hover:text-purple-300 bg-purple-900/20 hover:bg-purple-900/40 px-3 py-1.5 rounded-lg border border-purple-800/50 flex items-center gap-1.5 transition-all">
            <Upload className="w-3.5 h-3.5" /> Novo Upload
          </button>
          <button onClick={handleExportExcel} disabled={exporting}
            className="text-xs text-emerald-400 hover:text-emerald-300 bg-emerald-900/20 hover:bg-emerald-900/40 px-3 py-1.5 rounded-lg border border-emerald-800/50 flex items-center gap-1.5 transition-all disabled:opacity-40">
            <Download className="w-3.5 h-3.5" /> {exporting ? 'Gerando...' : 'Exportar Excel'}
          </button>
        </div>
      </div>

      {/* Assessment KPI — network health summary, distinct from Matriz */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {[
          { label: 'Dispositivos', value: riskDevices.length, sub: 'analisados',    color: 'text-purple-400',  ring: 'ring-purple-700/60',  bg: 'bg-purple-900/20' },
          { label: 'Itens',        value: gt.tot,  sub: 'verificados',   color: 'text-slate-200',   ring: 'ring-slate-700/60',   bg: 'bg-slate-800/40' },
          { label: 'SIM',          value: gt.sim,  sub: 'conformes',     color: 'text-emerald-400', ring: 'ring-emerald-700/60', bg: 'bg-emerald-900/20' },
          { label: 'NÃO',         value: gt.nao,  sub: 'não conformes', color: 'text-red-400',     ring: 'ring-red-700/60',     bg: 'bg-red-900/20' },
          { label: 'Parcial',      value: gt.par,  sub: 'pendentes',     color: 'text-amber-400',   ring: 'ring-amber-700/60',   bg: 'bg-amber-900/20' },
          { label: `${gPct}%`, value: '', sub: 'conformidade',   color: gPct>=80?'text-emerald-400':gPct>=50?'text-amber-400':'text-red-400',
            ring: gPct>=80?'ring-emerald-700/60':gPct>=50?'ring-amber-700/60':'ring-red-700/60',
            bg: gPct>=80?'bg-emerald-900/20':gPct>=50?'bg-amber-900/20':'bg-red-900/20' },
        ].map((s, i) => (
          <div key={i} className={cn('rounded-xl p-4 ring-1 text-center flex flex-col items-center justify-center gap-0.5', s.bg, s.ring)}>
            <p className={cn('text-3xl font-black', s.color)}>{s.value || s.label}</p>
            {s.value !== '' && <p className={cn('text-sm font-bold', s.color)}>{s.label}</p>}
            <p className="text-xs text-slate-600 font-medium">{s.sub}</p>
          </div>
        ))}
      </div>

      {/* Network health bar */}
      <div className="rounded-xl border border-slate-800 bg-slate-800/40 px-5 py-3 flex items-center gap-4">
        <span className="text-xs text-slate-500 font-semibold flex-shrink-0">SAÚDE DA REDE</span>
        <div className="flex-1 flex h-2.5 rounded-full overflow-hidden gap-px bg-slate-700/30">
          {gt.tot > 0 && <>
            <div className="bg-emerald-500 h-full transition-all" style={{ width: `${Math.round(gt.sim/gt.tot*100)}%` }} />
            <div className="bg-amber-500 h-full transition-all"   style={{ width: `${Math.round(gt.par/gt.tot*100)}%` }} />
            <div className="bg-red-500 h-full transition-all"     style={{ width: `${Math.round(gt.nao/gt.tot*100)}%` }} />
          </>}
        </div>
        <div className="flex items-center gap-3 text-xs flex-shrink-0">
          <span className="flex items-center gap-1 text-emerald-400"><span className="w-2 h-2 rounded-full bg-emerald-500 inline-block" /> {gt.tot>0?Math.round(gt.sim/gt.tot*100):0}% OK</span>
          <span className="flex items-center gap-1 text-amber-400"><span className="w-2 h-2 rounded-full bg-amber-500 inline-block" /> {gt.tot>0?Math.round(gt.par/gt.tot*100):0}% Parcial</span>
          <span className="flex items-center gap-1 text-red-400"><span className="w-2 h-2 rounded-full bg-red-500 inline-block" /> {gt.tot>0?Math.round(gt.nao/gt.tot*100):0}% Crítico</span>
        </div>
      </div>

      {/* Device table */}
      <div className="rounded-xl border border-slate-800 overflow-hidden">
        {/* Table header */}
        <div className="bg-slate-800/80 grid grid-cols-[2fr_1fr_1.2fr_0.7fr_0.7fr_0.7fr_0.7fr_0.7fr_0.9fr_0.6fr] gap-0 px-4 py-2.5">
          {['DISPOSITIVO','IP','VENDOR','TOTAL','SIM','NÃO','PARCIAL','RISCOS 🔴','CONFORM.','VER'].map((h,i) => (
            <span key={h} className={cn('text-xs font-bold uppercase tracking-wide text-slate-500', i >= 3 ? 'text-center' : '')}>{h}</span>
          ))}
        </div>

        <div className="divide-y divide-slate-800/70">
          {assessRows.map((row, i) => (
            <div key={i} className={cn(
              'grid grid-cols-[2fr_1fr_1.2fr_0.7fr_0.7fr_0.7fr_0.7fr_0.7fr_0.9fr_0.6fr] gap-0 px-4 py-3 items-center transition-colors',
              'hover:bg-purple-900/10',
              i % 2 === 0 ? 'bg-slate-900/60' : 'bg-slate-900/30'
            )}>
              {/* Hostname + model */}
              <div className="min-w-0">
                <p className="text-xs font-bold text-slate-200 font-mono truncate">{row.hostname || '—'}</p>
                {row.model && <p className="text-xs text-slate-500 truncate mt-0.5">{row.model}</p>}
              </div>
              {/* IP */}
              <span className="text-xs text-slate-500 font-mono">{row.ip || '—'}</span>
              {/* Vendor */}
              <div><VendorPill vendor={row.vendor} /></div>
              {/* Numbers */}
              <span className="text-xs font-bold text-slate-300 text-center">{row.tot}</span>
              <span className="text-xs font-bold text-emerald-400 text-center">{row.sim}</span>
              <span className="text-xs font-bold text-red-400 text-center">{row.nao}</span>
              <span className="text-xs font-bold text-amber-400 text-center">{row.par}</span>
              <span className="text-xs font-bold text-red-400 text-center">{row.alt}</span>
              <div className="text-center"><ConformBadge pct={row.pct} /></div>
              {/* Detail button */}
              <div className="text-center">
                <button
                  onClick={() => { setActiveDevice(i); setFilter('all'); setCollapsedSections({}); setView('detail'); }}
                  className="text-xs text-purple-400 hover:text-purple-200 bg-purple-900/20 hover:bg-purple-900/50 px-2.5 py-1 rounded-lg border border-purple-800/50 transition-all font-semibold">
                  Detalhe
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );

  // ── DETAIL SCREEN (Matriz per device) ────────────────────────────────────
  const detailScreen = dev && (
    <div className="space-y-5 animate-in fade-in duration-300">
      {/* Back + header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          {/* Assessment tab: back to consolidated table | Matriz tab: back to upload */}
          {defaultView === 'assessment' ? (
            <button onClick={() => setView('assessment')}
              className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors bg-slate-800 hover:bg-slate-700 px-3 py-1.5 rounded-lg border border-slate-700">
              ← Voltar ao Assessment
            </button>
          ) : (
            <button onClick={() => setView('upload')}
              className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors bg-slate-800 hover:bg-slate-700 px-3 py-1.5 rounded-lg border border-slate-700">
              ← Novo Upload
            </button>
          )}
          <SectionTitle icon={<Shield className="w-4 h-4" />}>Matriz de Riscos</SectionTitle>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={clearHistory}
            className="text-xs text-red-400 hover:text-red-300 bg-red-900/20 hover:bg-red-900/40 px-3 py-1.5 rounded-lg border border-red-800/50 flex items-center gap-1.5 transition-all">
            <XCircle className="w-3.5 h-3.5" /> Limpar
          </button>
          <button onClick={handleExportExcel} disabled={exporting}
            className="text-xs text-emerald-400 bg-emerald-900/20 hover:bg-emerald-900/40 px-3 py-1.5 rounded-lg border border-emerald-800/50 flex items-center gap-1.5 transition-all disabled:opacity-40">
            <Download className="w-3.5 h-3.5" /> {exporting ? 'Gerando...' : 'Exportar Excel'}
          </button>
        </div>
      </div>

      {/* Device info card — Matriz style */}
      <div className="rounded-xl border border-slate-700/80 bg-slate-800/60 px-5 py-3.5 flex flex-wrap items-center gap-4">
        <div className="flex-1 min-w-0">
          <p className="text-sm font-black text-slate-100 font-mono truncate">{dev.hostname}</p>
          {dev.model && <p className="text-xs text-slate-500 mt-0.5 truncate">{dev.model}</p>}
        </div>
        <VendorPill vendor={dev.vendor} />
        {dev.ip && <span className="text-xs text-slate-400 font-mono bg-slate-700/50 px-2 py-0.5 rounded">📍 {dev.ip}</span>}
        {(dev as any).osVersion && <span className="text-xs text-slate-500 bg-slate-700/50 px-2 py-0.5 rounded">📦 {(dev as any).osVersion}</span>}
      </div>

      {/* Matriz KPI — horizontal bar style, different from Assessment cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {/* Conformidade — big featured card */}
        <div className={cn(
          'sm:col-span-1 rounded-xl border bg-gradient-to-br p-4 flex flex-col items-center justify-center text-center',
          stats.pct>=80 ? 'from-emerald-900/40 to-emerald-900/10 border-emerald-700/50'
          : stats.pct>=50 ? 'from-amber-900/40 to-amber-900/10 border-amber-700/50'
          :                  'from-red-900/40 to-red-900/10 border-red-700/50'
        )}>
          <p className={cn('text-4xl font-black', stats.pct>=80?'text-emerald-400':stats.pct>=50?'text-amber-400':'text-red-400')}>
            {stats.pct}%
          </p>
          <p className="text-xs text-slate-400 mt-1 font-semibold">Conformidade</p>
          <p className="text-xs text-slate-600 mt-0.5">{stats.sim}/{stats.total} itens</p>
        </div>

        {/* Status breakdown */}
        <div className="sm:col-span-3 rounded-xl border border-slate-700/50 bg-slate-800/40 p-4 flex flex-col justify-center gap-2">
          {[
            { label: 'Conformes (SIM)',       val: stats.sim,     tot: stats.total, color: 'bg-emerald-500', tc: 'text-emerald-400' },
            { label: 'Não Conformes (NÃO)',  val: stats.nao,     tot: stats.total, color: 'bg-red-500',     tc: 'text-red-400' },
            { label: 'Parciais',              val: stats.parcial, tot: stats.total, color: 'bg-amber-500',   tc: 'text-amber-400' },
          ].map(bar => (
            <div key={bar.label} className="flex items-center gap-3">
              <span className="text-xs text-slate-500 w-40 flex-shrink-0">{bar.label}</span>
              <div className="flex-1 h-2 bg-slate-700/60 rounded-full overflow-hidden">
                <div className={cn('h-full rounded-full transition-all', bar.color)}
                  style={{ width: bar.tot > 0 ? `${Math.round(bar.val/bar.tot*100)}%` : '0%' }} />
              </div>
              <span className={cn('text-xs font-bold w-8 text-right', bar.tc)}>{bar.val}</span>
            </div>
          ))}
          {stats.altos > 0 && (
            <div className="flex items-center gap-2 mt-1 pt-2 border-t border-slate-700/50">
              <span className="text-xs text-red-400 font-bold">⚠ {stats.altos} risco(s) ALTO</span>
            </div>
          )}
        </div>
      </div>

      {/* Device selector tabs (if multiple) */}
      {riskDevices.length > 1 && (
        <div className="flex gap-2 flex-wrap">
          {riskDevices.map((d, i) => (
            <button key={i}
              onClick={() => { setActiveDevice(i); setFilter('all'); setCollapsedSections({}); }}
              className={cn(
                'px-3 py-1.5 rounded-lg text-xs font-bold transition-all border',
                i === activeDevice
                  ? 'bg-purple-700 text-white border-purple-600 shadow-lg shadow-purple-900/40'
                  : 'bg-slate-800/60 text-slate-400 border-slate-700 hover:border-purple-700 hover:text-purple-300'
              )}>
              {d.hostname || `Device ${i+1}`} <VendorPill vendor={d.vendor} />
            </button>
          ))}
        </div>
      )}

      {/* Filter tabs */}
      <div className="flex gap-2 flex-wrap items-center">
        <span className="text-xs text-slate-600 font-semibold uppercase tracking-wide">Filtrar:</span>
        {(['all','NÃO','PARCIAL','SIM'] as const).map(f => {
          const count = f === 'all' ? stats.total : f === 'NÃO' ? stats.nao : f === 'PARCIAL' ? stats.parcial : stats.sim;
          return (
            <button key={f} onClick={() => setFilter(f)}
              className={cn('px-3 py-1 rounded-lg text-xs font-bold transition-all border',
                filter === f
                  ? f==='all'    ? 'bg-slate-200 text-slate-900 border-slate-200'
                  : f==='NÃO'  ? 'bg-red-600 text-white border-red-600'
                  : f==='PARCIAL'? 'bg-amber-500 text-white border-amber-500'
                  :               'bg-emerald-600 text-white border-emerald-600'
                  : 'bg-transparent text-slate-500 border-slate-700 hover:border-slate-500 hover:text-slate-300')}>
              {f === 'all' ? 'Todos' : f} <span className="opacity-60 ml-1">({count})</span>
            </button>
          );
        })}
        {/* Collapse/expand all */}
        <div className="ml-auto flex gap-2">
          <button onClick={() => {
            const all: Record<string, boolean> = {};
            sections.forEach(s => { all[s.label] = true; });
            setCollapsedSections(all);
          }} className="text-xs text-slate-500 hover:text-slate-300 bg-slate-800/60 px-3 py-1 rounded-lg border border-slate-700 flex items-center gap-1.5 transition-colors">
            ▾ Minimizar todas
          </button>
          <button onClick={() => setCollapsedSections({})}
            className="text-xs text-slate-500 hover:text-slate-300 bg-slate-800/60 px-3 py-1 rounded-lg border border-slate-700 flex items-center gap-1.5 transition-colors">
            ▸ Expandir todas
          </button>
        </div>
      </div>

      {/* Table with collapsible sections */}
      <div className="rounded-xl border border-slate-800 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-slate-800/90 text-xs font-bold uppercase tracking-wide text-slate-500">
              <th className="py-3 px-4 text-left">Item</th>
              <th className="py-3 px-3 text-center w-28">Status</th>
              <th className="py-3 px-3 text-center w-16">Risco</th>
              <th className="py-3 px-4 text-left">Observação</th>
            </tr>
          </thead>
          <tbody>
            {sections.map((section) => {
              const isOpen = !collapsedSections[section.label];
              const filteredItems = filter === 'all' ? section.items : section.items.filter(i => i.status === filter);
              if (filteredItems.length === 0 && filter !== 'all') return null;
              return (
                <React.Fragment key={section.label}>
                  <SectionRow
                    label={section.label}
                    open={isOpen}
                    count={section.items.length}
                    onToggle={() => setCollapsedSections(prev => ({
                      ...prev, [section.label]: !prev[section.label]
                    }))}
                  />
                  {isOpen && filteredItems.map((item, idx) => (
                    <tr key={idx} className={cn(
                      'border-b border-slate-800/60 transition-colors',
                      idx % 2 === 0 ? 'bg-slate-900/70' : 'bg-slate-900/40'
                    )}>
                      <td className="py-2.5 px-4 text-xs text-slate-300 font-mono">{item.item}</td>
                      <td className="py-2.5 px-3 text-center"><StatusBadge status={item.status} /></td>
                      <td className="py-2.5 px-3 text-center"><RiscoIcon risco={item.risco} /></td>
                      <td className="py-2.5 px-4 text-xs text-slate-500 leading-relaxed max-w-sm">{item.obs}</td>
                    </tr>
                  ))}
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );

  return (
    <div>
      {view === 'upload'     && uploadScreen}
      {view === 'assessment' && assessmentScreen}
      {view === 'detail'     && (detailScreen ?? uploadScreen)}
    </div>
  );
}


// ─────────────────────────────────────────────────────────────────────────────
// EXECUTIVE DASHBOARD — visão completa Matriz + Assessment
// ─────────────────────────────────────────────────────────────────────────────
function ExecutiveDashboard({
  devices,
  onClear,
  onGoToMatriz,
  onGoToAssessment,
  onBack,
}: {
  devices: DeviceResult[];
  onClear: () => void;
  onGoToMatriz: (idx: number) => void;
  onGoToAssessment: () => void;
  onBack: () => void;
}) {
  const VENDOR_LABEL: Record<string, string> = {
    cisco_ios: 'Cisco IOS', cisco_nxos: 'Cisco NX-OS', dell_os10: 'Dell OS10',
    hpe_comware: 'HP Comware', huawei_vrp: 'Huawei VRP',
  };

  if (!devices.length) {
    return (
      <div className="flex flex-col items-center justify-center py-24 gap-4 text-center">
        <Monitor className="w-16 h-16 text-slate-700" />
        <p className="text-slate-400 font-semibold text-lg">Nenhum dado disponível</p>
        <p className="text-slate-600 text-sm max-w-sm">
          Carregue logs nas abas <span className="text-purple-400 font-semibold">Matriz de Riscos</span> ou{' '}
          <span className="text-cyan-400 font-semibold">Assessment Network</span> para ver o dashboard.
        </p>
        <button onClick={onBack}
          className="mt-2 flex items-center gap-2 text-sm text-slate-400 hover:text-slate-200 bg-slate-800 hover:bg-slate-700 px-4 py-2 rounded-xl border border-slate-700 transition-all">
          ← Voltar para tela inicial
        </button>
      </div>
    );
  }

  // ── Compute all aggregates ────────────────────────────────────────────────
  const rows = devices.map(d => {
    const it      = d.items.filter(i => i.status !== 'SECTION');
    const sim     = it.filter(i => i.status === 'SIM').length;
    const nao     = it.filter(i => i.status === 'NÃO').length;
    const parcial = it.filter(i => i.status === 'PARCIAL').length;
    const altos   = it.filter(i => (i.risco ?? '').includes('✕')).length;
    const medios  = it.filter(i => (i.risco ?? '').includes('⚠')).length;
    const tot     = it.length;
    const pct     = tot > 0 ? Math.round(sim / tot * 100) : 0;
    return { ...d, sim, nao, parcial, altos, medios, tot, pct, it };
  });

  const gt = rows.reduce((a, r) => ({
    tot: a.tot+r.tot, sim: a.sim+r.sim, nao: a.nao+r.nao,
    par: a.par+r.parcial, alt: a.alt+r.altos, med: a.med+r.medios,
  }), { tot:0, sim:0, nao:0, par:0, alt:0, med:0 });
  const gPct = gt.tot > 0 ? Math.round(gt.sim / gt.tot * 100) : 0;

  // Vendor breakdown
  const vendorCount: Record<string, number> = {};
  rows.forEach(r => { vendorCount[r.vendor] = (vendorCount[r.vendor]||0) + 1; });

  // Top offenders (worst pct first)
  const topOffenders = [...rows].sort((a,b) => a.pct - b.pct).slice(0, 5);
  // Top compliant
  const topCompliant = [...rows].sort((a,b) => b.pct - a.pct).slice(0, 5);
  // Devices with high risk
  const highRisk = rows.filter(r => r.altos > 0).sort((a,b) => b.altos - a.altos);

  // Section breakdown across all devices
  const sectionStats: Record<string, { sim:number; nao:number; par:number; tot:number }> = {};
  for (const d of devices) {
    let cur = '';
    for (const item of d.items) {
      if (item.status === 'SECTION') { cur = item.item; continue; }
      if (!cur) continue;
      if (!sectionStats[cur]) sectionStats[cur] = { sim:0, nao:0, par:0, tot:0 };
      sectionStats[cur].tot++;
      if (item.status === 'SIM')     sectionStats[cur].sim++;
      if (item.status === 'NÃO')    sectionStats[cur].nao++;
      if (item.status === 'PARCIAL') sectionStats[cur].par++;
    }
  }
  const sectionList = Object.entries(sectionStats)
    .map(([label, s]) => ({ label, ...s, pct: s.tot>0?Math.round(s.sim/s.tot*100):0 }))
    .sort((a,b) => a.pct - b.pct);

  const healthColor = gPct >= 80 ? 'text-emerald-400' : gPct >= 50 ? 'text-amber-400' : 'text-red-400';
  const healthBg    = gPct >= 80 ? 'from-emerald-900/40 to-emerald-900/10 border-emerald-700/50'
                    : gPct >= 50 ? 'from-amber-900/40 to-amber-900/10 border-amber-700/50'
                                 : 'from-red-900/40 to-red-900/10 border-red-700/50';

  return (
    <div className="space-y-6 animate-in fade-in duration-300">

      {/* ── Header ─────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <button onClick={onBack}
            className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 bg-slate-800 hover:bg-slate-700 px-3 py-1.5 rounded-lg border border-slate-700 transition-all">
            ← Voltar
          </button>
          <div>
            <h2 className="text-xs font-bold uppercase tracking-widest text-cyan-400 flex items-center gap-2">
              <Monitor className="w-4 h-4" /> Dashboard Executivo
            </h2>
            <p className="text-slate-500 text-xs mt-0.5">
              {devices.length} dispositivos · {new Date().toLocaleDateString('pt-BR', { day:'2-digit', month:'long', year:'numeric' })}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={onGoToAssessment}
            className="text-xs text-purple-400 bg-purple-900/20 hover:bg-purple-900/40 px-3 py-1.5 rounded-lg border border-purple-800/50 flex items-center gap-1.5 transition-all">
            <Activity className="w-3.5 h-3.5" /> Ver Assessment
          </button>
          <button onClick={onClear}
            className="text-xs text-red-400 bg-red-900/20 hover:bg-red-900/40 px-3 py-1.5 rounded-lg border border-red-800/50 flex items-center gap-1.5 transition-all">
            <XCircle className="w-3.5 h-3.5" /> Limpar
          </button>
        </div>
      </div>

      {/* ── Row 1: KPI macro ───────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
        {/* Health score — featured */}
        <div className={cn('lg:col-span-2 rounded-2xl border bg-gradient-to-br p-5 flex flex-col items-center justify-center text-center gap-1', healthBg)}>
          <p className={cn('text-6xl font-black leading-none', healthColor)}>{gPct}%</p>
          <p className="text-sm font-bold text-slate-300 mt-1">Saúde Geral da Rede</p>
          <p className="text-xs text-slate-500">{gt.sim} de {gt.tot} itens conformes</p>
          <div className="w-full mt-3 h-2 bg-slate-700/50 rounded-full overflow-hidden">
            <div className={cn('h-full rounded-full transition-all', gPct>=80?'bg-emerald-500':gPct>=50?'bg-amber-500':'bg-red-500')}
              style={{ width: `${gPct}%` }} />
          </div>
        </div>

        {/* KPI cards */}
        {[
          { label:'Dispositivos', value: devices.length, sub:'analisados',   c:'text-purple-400',  bg:'bg-purple-900/20',  b:'border-purple-800/50' },
          { label:'Conformes',    value: gt.sim,         sub:'SIM',          c:'text-emerald-400', bg:'bg-emerald-900/20', b:'border-emerald-800/50' },
          { label:'Não Conf.',    value: gt.nao,         sub:'NÃO',          c:'text-red-400',     bg:'bg-red-900/20',     b:'border-red-800/50' },
          { label:'Parciais',     value: gt.par,         sub:'PARCIAL',      c:'text-amber-400',   bg:'bg-amber-900/20',   b:'border-amber-800/50' },
          { label:'Risco Alto',   value: gt.alt,         sub:'itens críticos',c:'text-red-400',    bg:'bg-red-900/20',     b:'border-red-800/50' },
        ].map(s => (
          <div key={s.label} className={cn('rounded-2xl border p-4 flex flex-col items-center justify-center text-center gap-0.5', s.bg, s.b)}>
            <p className={cn('text-4xl font-black leading-none', s.c)}>{s.value}</p>
            <p className="text-xs font-bold text-slate-300 mt-1">{s.label}</p>
            <p className="text-xs text-slate-600">{s.sub}</p>
          </div>
        ))}
      </div>

      {/* ── Row 2: Network health bar + Vendor breakdown ──────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">

        {/* Network health stacked bar */}
        <div className="lg:col-span-2 rounded-2xl border border-slate-800 bg-slate-800/40 p-5 space-y-4">
          <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400 flex items-center gap-2">
            <Globe className="w-3.5 h-3.5" /> Distribuição de Conformidade
          </h3>
          <div className="flex h-6 rounded-xl overflow-hidden gap-0.5">
            {gt.tot > 0 && <>
              <div className="bg-emerald-500 h-full transition-all flex items-center justify-center" style={{ width:`${Math.round(gt.sim/gt.tot*100)}%` }}>
                {Math.round(gt.sim/gt.tot*100) > 8 && <span className="text-xs font-bold text-white">{Math.round(gt.sim/gt.tot*100)}%</span>}
              </div>
              <div className="bg-amber-500 h-full transition-all flex items-center justify-center" style={{ width:`${Math.round(gt.par/gt.tot*100)}%` }}>
                {Math.round(gt.par/gt.tot*100) > 6 && <span className="text-xs font-bold text-white">{Math.round(gt.par/gt.tot*100)}%</span>}
              </div>
              <div className="bg-red-500 h-full transition-all flex items-center justify-center" style={{ width:`${Math.round(gt.nao/gt.tot*100)}%` }}>
                {Math.round(gt.nao/gt.tot*100) > 6 && <span className="text-xs font-bold text-white">{Math.round(gt.nao/gt.tot*100)}%</span>}
              </div>
            </>}
          </div>
          <div className="flex gap-5 text-xs">
            <span className="flex items-center gap-1.5 text-emerald-400"><span className="w-3 h-3 rounded bg-emerald-500 inline-block" /> SIM — {gt.sim}</span>
            <span className="flex items-center gap-1.5 text-amber-400"><span className="w-3 h-3 rounded bg-amber-500 inline-block" /> PARCIAL — {gt.par}</span>
            <span className="flex items-center gap-1.5 text-red-400"><span className="w-3 h-3 rounded bg-red-500 inline-block" /> NÃO — {gt.nao}</span>
          </div>

          {/* Per-section breakdown */}
          <div className="space-y-2 pt-2 border-t border-slate-700/50">
            <p className="text-xs text-slate-500 font-semibold uppercase tracking-wide">Por Categoria de Segurança</p>
            {sectionList.slice(0, 8).map(s => (
              <div key={s.label} className="flex items-center gap-3">
                <span className="text-xs text-slate-500 truncate w-44 flex-shrink-0" title={s.label}>{s.label}</span>
                <div className="flex-1 h-1.5 bg-slate-700/50 rounded-full overflow-hidden">
                  <div className={cn('h-full rounded-full', s.pct>=80?'bg-emerald-500':s.pct>=50?'bg-amber-500':'bg-red-500')}
                    style={{ width:`${s.pct}%` }} />
                </div>
                <span className={cn('text-xs font-bold w-10 text-right flex-shrink-0', s.pct>=80?'text-emerald-400':s.pct>=50?'text-amber-400':'text-red-400')}>{s.pct}%</span>
              </div>
            ))}
          </div>
        </div>

        {/* Vendor breakdown */}
        <div className="rounded-2xl border border-slate-800 bg-slate-800/40 p-5 space-y-4">
          <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400 flex items-center gap-2">
            <Server className="w-3.5 h-3.5" /> Fabricantes
          </h3>
          <div className="space-y-3">
            {Object.entries(vendorCount).sort((a,b)=>b[1]-a[1]).map(([vendor, count]) => {
              const vRows = rows.filter(r => r.vendor === vendor);
              const vPct  = vRows.length > 0 ? Math.round(vRows.reduce((a,r)=>a+r.pct,0)/vRows.length) : 0;
              return (
                <div key={vendor} className="space-y-1">
                  <div className="flex justify-between items-center">
                    <VendorPill vendor={vendor} />
                    <span className="text-xs text-slate-400 font-semibold">{count} device{count>1?'s':''}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="flex-1 h-1.5 bg-slate-700/50 rounded-full overflow-hidden">
                      <div className={cn('h-full rounded-full', vPct>=80?'bg-emerald-500':vPct>=50?'bg-amber-500':'bg-red-500')}
                        style={{ width:`${vPct}%` }} />
                    </div>
                    <span className={cn('text-xs font-bold w-8 text-right', vPct>=80?'text-emerald-400':vPct>=50?'text-amber-400':'text-red-400')}>{vPct}%</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* ── Row 3: Top Offenders + Top Compliant + High Risk ─────── */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">

        {/* Top offenders */}
        <div className="rounded-2xl border border-red-900/40 bg-red-900/10 p-5 space-y-3">
          <h3 className="text-xs font-bold uppercase tracking-widest text-red-400 flex items-center gap-2">
            <AlertCircle className="w-3.5 h-3.5" /> Piores Conformidades
          </h3>
          <div className="space-y-2">
            {topOffenders.map((r, i) => (
              <button key={i} onClick={() => onGoToMatriz(rows.indexOf(r))}
                className="w-full flex items-center justify-between gap-2 p-2.5 rounded-xl bg-red-900/20 hover:bg-red-900/40 border border-red-900/30 hover:border-red-700/50 transition-all group text-left">
                <div className="min-w-0 flex-1">
                  <p className="text-xs font-bold text-slate-200 font-mono truncate">{r.hostname}</p>
                  <VendorPill vendor={r.vendor} />
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                  <span className={cn('text-sm font-black', r.pct>=50?'text-amber-400':'text-red-400')}>{r.pct}%</span>
                  <ChevronDown className="w-3.5 h-3.5 text-slate-600 group-hover:text-slate-400 -rotate-90" />
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Top compliant */}
        <div className="rounded-2xl border border-emerald-900/40 bg-emerald-900/10 p-5 space-y-3">
          <h3 className="text-xs font-bold uppercase tracking-widest text-emerald-400 flex items-center gap-2">
            <CheckCircle2 className="w-3.5 h-3.5" /> Melhores Conformidades
          </h3>
          <div className="space-y-2">
            {topCompliant.map((r, i) => (
              <button key={i} onClick={() => onGoToMatriz(rows.indexOf(r))}
                className="w-full flex items-center justify-between gap-2 p-2.5 rounded-xl bg-emerald-900/20 hover:bg-emerald-900/40 border border-emerald-900/30 hover:border-emerald-700/50 transition-all group text-left">
                <div className="min-w-0 flex-1">
                  <p className="text-xs font-bold text-slate-200 font-mono truncate">{r.hostname}</p>
                  <VendorPill vendor={r.vendor} />
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                  <span className="text-sm font-black text-emerald-400">{r.pct}%</span>
                  <ChevronDown className="w-3.5 h-3.5 text-slate-600 group-hover:text-slate-400 -rotate-90" />
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* High risk devices */}
        <div className="rounded-2xl border border-orange-900/40 bg-orange-900/10 p-5 space-y-3">
          <h3 className="text-xs font-bold uppercase tracking-widest text-orange-400 flex items-center gap-2">
            <Shield className="w-3.5 h-3.5" /> Riscos Críticos (✕ ALTO)
          </h3>
          {highRisk.length === 0 ? (
            <div className="flex flex-col items-center py-6 text-center gap-2">
              <CheckCircle2 className="w-8 h-8 text-emerald-500/50" />
              <p className="text-xs text-emerald-500/80 font-semibold">Nenhum risco alto detectado</p>
            </div>
          ) : (
            <div className="space-y-2">
              {highRisk.slice(0, 5).map((r, i) => (
                <button key={i} onClick={() => onGoToMatriz(rows.indexOf(r))}
                  className="w-full flex items-center justify-between gap-2 p-2.5 rounded-xl bg-orange-900/20 hover:bg-orange-900/40 border border-orange-900/30 hover:border-orange-700/50 transition-all group text-left">
                  <div className="min-w-0 flex-1">
                    <p className="text-xs font-bold text-slate-200 font-mono truncate">{r.hostname}</p>
                    <VendorPill vendor={r.vendor} />
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <span className="text-sm font-black text-red-400">{r.altos} ✕</span>
                    <ChevronDown className="w-3.5 h-3.5 text-slate-600 group-hover:text-slate-400 -rotate-90" />
                  </div>
                </button>
              ))}
              {highRisk.length > 5 && (
                <p className="text-xs text-slate-600 text-center">+ {highRisk.length-5} outros dispositivos</p>
              )}
            </div>
          )}
        </div>
      </div>

      {/* ── Row 4: Full device table ───────────────────────────────── */}
      <div className="rounded-2xl border border-slate-800 overflow-hidden">
        <div className="bg-slate-800/80 px-5 py-3 flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400 flex items-center gap-2">
            <Layers className="w-3.5 h-3.5" /> Todos os Dispositivos — {rows.length} total
          </h3>
        </div>

        {/* Table header */}
        <div className="grid grid-cols-[2fr_1fr_1.2fr_0.6fr_0.6fr_0.6fr_0.6fr_0.7fr_0.8fr_0.5fr] gap-0 px-5 py-2.5 bg-slate-800/60 text-xs font-bold uppercase tracking-wide text-slate-600">
          {['DISPOSITIVO','IP','VENDOR','TOTAL','SIM','NÃO','PARCIAL','ALTO ✕','CONFORM.','VER'].map((h,i) => (
            <span key={h} className={i >= 3 ? 'text-center' : ''}>{h}</span>
          ))}
        </div>

        <div className="divide-y divide-slate-800/50 max-h-[480px] overflow-y-auto">
          {rows.map((row, i) => (
            <div key={i} className={cn(
              'grid grid-cols-[2fr_1fr_1.2fr_0.6fr_0.6fr_0.6fr_0.6fr_0.7fr_0.8fr_0.5fr] gap-0 px-5 py-2.5 items-center transition-colors hover:bg-slate-800/40',
              i % 2 === 0 ? 'bg-slate-900/60' : 'bg-slate-900/30'
            )}>
              <div className="min-w-0">
                <p className="text-xs font-bold text-slate-200 font-mono truncate">{row.hostname||'—'}</p>
                {row.model && <p className="text-xs text-slate-600 truncate mt-0.5">{row.model}</p>}
              </div>
              <span className="text-xs text-slate-600 font-mono truncate">{row.ip||'—'}</span>
              <div><VendorPill vendor={row.vendor} /></div>
              <span className="text-xs text-slate-400 text-center font-semibold">{row.tot}</span>
              <span className="text-xs text-emerald-400 text-center font-bold">{row.sim}</span>
              <span className="text-xs text-red-400 text-center font-bold">{row.nao}</span>
              <span className="text-xs text-amber-400 text-center font-bold">{row.parcial}</span>
              <span className={cn('text-xs text-center font-bold', row.altos>0?'text-red-400':'text-slate-600')}>{row.altos}</span>
              <div className="text-center"><ConformBadge pct={row.pct} /></div>
              <div className="text-center">
                <button onClick={() => onGoToMatriz(i)}
                  className="text-xs text-purple-400 hover:text-purple-200 bg-purple-900/20 hover:bg-purple-900/50 px-2 py-0.5 rounded-lg border border-purple-800/50 transition-all font-semibold">
                  Ver
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

    </div>
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

  // ── Shared risk/assessment state — persists across tab switches ─────
  const [riskDevices,       setRiskDevices]       = useState<DeviceResult[]>([]);
  const [riskView,          setRiskView]          = useState<'upload'|'assessment'|'detail'>('upload');
  const [riskActiveDevice,  setRiskActiveDevice]  = useState(0);
  const [assessView,        setAssessView]        = useState<'upload'|'assessment'|'detail'>('upload');
  const [assessActiveDevice,setAssessActiveDevice] = useState(0);

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
      Array.from(files as FileList).forEach(f => fd.append('files', f as File, (f as File).name));
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
    <div className="min-h-screen bg-[#0d1117] text-slate-100 font-sans">

      {/* ── HEADER ────────────────────────────────────────────────── */}
      <header className="sticky top-0 z-20 border-b border-slate-800 bg-[#0d1117]">
        <div className="max-w-7xl mx-auto px-6 h-14 flex items-center gap-4">
          {/* Logo */}
          <div className="flex items-center gap-2.5 flex-shrink-0">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center">
              <Zap className="w-4 h-4 text-white" />
            </div>
            <span className="text-lg font-black tracking-tight text-white">
              Magneto
            </span>
          </div>

          {/* Dashboard button — next to logo, as shown in the image */}
          <button
            onClick={() => setActiveTab(activeTab === 'dashboard' ? 'discovery' : 'dashboard')}
            className={cn(
              'flex items-center gap-2 px-4 py-1.5 rounded-lg text-sm font-semibold transition-all border',
              activeTab === 'dashboard'
                ? 'bg-cyan-500/20 border-cyan-500/60 text-cyan-300'
                : 'bg-slate-800/60 border-slate-700 text-slate-400 hover:text-slate-200 hover:border-slate-600'
            )}
          >
            <Monitor className="w-4 h-4" />
            Dashboard
            {riskDevices.length > 0 && (
              <span className="bg-purple-700 text-purple-200 text-xs px-1.5 py-0.5 rounded-full font-bold leading-none">
                {riskDevices.length}
              </span>
            )}
          </button>

          <div className="flex-1" />

          {/* Theme toggle */}
          <button
            onClick={() => setTheme(t => t === 'dark' ? 'light' : 'dark')}
            className="p-2 rounded-lg hover:bg-slate-800 transition-colors text-slate-400 hover:text-slate-200"
            title="Alternar tema"
          >
            {theme === 'dark' ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
          </button>
        </div>
      </header>

      {/* ── MAIN ──────────────────────────────────────────────────── */}
      <main className="max-w-7xl mx-auto px-6 py-6 space-y-6">

        {/* ── DASHBOARD — full page, outside card ────────────────── */}
        {activeTab === 'dashboard' && (
          <ExecutiveDashboard
            devices={riskDevices}
            onClear={() => { setRiskDevices([]); setRiskView('upload'); setAssessView('upload'); }}
            onGoToMatriz={(i) => { setRiskActiveDevice(i); setRiskView('detail'); setActiveTab('risk'); }}
            onGoToAssessment={() => { setAssessView('assessment'); setActiveTab('assessment'); }}
            onBack={() => setActiveTab('discovery')}
          />
        )}

        {/* ── CARD — hidden when dashboard is active ─────────────── */}
        <div className={cn('bg-[#161b22] rounded-2xl border border-slate-800 overflow-hidden', activeTab === 'dashboard' && 'hidden')}>

          {/* TABS */}
          <div className="flex border-b border-slate-800">
            {([
              { id: 'discovery',  icon: <Search   className="w-4 h-4" />, label: 'Discovery Ativo (SSH)' },
              { id: 'upload',     icon: <Upload    className="w-4 h-4" />, label: 'Upload Offline' },
              { id: 'risk',       icon: <Shield    className="w-4 h-4" />, label: 'Matriz de Riscos' },
              { id: 'assessment', icon: <Activity  className="w-4 h-4" />, label: 'Assessment Network' },
            ] as const).map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={cn(
                  'flex-1 py-4 px-4 text-sm font-semibold flex items-center justify-center gap-2 transition-all',
                  activeTab === tab.id
                    ? 'border-b-2 border-cyan-400 text-white bg-slate-800/40'
                    : 'text-slate-500 hover:text-slate-300 hover:bg-slate-800/30'
                )}
              >
                {tab.icon} {tab.label}
                {(tab.id === 'risk' || tab.id === 'assessment') && riskDevices.length > 0 && (
                  <span className="bg-purple-700 text-purple-200 text-xs px-1.5 py-0.5 rounded-full font-bold leading-none">
                    {riskDevices.length}
                  </span>
                )}
              </button>
            ))}
          </div>

          <div className="p-8">
            {/* ERROR */}
            {errorMsg && (
              <div className="mb-6 bg-red-900/20 border border-red-700 rounded-xl p-4 flex items-start gap-3 text-red-300 animate-in fade-in slide-in-from-top-2">
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
                  className="bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 disabled:cursor-not-allowed text-white font-bold py-3 px-8 rounded-xl transition-all flex items-center gap-2 text-sm"
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
              <form onSubmit={handleUpload} className="space-y-6">
                <div
                  onClick={() => fileInputRef.current?.click()}
                  className="border-2 border-dashed border-slate-700 rounded-2xl p-14 text-center hover:border-cyan-500 hover:bg-cyan-900/10 transition-all cursor-pointer group"
                >
                  <div className="w-14 h-14 rounded-2xl bg-slate-800 group-hover:bg-cyan-900/40 flex items-center justify-center mx-auto mb-5 transition-colors">
                    <Server className="w-7 h-7 text-slate-400 group-hover:text-cyan-400 transition-colors" />
                  </div>
                  <p className="text-sm font-semibold text-slate-300 mb-1">
                    Arraste uma pasta ou clique para selecionar arquivos
                  </p>
                  <p className="text-xs text-slate-500">Pastas .txt, .log de coleta de comandos</p>

                  <input
                    type="file" multiple
                    {...{ webkitdirectory: '', directory: '' } as any}
                    ref={fileInputRef}
                    onChange={e => setFiles(e.target.files)}
                    className="hidden"
                  />
                </div>

                {files && files.length > 0 && (
                  <div className="flex items-center gap-2 text-sm font-medium text-emerald-400">
                    <CheckCircle2 className="w-4 h-4" />
                    {files.length} arquivo(s) selecionado(s)
                  </div>
                )}

                <button
                  type="submit"
                  disabled={loading || !files || files.length === 0}
                  className="bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 disabled:cursor-not-allowed text-white font-bold py-3 px-8 rounded-xl transition-all flex items-center gap-2 text-sm"
                >
                  {loading ? (
                    <><Layers className="w-5 h-5 animate-pulse" /> Processando...</>
                  ) : (
                    <><Layers className="w-5 h-5" /> Gerar Topologia</>
                  )}
                </button>
              </form>
            )}
            {/* ── RISK ASSESSMENT FORM ─────────────────────────────── */}
            <div style={{ display: activeTab === 'risk' ? 'block' : 'none' }}>
              <RiskAssessmentPanel
                defaultView="matrix"
                sharedDevices={riskDevices}
                setSharedDevices={setRiskDevices}
                sharedView={riskView}
                setSharedView={setRiskView}
                sharedActiveDevice={riskActiveDevice}
                setSharedActiveDevice={setRiskActiveDevice}
              />
            </div>
            {/* ── ASSESSMENT NETWORK ───────────────────────────────── */}
            <div style={{ display: activeTab === 'assessment' ? 'block' : 'none' }}>
              <RiskAssessmentPanel
                defaultView="assessment"
                sharedDevices={riskDevices}
                setSharedDevices={setRiskDevices}
                sharedView={assessView}
                setSharedView={setAssessView}
                sharedActiveDevice={assessActiveDevice}
                setSharedActiveDevice={setAssessActiveDevice}
              />
            </div>
          </div>
        </div>

        {resultXml && (
          <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">

            {/* Success banner */}
            <div className="bg-emerald-900/20 border border-emerald-700/50 rounded-2xl p-6">
              <div className="flex items-start gap-4">
                <div className="w-12 h-12 rounded-xl bg-emerald-900/50 flex items-center justify-center flex-shrink-0">
                  <CheckCircle2 className="w-6 h-6 text-emerald-400" />
                </div>
                <div className="flex-1">
                  <h2 className="font-black text-lg text-emerald-100 mb-1">
                    Topologia Gerada com Sucesso
                  </h2>
                  <p className="text-sm text-emerald-300/70">
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
                className="flex items-center gap-2 bg-cyan-600 hover:bg-cyan-500 text-white font-bold py-2.5 px-5 rounded-xl transition-all text-sm"
              >
                <Download className="w-4 h-4" /> Baixar .drawio
              </button>

              {rawOutputs && (<>
                <button
                  onClick={() => setShowRawOutputs(s => !s)}
                  className="flex items-center gap-2 bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold py-2.5 px-5 rounded-xl transition-colors text-sm border border-slate-700"
                >
                  <Terminal className="w-4 h-4" />
                  {showRawOutputs ? 'Ocultar Logs' : 'Ver Logs Brutos'}
                </button>
                <button
                  onClick={downloadRawOutputs}
                  className="flex items-center gap-2 bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold py-2.5 px-5 rounded-xl transition-colors text-sm border border-slate-700"
                >
                  <FileText className="w-4 h-4" /> Baixar (.txt)
                </button>
                <button
                  onClick={copyToClipboard}
                  className="flex items-center gap-2 bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold py-2.5 px-5 rounded-xl transition-colors text-sm border border-slate-700"
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
      <footer className="border-t border-slate-800 mt-16 py-6 text-center text-xs text-slate-600">
        Magneto (Autor Cleber Silva)
      </footer>
    </div>
  );
}
