import React, { useState, useEffect, useRef } from 'react';
import { Upload, Search, Download, Server, Network, Layers, Terminal, ChevronDown, ChevronUp, FileText, AlertCircle, Sun, Moon, CheckCircle2, Copy, XCircle, Monitor } from 'lucide-react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export default function App() {
  const [activeTab, setActiveTab] = useState<'discovery' | 'upload'>('discovery');
  const [vendor, setVendor] = useState('cisco_ios');
  const [ip, setIp] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [files, setFiles] = useState<FileList | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [loading, setLoading] = useState(false);
  const [resultXml, setResultXml] = useState<string | null>(null);
  const [rawOutputs, setRawOutputs] = useState<Record<string, string> | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const [profiles, setProfiles] = useState<Record<string, any> | null>(null);
  const [showCommands, setShowCommands] = useState(false);
  const [showRawOutputs, setShowRawOutputs] = useState(false);
  
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    if (typeof window !== 'undefined') {
      const savedTheme = localStorage.getItem('theme');
      if (savedTheme === 'light' || savedTheme === 'dark') {
        return savedTheme;
      }
    }
    return 'light';
  });
  const [isThemeMenuOpen, setIsThemeMenuOpen] = useState(false);

  const [commandText, setCommandText] = useState({
    l1: '', l2: '', l3: '', hardware: ''
  });

  useEffect(() => {
    const root = window.document.documentElement;
    root.classList.remove('light', 'dark');
    root.classList.add(theme);
    localStorage.setItem('theme', theme);
  }, [theme]);

  useEffect(() => {
    fetch('/api/profiles')
      .then(res => res.json())
      .then(data => {
        setProfiles(data);
        const saved = localStorage.getItem(`magneto_commands_cisco_ios`);
        if (saved) {
          setCommandText(JSON.parse(saved));
        } else if (data['cisco_ios']) {
          setCommandText({
            l1: data['cisco_ios'].l1.join('\n'),
            l2: data['cisco_ios'].l2.join('\n'),
            l3: data['cisco_ios'].l3.join('\n'),
            hardware: data['cisco_ios'].hardware.join('\n'),
          });
        }
      });
  }, []);

  const handleVendorChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const v = e.target.value;
    setVendor(v);
    const saved = localStorage.getItem(`magneto_commands_${v}`);
    if (saved) {
      setCommandText(JSON.parse(saved));
    } else if (profiles && profiles[v]) {
      setCommandText({
        l1: profiles[v].l1.join('\n'),
        l2: profiles[v].l2.join('\n'),
        l3: profiles[v].l3.join('\n'),
        hardware: profiles[v].hardware.join('\n'),
      });
    }
  };

  const handleSaveCommands = () => {
    localStorage.setItem(`magneto_commands_${vendor}`, JSON.stringify(commandText));
    alert('Comandos salvos com sucesso!');
  };

  const handleDiscovery = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setErrorMsg(null);
    setResultXml(null);
    setRawOutputs(null);
    
    const customCommands = {
      l1: commandText.l1.split('\n').filter(c => c.trim() !== ''),
      l2: commandText.l2.split('\n').filter(c => c.trim() !== ''),
      l3: commandText.l3.split('\n').filter(c => c.trim() !== ''),
      hardware: commandText.hardware.split('\n').filter(c => c.trim() !== ''),
    };

    try {
      const res = await fetch('/api/discovery', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, username, password, vendor, customCommands }),
      });
      
      const data = await res.json();
      
      if (!res.ok) {
        throw new Error(data.error || 'Erro desconhecido na descoberta');
      }
      
      setResultXml(data.xml);
      setRawOutputs(data.rawOutputs);
    } catch (error: any) {
      console.error(error);
      setErrorMsg(error.message);
    } finally {
      setLoading(false);
    }
  };

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!files || files.length === 0) return;
    setLoading(true);
    setErrorMsg(null);
    setResultXml(null);
    setRawOutputs(null);
    try {
      const formData = new FormData();
      formData.append('vendor', vendor);
      Array.from(files).forEach((file: File) => {
        formData.append('files', file);
      });

      const res = await fetch('/api/upload', {
        method: 'POST',
        body: formData,
      });
      const data = await res.json();
      
      if (!res.ok) {
        throw new Error(data.error || 'Erro desconhecido no upload');
      }
      
      setResultXml(data.xml);
    } catch (error: any) {
      console.error(error);
      setErrorMsg(error.message);
    } finally {
      setLoading(false);
    }
  };

  const downloadDrawio = () => {
    if (!resultXml) return;
    const blob = new Blob([resultXml], { type: 'application/xml' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'topology.drawio';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const downloadRawOutputs = () => {
    if (!rawOutputs) return;
    
    let textContent = '';
    for (const [cmd, output] of Object.entries(rawOutputs)) {
      textContent += `================================================================\n`;
      textContent += `COMMAND: ${cmd}\n`;
      textContent += `================================================================\n`;
      textContent += `${output}\n\n`;
    }
    
    const blob = new Blob([textContent], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `raw_outputs_${ip.replace(/\./g, '_')}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const copyToClipboard = async () => {
    if (!rawOutputs) return;
    
    let textContent = '';
    for (const [cmd, output] of Object.entries(rawOutputs)) {
      textContent += `================================================================\n`;
      textContent += `COMMAND: ${cmd}\n`;
      textContent += `================================================================\n`;
      textContent += `${output}\n\n`;
    }
    
    try {
      await navigator.clipboard.writeText(textContent);
      // Could add a toast here, but for now just a simple alert or silent success
      alert('Logs copiados para a área de transferência!');
    } catch (err) {
      console.error('Failed to copy text: ', err);
      alert('Erro ao copiar logs.');
    }
  };

  const handleClear = () => {
    setIp('');
    setUsername('');
    setPassword('');
    setFiles(null);
    setResultXml(null);
    setRawOutputs(null);
    setErrorMsg(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 font-sans transition-colors duration-300">
      {/* Header */}
      <header className="bg-indigo-600 dark:bg-indigo-900 text-white shadow-md sticky top-0 z-10">
        <div className="max-w-5xl mx-auto px-6 py-4 flex items-center gap-3">
          <Network className="w-8 h-8" />
          <h1 className="text-2xl font-bold tracking-tight">Magneto</h1>
          <span className="hidden sm:inline-block ml-4 text-indigo-200 dark:text-indigo-300 text-sm font-medium border-l border-indigo-500 pl-4">
            L1, L2 & L3 Topology Generator
          </span>
          
          <div className="relative ml-auto">
            <button 
              onClick={() => setIsThemeMenuOpen(!isThemeMenuOpen)}
              className="p-2 rounded-full hover:bg-white/10 transition-colors flex items-center gap-2"
              title="Alterar Tema"
            >
              {theme === 'light' && <Sun className="w-5 h-5" />}
              {theme === 'dark' && <Moon className="w-5 h-5" />}
            </button>

            {isThemeMenuOpen && (
              <>
                <div className="fixed inset-0 z-40" onClick={() => setIsThemeMenuOpen(false)} />
                <div className="absolute right-0 mt-2 w-36 bg-white dark:bg-slate-800 rounded-xl shadow-lg border border-slate-200 dark:border-slate-700 overflow-hidden z-50 py-1">
                  <button
                    onClick={() => { setTheme('light'); setIsThemeMenuOpen(false); }}
                    className={cn("w-full text-left px-4 py-2 text-sm flex items-center gap-3 hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors", theme === 'light' ? "text-indigo-600 dark:text-indigo-400 font-medium" : "text-slate-700 dark:text-slate-300")}
                  >
                    <Sun className="w-4 h-4" /> Claro
                  </button>
                  <button
                    onClick={() => { setTheme('dark'); setIsThemeMenuOpen(false); }}
                    className={cn("w-full text-left px-4 py-2 text-sm flex items-center gap-3 hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors", theme === 'dark' ? "text-indigo-600 dark:text-indigo-400 font-medium" : "text-slate-700 dark:text-slate-300")}
                  >
                    <Moon className="w-4 h-4" /> Escuro
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-6 py-8">
        <div className="bg-white dark:bg-slate-900 rounded-2xl shadow-sm border border-slate-200 dark:border-slate-800 overflow-hidden transition-colors duration-300">
          {/* Tabs */}
          <div className="flex border-b border-slate-200 dark:border-slate-800">
            <button
              onClick={() => setActiveTab('discovery')}
              className={cn(
                "flex-1 py-4 px-6 text-sm font-semibold flex items-center justify-center gap-2 transition-colors",
                activeTab === 'discovery' 
                  ? "border-b-2 border-indigo-600 dark:border-indigo-400 text-indigo-600 dark:text-indigo-400 bg-indigo-50/50 dark:bg-indigo-900/20" 
                  : "text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800/50"
              )}
            >
              <Search className="w-4 h-4" />
              Discovery Ativo (SSH/Telnet)
            </button>
            <button
              onClick={() => setActiveTab('upload')}
              className={cn(
                "flex-1 py-4 px-6 text-sm font-semibold flex items-center justify-center gap-2 transition-colors",
                activeTab === 'upload' 
                  ? "border-b-2 border-indigo-600 dark:border-indigo-400 text-indigo-600 dark:text-indigo-400 bg-indigo-50/50 dark:bg-indigo-900/20" 
                  : "text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800/50"
              )}
            >
              <Upload className="w-4 h-4" />
              Upload de Arquivos (Offline)
            </button>
          </div>

          <div className="p-8">
            {/* Error Message */}
            {errorMsg && (
              <div className="mb-8 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800/50 rounded-xl p-4 flex items-start gap-3 text-red-800 dark:text-red-300 animate-in fade-in slide-in-from-top-2">
                <AlertCircle className="w-5 h-5 flex-shrink-0 mt-0.5" />
                <div>
                  <h3 className="font-semibold mb-1">Erro na Execução</h3>
                  <p className="text-sm">{errorMsg}</p>
                </div>
              </div>
            )}

            {/* Discovery Form */}
            {activeTab === 'discovery' && (
              <form onSubmit={handleDiscovery} className="space-y-6 max-w-2xl animate-in fade-in">
                {/* Common Vendor Select */}
                <div className="max-w-md">
                  <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                    Vendor / OS
                  </label>
                  <select
                    value={vendor}
                    onChange={handleVendorChange}
                    className="w-full rounded-lg border border-slate-300 dark:border-slate-700 shadow-sm bg-white dark:bg-slate-950 px-4 py-2.5 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-indigo-600 dark:focus:ring-indigo-500 focus:border-indigo-600 dark:focus:border-indigo-500 outline-none transition-all"
                  >
                    <option value="cisco_ios">Cisco IOS-XE</option>
                    <option value="cisco_nxos">Cisco NX-OS</option>
                    <option value="aruba_os">HP/HPE Aruba Switches</option>
                    <option value="hpe_comware">HPE Comware</option>
                    <option value="juniper_junos">Juniper Junos</option>
                    <option value="huawei_vrp">Huawei VRP</option>
                  </select>
                </div>

                <div className="max-w-md">
                  <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                    Endereço(s) IP (Seed)
                  </label>
                  <input
                    type="text"
                    required
                    value={ip}
                    onChange={(e) => setIp(e.target.value)}
                    placeholder="Ex: 10.0.0.1, 10.0.0.2"
                    className="w-full rounded-lg border border-slate-300 dark:border-slate-700 shadow-sm bg-white dark:bg-slate-950 px-4 py-2.5 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-indigo-600 dark:focus:ring-indigo-500 focus:border-indigo-600 dark:focus:border-indigo-500 outline-none transition-all"
                  />
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 max-w-md">
                  <div>
                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                      Usuário
                    </label>
                    <input
                      type="text"
                      required
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      className="w-full rounded-lg border border-slate-300 dark:border-slate-700 shadow-sm bg-white dark:bg-slate-950 px-4 py-2.5 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-indigo-600 dark:focus:ring-indigo-500 focus:border-indigo-600 dark:focus:border-indigo-500 outline-none transition-all"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                      Senha
                    </label>
                    <input
                      type="password"
                      required
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="w-full rounded-lg border border-slate-300 dark:border-slate-700 shadow-sm bg-white dark:bg-slate-950 px-4 py-2.5 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-indigo-600 dark:focus:ring-indigo-500 focus:border-indigo-600 dark:focus:border-indigo-500 outline-none transition-all"
                    />
                  </div>
                </div>

                {/* Commands Section */}
                <div className="border border-slate-200 dark:border-slate-700 rounded-xl overflow-hidden mt-6 transition-colors">
                  <button
                    type="button"
                    onClick={() => setShowCommands(!showCommands)}
                    className="w-full flex items-center justify-between px-4 py-3 bg-slate-50 dark:bg-slate-800/50 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors text-sm font-semibold text-slate-700 dark:text-slate-300"
                  >
                    <div className="flex items-center gap-2">
                      <Terminal className="w-4 h-4" />
                      Personalizar Comandos (Command Profiles)
                    </div>
                    {showCommands ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                  </button>
                  
                  {showCommands && (
                    <div className="p-4 bg-white dark:bg-slate-900 border-t border-slate-200 dark:border-slate-700 grid grid-cols-1 sm:grid-cols-2 gap-4 animate-in slide-in-from-top-2">
                      <div>
                        <label className="block text-xs font-medium text-slate-700 dark:text-slate-400 mb-1">Layer 1 (Física)</label>
                        <textarea
                          rows={3}
                          value={commandText.l1}
                          onChange={(e) => setCommandText({ ...commandText, l1: e.target.value })}
                          className="w-full rounded-lg border border-slate-300 dark:border-slate-700 shadow-sm bg-slate-50 dark:bg-slate-950 px-3 py-2 text-sm text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-indigo-600 dark:focus:ring-indigo-500 outline-none font-mono"
                          placeholder="Um comando por linha"
                        />
                      </div>
                      <div>
                        <label className="block text-xs font-medium text-slate-700 dark:text-slate-400 mb-1">Layer 2 (Lógica)</label>
                        <textarea
                          rows={3}
                          value={commandText.l2}
                          onChange={(e) => setCommandText({ ...commandText, l2: e.target.value })}
                          className="w-full rounded-lg border border-slate-300 dark:border-slate-700 shadow-sm bg-slate-50 dark:bg-slate-950 px-3 py-2 text-sm text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-indigo-600 dark:focus:ring-indigo-500 outline-none font-mono"
                          placeholder="Um comando por linha"
                        />
                      </div>
                      <div>
                        <label className="block text-xs font-medium text-slate-700 dark:text-slate-400 mb-1">Layer 3 (Roteamento)</label>
                        <textarea
                          rows={3}
                          value={commandText.l3}
                          onChange={(e) => setCommandText({ ...commandText, l3: e.target.value })}
                          className="w-full rounded-lg border border-slate-300 dark:border-slate-700 shadow-sm bg-slate-50 dark:bg-slate-950 px-3 py-2 text-sm text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-indigo-600 dark:focus:ring-indigo-500 outline-none font-mono"
                          placeholder="Um comando por linha"
                        />
                      </div>
                      <div>
                        <label className="block text-xs font-medium text-slate-700 dark:text-slate-400 mb-1">Hardware / OS</label>
                        <textarea
                          rows={3}
                          value={commandText.hardware}
                          onChange={(e) => setCommandText({ ...commandText, hardware: e.target.value })}
                          className="w-full rounded-lg border border-slate-300 dark:border-slate-700 shadow-sm bg-slate-50 dark:bg-slate-950 px-3 py-2 text-sm text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-indigo-600 dark:focus:ring-indigo-500 outline-none font-mono"
                          placeholder="Um comando por linha"
                        />
                      </div>
                      <div className="sm:col-span-2 flex justify-end mt-2">
                        <button
                          type="button"
                          onClick={handleSaveCommands}
                          className="bg-indigo-100 text-indigo-700 hover:bg-indigo-200 dark:bg-indigo-900/50 dark:text-indigo-300 dark:hover:bg-indigo-800 px-4 py-2 rounded-lg text-sm font-medium transition-colors"
                        >
                          Salvar Comandos
                        </button>
                      </div>
                    </div>
                  )}
                </div>

                <button
                  type="submit"
                  disabled={loading || !ip || !username || !password}
                  className="w-full max-w-md bg-indigo-600 hover:bg-indigo-700 dark:bg-indigo-500 dark:hover:bg-indigo-600 text-white font-semibold py-3 px-4 rounded-xl transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 shadow-sm"
                >
                  {loading ? (
                    <span className="animate-pulse flex items-center gap-2">
                      <Network className="w-5 h-5 animate-spin" />
                      Analisando rede...
                    </span>
                  ) : (
                    <>
                      <Search className="w-5 h-5" />
                      Iniciar Discovery
                    </>
                  )}
                </button>
              </form>
            )}

            {/* Upload Form */}
            {activeTab === 'upload' && (
              <form onSubmit={handleUpload} className="space-y-6 max-w-xl animate-in fade-in">
                <div className="border-2 border-dashed border-slate-300 dark:border-slate-700 rounded-2xl p-10 text-center hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors">
                  <Server className="w-12 h-12 text-slate-400 dark:text-slate-500 mx-auto mb-4" />
                  <p className="text-sm text-slate-600 dark:text-slate-400 mb-4">
                    Arraste os arquivos de coleta (folder, .txt, .log) ou clique para selecionar.
                  </p>
                  <input
                    type="file"
                    multiple
                    {...{ webkitdirectory: "", directory: "" } as any}
                    ref={fileInputRef}
                    onChange={(e) => setFiles(e.target.files)}
                    className="block w-full text-sm text-slate-500 dark:text-slate-400 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-indigo-50 dark:file:bg-indigo-900/30 file:text-indigo-700 dark:file:text-indigo-400 hover:file:bg-indigo-100 dark:hover:file:bg-indigo-900/50 cursor-pointer transition-colors"
                  />
                  {files && files.length > 0 && (
                    <div className="mt-4 flex items-center justify-center gap-2 text-sm text-emerald-600 dark:text-emerald-400 font-medium">
                      <CheckCircle2 className="w-4 h-4" />
                      {files.length} arquivo(s) selecionado(s)
                    </div>
                  )}
                </div>
                <button
                  type="submit"
                  disabled={loading || !files || files.length === 0}
                  className="w-full bg-indigo-600 hover:bg-indigo-700 dark:bg-indigo-500 dark:hover:bg-indigo-600 text-white font-semibold py-3 px-4 rounded-xl transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 shadow-sm"
                >
                  {loading ? (
                    <span className="animate-pulse flex items-center gap-2">
                      <Layers className="w-5 h-5 animate-bounce" />
                      Processando arquivos...
                    </span>
                  ) : (
                    <>
                      <Layers className="w-5 h-5" />
                      Gerar Topologia
                    </>
                  )}
                </button>
              </form>
            )}
          </div>
        </div>

        {/* Results Area */}
        {resultXml && (
          <div className="mt-8 bg-emerald-50 dark:bg-emerald-900/10 border border-emerald-200 dark:border-emerald-800/50 rounded-2xl p-8 text-center animate-in fade-in slide-in-from-bottom-4 duration-500">
            <div className="w-16 h-16 bg-emerald-100 dark:bg-emerald-900/50 rounded-full flex items-center justify-center mx-auto mb-4">
              <Download className="w-8 h-8 text-emerald-600 dark:text-emerald-400" />
            </div>
            <h2 className="text-2xl font-bold text-emerald-900 dark:text-emerald-100 mb-2">
              Topologia Gerada com Sucesso!
            </h2>
            <p className="text-emerald-700 dark:text-emerald-300/80 mb-6">
              O arquivo contém 3 abas (L1 Física, L2 Lógica e L3 Roteamento) com ícones mapeados automaticamente.
            </p>
            <div className="flex flex-col sm:flex-row justify-center gap-4">
              <button
                onClick={downloadDrawio}
                className="bg-emerald-600 hover:bg-emerald-700 dark:bg-emerald-500 dark:hover:bg-emerald-600 text-white font-bold py-3 px-8 rounded-xl transition-colors shadow-sm flex items-center justify-center gap-2"
              >
                <Download className="w-5 h-5" />
                Baixar Arquivo .drawio
              </button>
              
              {rawOutputs && (
                <button
                  onClick={() => setShowRawOutputs(!showRawOutputs)}
                  className="bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 text-emerald-700 dark:text-emerald-400 border border-emerald-300 dark:border-emerald-700 font-bold py-3 px-8 rounded-xl transition-colors shadow-sm flex items-center justify-center gap-2"
                >
                  <Terminal className="w-5 h-5" />
                  {showRawOutputs ? 'Ocultar Logs' : 'Ver Logs Brutos'}
                </button>
              )}
              {rawOutputs && (
                <button
                  onClick={downloadRawOutputs}
                  className="bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 text-emerald-700 dark:text-emerald-400 border border-emerald-300 dark:border-emerald-700 font-bold py-3 px-8 rounded-xl transition-colors shadow-sm flex items-center justify-center gap-2"
                >
                  <FileText className="w-5 h-5" />
                  Baixar (.txt)
                </button>
              )}
              {rawOutputs && (
                <button
                  onClick={copyToClipboard}
                  className="bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 text-emerald-700 dark:text-emerald-400 border border-emerald-300 dark:border-emerald-700 font-bold py-3 px-8 rounded-xl transition-colors shadow-sm flex items-center justify-center gap-2"
                >
                  <Copy className="w-5 h-5" />
                  Copiar Logs
                </button>
              )}
              <button
                onClick={handleClear}
                className="bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 font-bold py-3 px-8 rounded-xl transition-colors shadow-sm flex items-center justify-center gap-2"
              >
                <XCircle className="w-5 h-5" />
                Limpar Resultados
              </button>
            </div>

            {/* Raw Outputs Viewer */}
            {showRawOutputs && rawOutputs && (
              <div className="mt-8 text-left bg-slate-900 rounded-xl overflow-hidden border border-slate-800 shadow-inner animate-in slide-in-from-top-4">
                <div className="bg-slate-950 px-4 py-2 border-b border-slate-800 flex items-center gap-2 text-slate-400 text-sm font-mono">
                  <Terminal className="w-4 h-4" />
                  Terminal Output
                </div>
                <div className="p-4 max-h-96 overflow-y-auto font-mono text-xs sm:text-sm text-emerald-400 whitespace-pre-wrap">
                  {Object.entries(rawOutputs).map(([cmd, output], idx) => (
                    <div key={idx} className="mb-6 last:mb-0">
                      <div className="text-slate-500 select-none mb-1">$ {cmd}</div>
                      <div className="text-slate-300">{output || '<Sem saída>'}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}
