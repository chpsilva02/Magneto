import React, { useState } from 'react';
import { Upload, FolderUp, Terminal, Save, Plus, Trash2, Play, Settings } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState('upload');

  return (
    <div className="min-h-screen bg-gray-50 text-gray-900 flex flex-col">
      {/* Header */}
      <header className="bg-blue-900 text-white p-4 shadow-md">
        <div className="container mx-auto flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Settings className="w-6 h-6" />
            <h1 className="text-2xl font-bold tracking-tight">Magneto</h1>
          </div>
          <nav className="flex space-x-1">
            <button
              onClick={() => setActiveTab('upload')}
              className={`px-4 py-2 rounded-md transition-colors ${
                activeTab === 'upload' ? 'bg-blue-800 font-medium' : 'hover:bg-blue-800/50'
              }`}
            >
              Upload de Arquivos
            </button>
            <button
              onClick={() => setActiveTab('discovery')}
              className={`px-4 py-2 rounded-md transition-colors ${
                activeTab === 'discovery' ? 'bg-blue-800 font-medium' : 'hover:bg-blue-800/50'
              }`}
            >
              Discovery Ativo (SSH/Telnet)
            </button>
          </nav>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 container mx-auto p-6">
        {activeTab === 'upload' && <UploadTab />}
        {activeTab === 'discovery' && <DiscoveryTab />}
      </main>
    </div>
  );
}

function UploadTab() {
  const [dragActive, setDragActive] = useState(false);
  const [files, setFiles] = useState<File[]>([]);

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const newFiles = Array.from(e.dataTransfer.files);
      setFiles((prev) => [...prev, ...newFiles]);
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    e.preventDefault();
    if (e.target.files && e.target.files[0]) {
      const newFiles = Array.from(e.target.files);
      setFiles((prev) => [...prev, ...newFiles]);
    }
  };

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
      <h2 className="text-xl font-semibold mb-6 flex items-center">
        <Upload className="w-5 h-5 mr-2 text-blue-600" />
        Upload de Arquivos Vendor (Officeline)
      </h2>

      <div
        className={`relative border-2 border-dashed rounded-xl p-12 text-center transition-colors ${
          dragActive ? 'border-blue-500 bg-blue-50' : 'border-gray-300 hover:border-blue-400 hover:bg-gray-50'
        }`}
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
      >
        <input
          type="file"
          multiple
          // @ts-ignore - webkitdirectory is a non-standard attribute but widely supported
          webkitdirectory="true"
          directory="true"
          className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
          onChange={handleChange}
        />
        <div className="flex flex-col items-center justify-center space-y-4 pointer-events-none">
          <div className="bg-blue-100 p-4 rounded-full text-blue-600">
            <FolderUp className="w-8 h-8" />
          </div>
          <div className="space-y-1">
            <p className="text-lg font-medium text-gray-700">
              Arraste os arquivos de coleta (folder, .txt, .log) ou clique para selecionar
            </p>
            <p className="text-sm text-gray-500">
              Suporta pastas completas e múltiplos arquivos
            </p>
          </div>
        </div>
      </div>

      {files.length > 0 && (
        <div className="mt-8">
          <h3 className="text-md font-medium mb-3 text-gray-700">Arquivos Selecionados ({files.length})</h3>
          <div className="bg-gray-50 rounded-lg border border-gray-200 max-h-60 overflow-y-auto">
            <ul className="divide-y divide-gray-200">
              {files.map((file, index) => (
                <li key={index} className="px-4 py-3 flex items-center justify-between text-sm">
                  <span className="text-gray-700 truncate">{file.webkitRelativePath || file.name}</span>
                  <span className="text-gray-500 text-xs">{(file.size / 1024).toFixed(1)} KB</span>
                </li>
              ))}
            </ul>
          </div>
          <div className="mt-4 flex justify-end">
            <button 
              onClick={() => setFiles([])}
              className="px-4 py-2 text-sm text-red-600 hover:bg-red-50 rounded-md transition-colors mr-2"
            >
              Limpar
            </button>
            <button className="px-4 py-2 text-sm bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors">
              Processar Arquivos
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function DiscoveryTab() {
  const [commands, setCommands] = useState<string[]>(['show version', 'show running-config']);
  const [newCommand, setNewCommand] = useState('');
  const [saved, setSaved] = useState(false);

  const handleAddCommand = () => {
    if (newCommand.trim()) {
      setCommands([...commands, newCommand.trim()]);
      setNewCommand('');
      setSaved(false);
    }
  };

  const handleRemoveCommand = (index: number) => {
    setCommands(commands.filter((_, i) => i !== index));
    setSaved(false);
  };

  const handleSave = () => {
    // Simulate saving to backend/localstorage
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      {/* Settings Panel */}
      <div className="lg:col-span-1 space-y-6">
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <h2 className="text-lg font-semibold mb-4 flex items-center">
            <Terminal className="w-5 h-5 mr-2 text-blue-600" />
            Conexão
          </h2>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Protocolo</label>
              <select className="w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm">
                <option>SSH</option>
                <option>Telnet</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Endereço IP / Hostname</label>
              <input type="text" className="w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm" placeholder="192.168.1.1" />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Usuário</label>
              <input type="text" className="w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm" placeholder="admin" />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Senha</label>
              <input type="password" className="w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm" placeholder="••••••••" />
            </div>
            <button className="w-full flex justify-center items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500">
              <Play className="w-4 h-4 mr-2" />
              Iniciar Discovery
            </button>
          </div>
        </div>
      </div>

      {/* Commands Profile */}
      <div className="lg:col-span-2">
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6 h-full">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-lg font-semibold flex items-center">
              <Settings className="w-5 h-5 mr-2 text-blue-600" />
              Personalizar Comandos (Commands Profiles)
            </h2>
            <button 
              onClick={handleSave}
              className="flex items-center px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-md hover:bg-blue-700 transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
            >
              <Save className="w-4 h-4 mr-2" />
              {saved ? 'Salvo!' : 'Salvar'}
            </button>
          </div>

          <div className="mb-6">
            <label className="block text-sm font-medium text-gray-700 mb-2">Adicionar Novo Comando</label>
            <div className="flex space-x-2">
              <input
                type="text"
                value={newCommand}
                onChange={(e) => setNewCommand(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleAddCommand()}
                className="flex-1 border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                placeholder="Ex: show interfaces status"
              />
              <button
                onClick={handleAddCommand}
                className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-gray-800 hover:bg-gray-900 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-900"
              >
                <Plus className="w-4 h-4 mr-1" />
                Incluir
              </button>
            </div>
          </div>

          <div>
            <h3 className="text-sm font-medium text-gray-700 mb-3">Comandos na Fila de Execução</h3>
            {commands.length === 0 ? (
              <div className="text-center py-8 bg-gray-50 rounded-lg border border-dashed border-gray-300">
                <p className="text-gray-500 text-sm">Nenhum comando configurado.</p>
              </div>
            ) : (
              <ul className="space-y-2">
                {commands.map((cmd, index) => (
                  <li key={index} className="flex items-center justify-between bg-gray-50 border border-gray-200 rounded-md px-4 py-3">
                    <div className="flex items-center">
                      <span className="text-gray-400 font-mono text-sm mr-3">{index + 1}.</span>
                      <span className="font-mono text-sm text-gray-800">{cmd}</span>
                    </div>
                    <button
                      onClick={() => handleRemoveCommand(index)}
                      className="text-gray-400 hover:text-red-500 transition-colors"
                      title="Remover comando"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </li>
                ))}
              </ul>
            )}
            
            {saved && (
              <div className="mt-4 p-3 bg-green-50 text-green-700 rounded-md text-sm flex items-center">
                <div className="w-2 h-2 bg-green-500 rounded-full mr-2"></div>
                Perfil de comandos salvo com sucesso.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
