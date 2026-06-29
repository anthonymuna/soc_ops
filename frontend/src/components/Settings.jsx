import React, { useState, useEffect } from 'react';
import { 
  Settings as SettingsIcon, Shield, Moon, Sun, Monitor, 
  Key, User, CheckCircle, AlertTriangle, RefreshCw
} from 'lucide-react';
import { getToken } from '../auth';

export default function Settings({ onUnauth }) {
  const [activeTab, setActiveTab] = useState('appearance');
  const [isDark, setIsDark] = useState(true);
  
  // Password state
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [passwordStatus, setPasswordStatus] = useState(null);
  const [isLoading, setIsLoading] = useState(false);

  // Initialize theme
  useEffect(() => {
    const theme = localStorage.getItem('theme');
    if (theme === 'light') {
      setIsDark(false);
      document.documentElement.classList.remove('dark');
    } else {
      setIsDark(true);
      document.documentElement.classList.add('dark');
    }
  }, []);

  const toggleTheme = (dark) => {
    setIsDark(dark);
    if (dark) {
      document.documentElement.classList.add('dark');
      localStorage.setItem('theme', 'dark');
    } else {
      document.documentElement.classList.remove('dark');
      localStorage.setItem('theme', 'light');
    }
  };

  const handleChangePassword = async (e) => {
    e.preventDefault();
    setPasswordStatus(null);

    if (newPassword !== confirmPassword) {
      setPasswordStatus({ type: 'error', message: 'New passwords do not match.' });
      return;
    }

    if (newPassword.length < 8) {
      setPasswordStatus({ type: 'error', message: 'Password must be at least 8 characters long.' });
      return;
    }

    setIsLoading(true);
    const token = getToken();
    if (!token) {
      if (onUnauth) onUnauth();
      return;
    }

    try {
      const response = await fetch('/api/auth/password/change/', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          current_password: currentPassword,
          new_password: newPassword
        })
      });

      const data = await response.json();

      if (response.ok) {
        setPasswordStatus({ type: 'success', message: 'Password updated successfully.' });
        setCurrentPassword('');
        setNewPassword('');
        setConfirmPassword('');
      } else {
        setPasswordStatus({ type: 'error', message: data.error || 'Failed to update password.' });
      }
    } catch (err) {
      setPasswordStatus({ type: 'error', message: 'Network error. Please try again later.' });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex flex-col h-full bg-transparent text-slate-200 font-sans space-y-6">
      
      {/* Top Header */}
      <div className="flex items-center gap-3 border-b border-[#1e2d3d] pb-4 shrink-0">
        <SettingsIcon className="w-6 h-6 text-cyan-400" />
        <h1 className="text-xl font-bold tracking-widest text-slate-100 uppercase">System Settings</h1>
      </div>

      <div className="flex flex-col md:flex-row gap-8 flex-1 overflow-hidden">
        
        {/* Settings Navigation Menu */}
        <div className="w-full md:w-64 glass-panel p-4 rounded-xl border border-slate-800/80 bg-[#0d1520]/80 h-fit shrink-0">
          <nav className="flex flex-col space-y-2">
            {[
              { id: 'appearance', label: 'Appearance', icon: Monitor },
              { id: 'account', label: 'Account & Security', icon: User },
              { id: 'apikeys', label: 'API Integrations', icon: Key },
              { id: 'system', label: 'System Info', icon: Shield },
            ].map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-semibold transition-all ${
                  activeTab === tab.id 
                    ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20' 
                    : 'text-slate-400 hover:text-slate-200 hover:bg-[#121824] border border-transparent'
                }`}
              >
                <tab.icon className="w-4 h-4" />
                {tab.label}
              </button>
            ))}
          </nav>
        </div>

        {/* Settings Content Area */}
        <div className="flex-1 overflow-y-auto pr-2 pb-8">
          
          {/* Appearance Tab */}
          {activeTab === 'appearance' && (
            <div className="space-y-6 max-w-3xl">
              <div className="glass-panel p-6 rounded-xl border border-slate-800/80 bg-[#0d1520]/80">
                <h2 className="text-sm font-bold uppercase tracking-widest text-slate-300 border-b border-slate-800 pb-3 mb-6">Interface Theme</h2>
                
                <div className="grid grid-cols-2 gap-4">
                  
                  {/* Dark Mode Option */}
                  <button
                    onClick={() => toggleTheme(true)}
                    className={`flex flex-col items-center justify-center p-6 border-2 rounded-xl transition-all ${
                      isDark ? 'border-cyan-500 bg-[#0f172a]' : 'border-slate-800 bg-[#1e293b] hover:border-slate-600'
                    }`}
                  >
                    <Moon className={`w-8 h-8 mb-3 ${isDark ? 'text-cyan-400' : 'text-slate-400'}`} />
                    <span className="font-bold text-slate-200">Dark Mode</span>
                    <span className="text-xs text-slate-500 mt-1">NGAO SOC Default</span>
                    {isDark && <CheckCircle className="w-4 h-4 text-cyan-400 mt-3" />}
                  </button>

                  {/* Light Mode Option */}
                  <button
                    onClick={() => toggleTheme(false)}
                    className={`flex flex-col items-center justify-center p-6 border-2 rounded-xl transition-all ${
                      !isDark ? 'border-cyan-500 bg-white' : 'border-slate-200 bg-slate-50 hover:border-slate-300'
                    }`}
                  >
                    <Sun className={`w-8 h-8 mb-3 ${!isDark ? 'text-cyan-500' : 'text-slate-500'}`} />
                    <span className={`font-bold ${!isDark ? 'text-slate-900' : 'text-slate-700'}`}>Light Mode</span>
                    <span className="text-xs text-slate-500 mt-1">High Contrast</span>
                    {!isDark && <CheckCircle className="w-4 h-4 text-cyan-500 mt-3" />}
                  </button>

                </div>
              </div>
            </div>
          )}

          {/* Account & Security Tab */}
          {activeTab === 'account' && (
            <div className="space-y-6 max-w-2xl">
              <div className="glass-panel p-6 rounded-xl border border-slate-800/80 bg-[#0d1520]/80">
                <h2 className="text-sm font-bold uppercase tracking-widest text-slate-300 border-b border-slate-800 pb-3 mb-6 flex items-center gap-2">
                  <Shield className="w-4 h-4 text-cyan-400" />
                  Change Password
                </h2>
                
                {passwordStatus && (
                  <div className={`p-4 mb-6 rounded-lg flex items-center gap-3 border ${
                    passwordStatus.type === 'error' 
                      ? 'bg-rose-500/10 border-rose-500/20 text-rose-400' 
                      : 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'
                  }`}>
                    {passwordStatus.type === 'error' ? <AlertTriangle className="w-5 h-5" /> : <CheckCircle className="w-5 h-5" />}
                    <span className="text-sm font-medium">{passwordStatus.message}</span>
                  </div>
                )}

                <form onSubmit={handleChangePassword} className="space-y-5">
                  <div className="space-y-2">
                    <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Current Password</label>
                    <input
                      type="password"
                      required
                      value={currentPassword}
                      onChange={(e) => setCurrentPassword(e.target.value)}
                      className="w-full bg-[#0a0f1a] border border-slate-700 rounded-lg px-4 py-2.5 text-sm focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors"
                      placeholder="••••••••"
                    />
                  </div>

                  <div className="space-y-2">
                    <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider">New Password</label>
                    <input
                      type="password"
                      required
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      className="w-full bg-[#0a0f1a] border border-slate-700 rounded-lg px-4 py-2.5 text-sm focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors"
                      placeholder="••••••••"
                    />
                  </div>

                  <div className="space-y-2">
                    <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Confirm New Password</label>
                    <input
                      type="password"
                      required
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      className="w-full bg-[#0a0f1a] border border-slate-700 rounded-lg px-4 py-2.5 text-sm focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors"
                      placeholder="••••••••"
                    />
                  </div>

                  <div className="pt-2">
                    <button
                      type="submit"
                      disabled={isLoading}
                      className="bg-cyan-500 hover:bg-cyan-600 disabled:opacity-50 text-[#0a0f1a] font-bold text-xs uppercase tracking-wider px-6 py-3 rounded-lg transition-all flex items-center justify-center gap-2 w-full sm:w-auto"
                    >
                      {isLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Shield className="w-4 h-4" />}
                      Update Password
                    </button>
                  </div>
                </form>
              </div>
            </div>
          )}

          {/* API Integrations Tab (Placeholder) */}
          {activeTab === 'apikeys' && (
            <div className="space-y-6 max-w-3xl">
              <div className="glass-panel p-6 rounded-xl border border-slate-800/80 bg-[#0d1520]/80">
                <h2 className="text-sm font-bold uppercase tracking-widest text-slate-300 border-b border-slate-800 pb-3 mb-6">External Integrations</h2>
                
                <div className="space-y-4">
                  <div className="bg-[#121824] border border-slate-800 rounded-lg p-4 flex items-center justify-between opacity-70">
                    <div>
                      <h4 className="font-bold text-slate-200">VirusTotal API Key</h4>
                      <p className="text-xs text-slate-500 mt-1">Used for enriching IP addresses and file hashes.</p>
                    </div>
                    <button className="px-3 py-1.5 border border-slate-600 text-slate-400 rounded text-xs font-semibold hover:bg-slate-800">Configure</button>
                  </div>

                  <div className="bg-[#121824] border border-slate-800 rounded-lg p-4 flex items-center justify-between opacity-70">
                    <div>
                      <h4 className="font-bold text-slate-200">Qwen AI API Key</h4>
                      <p className="text-xs text-slate-500 mt-1">Required for Threat Hunting DSL generation and Executive Reports.</p>
                    </div>
                    <button className="px-3 py-1.5 border border-slate-600 text-slate-400 rounded text-xs font-semibold hover:bg-slate-800">Configure</button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* System Info Tab */}
          {activeTab === 'system' && (
            <div className="space-y-6 max-w-3xl">
              <div className="glass-panel p-6 rounded-xl border border-slate-800/80 bg-[#0d1520]/80">
                <h2 className="text-sm font-bold uppercase tracking-widest text-slate-300 border-b border-slate-800 pb-3 mb-6">NGAO SOC Platform Details</h2>
                
                <div className="grid grid-cols-2 gap-y-4 gap-x-8 text-sm">
                  <div>
                    <span className="text-slate-500 font-mono text-xs block mb-1">Platform Version</span>
                    <span className="font-bold text-slate-200">v1.2.4 (Syndicate4)</span>
                  </div>
                  <div>
                    <span className="text-slate-500 font-mono text-xs block mb-1">Environment</span>
                    <span className="font-bold text-cyan-400">Production</span>
                  </div>
                  <div>
                    <span className="text-slate-500 font-mono text-xs block mb-1">Backend Framework</span>
                    <span className="font-bold text-slate-200">Django REST Framework</span>
                  </div>
                  <div>
                    <span className="text-slate-500 font-mono text-xs block mb-1">Frontend Core</span>
                    <span className="font-bold text-slate-200">React 18 / Vite</span>
                  </div>
                  <div className="col-span-2 mt-4 pt-4 border-t border-slate-800">
                    <span className="text-slate-500 font-mono text-[10px] uppercase block text-center">Proprietary Technology • Developed for Enterprise SOC</span>
                  </div>
                </div>
              </div>
            </div>
          )}

        </div>
      </div>
    </div>
  );
}
