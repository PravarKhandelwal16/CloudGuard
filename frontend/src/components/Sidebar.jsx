import React from 'react';
import { Shield, LayoutDashboard, PlusCircle, History, LogOut, User, Cloud } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export function Sidebar({ currentTab, setTab }) {
  const { user, logout } = useAuth();

  const navItems = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'new-scan', label: 'New Scan', icon: PlusCircle },
    { id: 'history', label: 'Scan History', icon: History },
    { id: 'cloud-security', label: 'Cloud Security', icon: Cloud },
  ];

  return (
    <aside className="app-sidebar">
      <div className="sidebar-brand">
        <div className="brand-logo">
          <Shield size={24} color="#2563eb" />
        </div>
        <div>
          <span className="brand-title">CloudGuard</span>
          <span className="brand-tag">v1.0</span>
        </div>
      </div>

      <nav className="sidebar-nav">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentTab === item.id;
          return (
            <button
              key={item.id}
              className={`nav-button ${isActive ? 'active' : ''}`}
              onClick={() => setTab(item.id)}
            >
              <Icon size={18} />
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>

      <div className="sidebar-footer">
        <div className="user-profile">
          <div className="user-avatar">
            <User size={16} />
          </div>
          <div className="user-details">
            <span className="user-name">{user?.name || 'Developer'}</span>
            <span className="user-email">{user?.email}</span>
          </div>
        </div>
        <button className="logout-button" onClick={logout} title="Sign Out">
          <LogOut size={16} />
          <span>Logout</span>
        </button>
      </div>
    </aside>
  );
}

