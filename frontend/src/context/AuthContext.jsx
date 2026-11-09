import React, { createContext, useContext, useState, useEffect } from 'react';
import { api } from '../api/client';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    try {
      const saved = localStorage.getItem('cloudguard_user');
      return saved ? JSON.parse(saved) : null;
    } catch {
      return null;
    }
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const handleUnauthorized = () => {
      setUser(null);
    };
    window.addEventListener('cloudguard:unauthorized', handleUnauthorized);

    const token = localStorage.getItem('cloudguard_token');
    if (token) {
      api.getMe()
        .then((res) => {
          if (res.data?.user) {
            setUser(res.data.user);
            localStorage.setItem('cloudguard_user', JSON.stringify(res.data.user));
          }
        })
        .catch(() => {
          localStorage.removeItem('cloudguard_token');
          localStorage.removeItem('cloudguard_user');
          setUser(null);
        })
        .finally(() => setLoading(false));
    } else {
      setLoading(false);
    }

    return () => {
      window.removeEventListener('cloudguard:unauthorized', handleUnauthorized);
    };
  }, []);

  const login = async (email, password) => {
    const res = await api.login(email, password);
    const userData = res.data.user;
    const token = res.data.token;
    localStorage.setItem('cloudguard_token', token);
    localStorage.setItem('cloudguard_user', JSON.stringify(userData));
    setUser(userData);
    return userData;
  };

  const register = async (name, email, password) => {
    const res = await api.register(name, email, password);
    const userData = res.data.user;
    const token = res.data.token;
    localStorage.setItem('cloudguard_token', token);
    localStorage.setItem('cloudguard_user', JSON.stringify(userData));
    setUser(userData);
    return userData;
  };

  const logout = async () => {
    try {
      await api.logout();
    } catch {
      // Ignore logout errors
    } finally {
      localStorage.removeItem('cloudguard_token');
      localStorage.removeItem('cloudguard_user');
      setUser(null);
    }
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

