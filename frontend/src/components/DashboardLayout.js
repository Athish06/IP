import React, { useState, useEffect } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Home,
  FolderGit2,
  Brain,
  LogOut,
  Menu,
  X,
  PanelLeftClose,
  ChevronRight,
  BarChart2,
  Settings,
  AlertTriangle
} from 'lucide-react';
import { useAuthStore } from '../store/authStore';
import { Button } from '../components/ui/button';
import ThemeToggle from './ThemeToggle';

const SharpInfinity = ({ className }) => (
  <svg 
    xmlns="http://www.w3.org/2000/svg" 
    viewBox="0 0 24 24" 
    fill="none" 
    stroke="currentColor" 
    strokeWidth="2" 
    strokeLinecap="square" 
    strokeLinejoin="miter" 
    className={className}
  >
    <path d="M 4 2.5 L 5.5 4 L 4 5.5 L 2.5 4 Z" fill="currentColor" stroke="none" />
    <path d="M 20 18.5 L 21.5 20 L 20 21.5 L 18.5 20 Z" fill="currentColor" stroke="none" />
    <path d="M 9 10.5 L 4 8 L 4 20 L 20 4 L 20 16 L 15 13.5" />
  </svg>
);

const DashboardLayout = ({ children }) => {
  const location = useLocation();
  const navigate = useNavigate();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    const saved = localStorage.getItem('sidebarCollapsed');
    return saved === 'true';
  });
  const logout = useAuthStore((state) => state.logout);
  const user = useAuthStore((state) => state.user);

  useEffect(() => {
    localStorage.setItem('sidebarCollapsed', sidebarCollapsed);
  }, [sidebarCollapsed]);

  // Navigation organized by sections
  const navigationSections = [
    {
      title: '',
      items: [
        { name: 'Dashboard', path: '/dashboard', icon: Home },
      ]
    },
    {
      title: '',
      items: [
        { name: 'Repositories', path: '/repositories', icon: FolderGit2 },
      ]
    },
    {
      title: '',
      items: [
        { name: 'History', path: '/ai-knowledge', icon: Brain },
      ]
    },
    {
      title: '',
      items: [
        { name: 'Benchmark Results', path: '/results', icon: BarChart2 },
      ]
    },
    {
      title: '',
      items: [
        { name: 'Settings', path: '/settings', icon: Settings },
      ]
    }
  ];

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Sidebar */}
      <aside
        className={`fixed left-0 top-0 h-screen bg-card border-r border-border z-40 transition-all duration-300 ease-in-out flex flex-col ${
          sidebarOpen ? 'translate-x-0' : '-translate-x-full'
        } md:translate-x-0 ${sidebarCollapsed ? 'md:w-[72px]' : 'md:w-[260px]'} w-[260px]`}
        data-testid="sidebar"
      >
        {/* Sidebar Header with Logo */}
        <div className={`flex items-center ${sidebarCollapsed ? 'justify-center' : 'justify-between'} h-16 px-4 border-b border-border`}>
          <Link to="/dashboard" className={`flex items-center ${sidebarCollapsed ? '' : 'space-x-3'}`} data-testid="logo">
            <div className="w-8 h-8 bg-primary rounded-lg flex items-center justify-center flex-shrink-0">
              <SharpInfinity className="w-5 h-5 text-primary-foreground" />
            </div>
            {!sidebarCollapsed && (
              <span className="text-lg font-semibold text-foreground">Fixora</span>
            )}
          </Link>
          {!sidebarCollapsed && (
            <button
              onClick={() => setSidebarCollapsed(true)}
              className="hidden md:flex w-8 h-8 items-center justify-center rounded-md text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
              aria-label="Collapse sidebar"
            >
              <PanelLeftClose className="w-4 h-4" />
            </button>
          )}
          {sidebarCollapsed && (
            <button
              onClick={() => setSidebarCollapsed(false)}
              className="hidden md:flex absolute -right-3 top-6 w-6 h-6 bg-card border border-border rounded-full items-center justify-center text-muted-foreground hover:text-foreground transition-colors shadow-sm"
              aria-label="Expand sidebar"
            >
              <ChevronRight className="w-3 h-3" />
            </button>
          )}
        </div>

        {/* Navigation */}
        <nav className="flex-1 overflow-y-auto py-4 px-3">
          {navigationSections.map((section, sectionIndex) => (
            <div key={section.title} className={sectionIndex > 0 ? 'mt-6' : ''}>
              {/* Section Header */}
              {!sidebarCollapsed && section.title && (
                <div className="px-3 mb-2">
                  <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                    {section.title}
                  </span>
                </div>
              )}
              {sidebarCollapsed && sectionIndex > 0 && (
                <div className="mx-3 mb-3 border-t border-border" />
              )}
              
              {/* Section Items */}
              <div className="space-y-1">
                {section.items.map((item) => {
                  const Icon = item.icon;
                  const isActive = location.pathname === item.path;
                  return (
                    <Link
                      key={item.path}
                      to={item.path}
                      className={`group relative flex items-center ${
                        sidebarCollapsed ? 'justify-center px-2' : 'px-3'
                      } py-2.5 rounded-lg transition-all duration-150 ${
                        isActive
                          ? 'bg-primary text-primary-foreground shadow-sm'
                          : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground'
                      }`}
                      onClick={() => setSidebarOpen(false)}
                      data-testid={`nav-${item.name.toLowerCase().replace(' ', '-')}`}
                    >
                      <Icon className={`w-5 h-5 flex-shrink-0 ${isActive ? '' : ''}`} />
                      {!sidebarCollapsed && (
                        <span className="ml-3 text-sm font-medium">{item.name}</span>
                      )}

                      {/* Tooltip for collapsed state */}
                      {sidebarCollapsed && (
                        <div className="absolute left-full ml-3 px-2.5 py-1.5 bg-popover text-popover-foreground text-xs font-medium rounded-md opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all whitespace-nowrap pointer-events-none z-50 shadow-lg border border-border">
                          {item.name}
                        </div>
                      )}
                    </Link>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>

        {/* Sidebar Footer - User Info (visible when expanded) */}
        {!sidebarCollapsed && (
          <div className="mt-auto border-t border-border p-4">
            <div className="flex items-center space-x-3">
              <div className="w-9 h-9 bg-primary/10 rounded-full flex items-center justify-center text-primary font-medium text-sm flex-shrink-0">
                {user?.full_name?.charAt(0)?.toUpperCase() || 'U'}
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-foreground truncate">
                  {user?.full_name || 'User'}
                </p>
              </div>
            </div>
          </div>
        )}
      </aside>

      {/* Header */}
      <header className={`fixed top-0 right-0 z-30 bg-background/95 backdrop-blur-sm border-b border-border transition-all duration-300 ${
        sidebarCollapsed ? 'md:left-[72px]' : 'md:left-[260px]'
      } left-0`}>
        <div className="flex items-center justify-between h-16 px-4 md:px-6">
          <div className="flex items-center space-x-3">
            <button
              onClick={() => setSidebarOpen(!sidebarOpen)}
              className="md:hidden p-2 rounded-lg hover:bg-accent transition-colors"
              data-testid="mobile-menu-button"
            >
              {sidebarOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
            {/* Mobile logo */}
            <Link to="/dashboard" className="flex items-center space-x-2 md:hidden" data-testid="mobile-logo">
              <div className="w-8 h-8 bg-primary rounded-lg flex items-center justify-center">
                <span className="text-primary-foreground font-bold text-base">F</span>
              </div>
              <span className="text-lg font-semibold">Fixora</span>
            </Link>
          </div>
          <div className="flex items-center space-x-2">
            <ThemeToggle />
            <Button
              variant="ghost"
              size="sm"
              onClick={handleLogout}
              className="text-muted-foreground hover:text-foreground"
              data-testid="logout-button"
            >
              <LogOut className="w-4 h-4 md:mr-2" />
              <span className="hidden md:inline">Logout</span>
            </Button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className={`pt-16 min-h-screen transition-all duration-300 ease-in-out ${
        sidebarCollapsed ? 'md:ml-[72px]' : 'md:ml-[260px]'
      }`}>
        <div className="p-4 md:p-6 lg:p-8">
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3, ease: 'easeOut' }}
          >
            {/* API Key Warning Banner */}
            {user && !user.has_groq_key && (
              <div className="mb-4 rounded-lg border border-yellow-500/30 bg-yellow-500/5 p-4 flex items-start gap-3">
                <AlertTriangle className="w-5 h-5 text-yellow-500 flex-shrink-0 mt-0.5" />
                <div className="flex-1">
                  <p className="text-sm font-medium text-foreground">Groq API Key Required</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    You need to configure your Groq API key to run security scans.{' '}
                    <a href="/settings" className="text-primary hover:underline font-medium">Go to Settings →</a>
                  </p>
                </div>
              </div>
            )}
            {children}
          </motion.div>
        </div>
      </main>

      {/* Mobile overlay */}
      <AnimatePresence>
        {sidebarOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="fixed inset-0 bg-black/50 z-30 md:hidden"
            onClick={() => setSidebarOpen(false)}
          />
        )}
      </AnimatePresence>
    </div>
  );
};

export default DashboardLayout;