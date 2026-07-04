import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Key, Eye, EyeOff, CheckCircle, AlertTriangle, Trash2, ExternalLink, Shield, Loader2 } from 'lucide-react';
import DashboardLayout from '../components/DashboardLayout';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { api } from '../services/api';
import { useAuthStore } from '../store/authStore';
import { toast } from 'sonner';

const Settings = () => {
  const user = useAuthStore((state) => state.user);
  const fetchUser = useAuthStore((state) => state.fetchUser);

  const [apiKey, setApiKey] = useState('');
  const [showKey, setShowKey] = useState(false);
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const hasKey = user?.has_groq_key || false;

  const handleSave = async () => {
    const trimmed = apiKey.trim();
    if (!trimmed) {
      toast.error('Please enter your Groq API key');
      return;
    }
    if (!trimmed.startsWith('gsk_')) {
      toast.error('Invalid key format. Groq API keys start with "gsk_"');
      return;
    }

    setSaving(true);
    try {
      await api.saveGroqKey(trimmed);
      toast.success('Groq API key saved securely!');
      setApiKey('');
      setShowKey(false);
      // Refresh user data so has_groq_key updates globally
      await fetchUser();
    } catch (err) {
      toast.error(err?.response?.data?.detail || 'Failed to save API key');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    setDeleting(true);
    try {
      await api.deleteGroqKey();
      toast.success('Groq API key removed');
      // Refresh user data
      await fetchUser();
    } catch (err) {
      toast.error(err?.response?.data?.detail || 'Failed to remove API key');
    } finally {
      setDeleting(false);
    }
  };

  return (
    <DashboardLayout>
      <div className="max-w-2xl mx-auto space-y-6">
        {/* Page Header */}
        <div>
          <h1 className="text-2xl font-bold text-foreground">Settings</h1>
          <p className="text-muted-foreground mt-1">Manage your account configuration</p>
        </div>

        {/* Groq API Key Card */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
        >
          <Card className="border-border">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
                    <Key className="w-5 h-5 text-primary" />
                  </div>
                  <div>
                    <CardTitle className="text-lg">Groq API Key</CardTitle>
                    <CardDescription>Required for AI-powered vulnerability analysis</CardDescription>
                  </div>
                </div>
                {hasKey ? (
                  <Badge variant="default" className="bg-green-500/10 text-green-500 border-green-500/20 gap-1">
                    <CheckCircle className="w-3 h-3" />
                    Configured
                  </Badge>
                ) : (
                  <Badge variant="destructive" className="gap-1">
                    <AlertTriangle className="w-3 h-3" />
                    Not Set
                  </Badge>
                )}
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Info Box */}
              <div className="rounded-lg border border-border bg-muted/30 p-4 space-y-2">
                <div className="flex items-start gap-2">
                  <Shield className="w-4 h-4 text-primary mt-0.5 flex-shrink-0" />
                  <div className="text-sm text-muted-foreground space-y-1">
                    <p>
                      Fixora uses <strong className="text-foreground">Groq</strong> (free, no credit card required) to power its AI vulnerability analysis engine.
                    </p>
                    <p>
                      Your key is encrypted with <strong className="text-foreground">AES-128 (Fernet)</strong> before storage. We never store plaintext keys.
                    </p>
                  </div>
                </div>
              </div>

              {/* Get Key Link */}
              <a
                href="https://console.groq.com/keys"
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-2 text-sm text-primary hover:underline"
              >
                <ExternalLink className="w-3.5 h-3.5" />
                Get your free API key from console.groq.com
              </a>

              {/* Input Section */}
              <div className="space-y-3">
                <label className="text-sm font-medium text-foreground">
                  {hasKey ? 'Update your Groq API key' : 'Enter your Groq API key'}
                </label>
                <div className="flex gap-2">
                  <div className="relative flex-1">
                    <input
                      type={showKey ? 'text' : 'password'}
                      value={apiKey}
                      onChange={(e) => setApiKey(e.target.value)}
                      placeholder="gsk_..."
                      className="w-full h-10 rounded-md border border-input bg-background px-3 pr-10 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 focus:ring-offset-background"
                      onKeyDown={(e) => e.key === 'Enter' && handleSave()}
                      data-testid="groq-key-input"
                    />
                    <button
                      type="button"
                      onClick={() => setShowKey(!showKey)}
                      className="absolute right-2 top-1/2 -translate-y-1/2 p-1 text-muted-foreground hover:text-foreground transition-colors"
                    >
                      {showKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                  <Button
                    onClick={handleSave}
                    disabled={saving || !apiKey.trim()}
                    className="min-w-[80px]"
                    data-testid="save-groq-key"
                  >
                    {saving ? (
                      <Loader2 className="w-4 h-4 animate-spin" />
                    ) : (
                      hasKey ? 'Update' : 'Save'
                    )}
                  </Button>
                </div>
                <p className="text-xs text-muted-foreground">
                  Only Groq API keys are supported. Keys must start with <code className="bg-muted px-1 rounded">gsk_</code>
                </p>
              </div>

              {/* Delete Section */}
              {hasKey && (
                <div className="pt-3 border-t border-border">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium text-foreground">Remove API Key</p>
                      <p className="text-xs text-muted-foreground mt-0.5">
                        This will prevent scans from running until a new key is added
                      </p>
                    </div>
                    <Button
                      variant="destructive"
                      size="sm"
                      onClick={handleDelete}
                      disabled={deleting}
                      data-testid="delete-groq-key"
                    >
                      {deleting ? (
                        <Loader2 className="w-4 h-4 animate-spin" />
                      ) : (
                        <>
                          <Trash2 className="w-4 h-4 mr-1" />
                          Remove
                        </>
                      )}
                    </Button>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </motion.div>

        {/* Account Info Card */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.1 }}
        >
          <Card className="border-border">
            <CardHeader>
              <CardTitle className="text-lg">Account</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex items-center justify-between py-2">
                <span className="text-sm text-muted-foreground">Email</span>
                <span className="text-sm font-medium text-foreground">{user?.email || '—'}</span>
              </div>
              <div className="flex items-center justify-between py-2 border-t border-border">
                <span className="text-sm text-muted-foreground">Name</span>
                <span className="text-sm font-medium text-foreground">{user?.full_name || '—'}</span>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </div>
    </DashboardLayout>
  );
};

export default Settings;
