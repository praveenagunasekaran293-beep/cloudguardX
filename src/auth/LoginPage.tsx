import React, { useState } from "react";

interface LoginPageProps {
  onLogin: () => void;
}

export function LoginPage({ onLogin }: LoginPageProps) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError("");

    if (!email.trim() || !password.trim()) {
      setError("Please enter your email and password.");
      return;
    }

    // Demo-only login validation. Replace with backend authentication.
    if (email.trim().toLowerCase() === "admin@cybersentinel.com" && password === "Cyber@123") {
      onLogin();
    } else {
      setError("Invalid email or password.");
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950 px-4 py-10 text-slate-100">
      <div className="w-full max-w-md">
        <div className="mb-8 text-center">
          <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-2xl border border-cyan-400/30 bg-cyan-400/10 text-cyan-300">
            <svg
              viewBox="0 0 24 24"
              className="h-9 w-9"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.7"
              aria-hidden="true"
            >
              <path d="M12 2.5 20 6v5.5c0 5-3.4 8.4-8 10-4.6-1.6-8-5-8-10V6l8-3.5Z" />
              <path d="m8.5 12 2.2 2.2 4.8-5" />
            </svg>
          </div>
          <h1 className="text-3xl font-bold tracking-tight">
            Cyber<span className="text-cyan-400">Sentinel X</span>
          </h1>
          <p className="mt-2 text-sm text-slate-400">
            Cloud-Based Cybersecurity Monitoring and Incident Intelligence Platform

          </p>
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-7 shadow-2xl shadow-black/30">
          <div className="mb-6">
            <h2 className="text-xl font-semibold">Welcome back</h2>
            <p className="mt-1 text-sm text-slate-400">
              Sign in to access your security operations dashboard.
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label htmlFor="email" className="mb-2 block text-sm font-medium text-slate-300">
                Email address
              </label>
              <input
                id="email"
                type="email"
                autoComplete="username"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="admin@cybersentinel.com"
                className="w-full rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-sm text-white outline-none transition placeholder:text-slate-600 focus:border-cyan-400 focus:ring-2 focus:ring-cyan-400/20"
              />
            </div>

            <div>
              <label htmlFor="password" className="mb-2 block text-sm font-medium text-slate-300">
                Password
              </label>
              <div className="relative">
                <input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your password"
                  className="w-full rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 pr-16 text-sm text-white outline-none transition placeholder:text-slate-600 focus:border-cyan-400 focus:ring-2 focus:ring-cyan-400/20"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((value) => !value)}
                  className="absolute inset-y-0 right-3 text-xs font-medium text-cyan-400 hover:text-cyan-300"
                >
                  {showPassword ? "Hide" : "Show"}
                </button>
              </div>
            </div>

            {error && (
              <p role="alert" className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-300">
                {error}
              </p>
            )}

            <button
              type="submit"
              className="w-full rounded-xl bg-cyan-500 px-4 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400 focus:outline-none focus:ring-2 focus:ring-cyan-300 focus:ring-offset-2 focus:ring-offset-slate-900"
            >
              Sign in
            </button>
          </form>

          <div className="mt-6 rounded-xl border border-slate-800 bg-slate-950/70 p-3">
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
              Demo credentials
            </p>
            <p className="mt-2 text-sm text-slate-300">
              Email: <span className="text-cyan-300">admin@cybersentinel.com</span>
            </p>
            <p className="mt-1 text-sm text-slate-300">
              Password: <span className="text-cyan-300">Cyber@123</span>
            </p>
          </div>
        </div>

        <p className="mt-6 text-center text-xs text-slate-600">
          CyberSentinel X · Security Operations Platform
        </p>
      </div>
    </div>
  );
}
