"use client";

import React, { createContext, useContext, useState, useEffect, useCallback, ReactNode } from "react";

interface SessionUser {
  sub: string;
  name?: string;
  email?: string;
  groups?: string[];
}

interface AuthContextValue {
  isAuthenticated: boolean;
  isLoading: boolean;
  token: string;
  user: SessionUser | null;
  login: (token: string) => boolean;
  logout: () => void;
  // Kick off the OIDC (PocketID) login by redirecting to the backend.
  loginWithOIDC: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

// Session storage key
const AUTH_KEY = "xray_auth_token";

// decodeSession parses the (unverified) JWT payload. Used only client-side to
// read display info and drop tokens that are already expired — the backend
// always re-verifies the signature, so this is presentation-only.
function decodeSession(token: string): (SessionUser & { exp?: number }) | null {
  try {
    const payload = token.split(".")[1];
    if (!payload) return null;
    const json = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
    return JSON.parse(json);
  } catch {
    return null;
  }
}

function isExpired(claims: { exp?: number } | null): boolean {
  return !!claims?.exp && Date.now() >= claims.exp * 1000;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [token, setToken] = useState("");
  const [user, setUser] = useState<SessionUser | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Check session on mount
  useEffect(() => {
    try {
      const stored = localStorage.getItem(AUTH_KEY);
      if (stored) {
        const claims = decodeSession(stored);
        // Drop a stale token so we don't render a dashboard that 401s.
        if (isExpired(claims)) {
          localStorage.removeItem(AUTH_KEY);
        } else {
          setToken(stored);
          setUser(claims);
          setIsAuthenticated(true);
        }
      }
    } catch {
      localStorage.removeItem(AUTH_KEY);
    }
    setIsLoading(false);
  }, []);

  const login = useCallback((inputToken: string): boolean => {
    if (inputToken) {
      localStorage.setItem(AUTH_KEY, inputToken);
      setToken(inputToken);
      setUser(decodeSession(inputToken));
      setIsAuthenticated(true);
      return true;
    }
    return false;
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem(AUTH_KEY);
    setToken("");
    setUser(null);
    setIsAuthenticated(false);
  }, []);

  const loginWithOIDC = useCallback(() => {
    window.location.href = "/api/auth/login";
  }, []);

  return (
    <AuthContext.Provider value={{ isAuthenticated, isLoading, token, user, login, logout, loginWithOIDC }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}

// Helper to get token for fetch calls (works outside React components)
export function getAuthToken(): string {
  if (typeof window === "undefined") return "";
  return localStorage.getItem(AUTH_KEY) || "";
}

// Authenticated fetch helper
export async function authFetch(url: string, options?: RequestInit): Promise<Response> {
  const token = getAuthToken();
  const headers = new Headers(options?.headers);
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  return fetch(url, { ...options, headers });
}
