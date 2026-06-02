"use client";

import { useAuth } from "@/contexts/auth-context";
import { useEffect, ReactNode } from "react";
import { useRouter, usePathname } from "next/navigation";
import { Loader2 } from "lucide-react";

interface AuthGuardProps {
  children: ReactNode;
}

// Routes reachable without an established session: the login page and the
// OIDC callback (which establishes the session from the URL fragment).
const PUBLIC_PATHS = ["/login", "/auth/callback"];

export function AuthGuard({ children }: AuthGuardProps) {
  const { isAuthenticated, isLoading } = useAuth();
  const router = useRouter();
  const pathname = usePathname();
  const isPublic = PUBLIC_PATHS.includes(pathname);

  useEffect(() => {
    if (!isLoading && !isAuthenticated && !isPublic) {
      router.replace("/login");
    }
  }, [isAuthenticated, isLoading, isPublic, router]);

  // Show loading spinner while checking auth
  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  // Allow public routes (login / OIDC callback) without auth
  if (isPublic) {
    return <>{children}</>;
  }

  // Block content if not authenticated
  if (!isAuthenticated) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return <>{children}</>;
}
