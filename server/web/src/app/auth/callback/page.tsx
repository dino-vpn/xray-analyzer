"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/contexts/auth-context";
import { Loader2 } from "lucide-react";

// Landing page for the OIDC redirect. The backend appends the freshly-minted
// session token in the URL fragment (#token=…) so it never reaches a server or
// the Referer header. We read it client-side, store it, and head to the
// dashboard. Missing token → bounce back to login with an error.
export default function AuthCallbackPage() {
  const { login } = useAuth();
  const router = useRouter();

  useEffect(() => {
    const params = new URLSearchParams(window.location.hash.replace(/^#/, ""));
    const token = params.get("token");
    if (token && login(token)) {
      router.replace("/dashboard");
    } else {
      router.replace("/login?error=auth");
    }
  }, [login, router]);

  return (
    <div className="min-h-screen flex items-center justify-center">
      <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
    </div>
  );
}
