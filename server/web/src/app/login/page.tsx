"use client";

import { useState, FormEvent, useEffect, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useTranslations } from "next-intl";
import { useAuth } from "@/contexts/auth-context";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { ShieldAlert, Eye, EyeOff, Loader2, LogIn } from "lucide-react";

// useSearchParams() must run inside a Suspense boundary (Next.js build rule).
export default function LoginPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen flex items-center justify-center">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      }
    >
      <LoginForm />
    </Suspense>
  );
}

function LoginForm() {
  const [token, setToken] = useState("");
  const [showToken, setShowToken] = useState(false);
  const [error, setError] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  // null = still discovering which login method the backend offers.
  const [oidcEnabled, setOidcEnabled] = useState<boolean | null>(null);

  const { login, loginWithOIDC, isAuthenticated, isLoading } = useAuth();
  const router = useRouter();
  const searchParams = useSearchParams();
  const t = useTranslations("login");

  // Discover available login method (PocketID vs. token).
  useEffect(() => {
    fetch("/api/auth/config")
      .then((res) => (res.ok ? res.json() : { oidcEnabled: false }))
      .then((cfg) => setOidcEnabled(!!cfg.oidcEnabled))
      .catch(() => setOidcEnabled(false));
  }, []);

  // Error handed back by the OIDC callback (e.g. ?error=forbidden), derived
  // during render so we don't setState inside an effect.
  const urlErrorCode = searchParams.get("error");
  const urlError = urlErrorCode === "forbidden"
    ? t("errorForbidden")
    : urlErrorCode === "session"
      ? t("errorSession")
      : urlErrorCode
        ? t("errorAuth")
        : "";
  const displayError = error || urlError;

  // Redirect if already authenticated
  useEffect(() => {
    if (!isLoading && isAuthenticated) {
      router.replace("/dashboard");
    }
  }, [isAuthenticated, isLoading, router]);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    setIsSubmitting(true);

    // Verify token against API
    try {
      const res = await fetch("/api/stats", {
        headers: { "Authorization": `Bearer ${token}` },
      });
      if (res.ok) {
        login(token);
        router.replace("/dashboard");
      } else {
        setError(t("errorInvalidToken"));
        setIsSubmitting(false);
      }
    } catch {
      setError(t("errorConnection"));
      setIsSubmitting(false);
    }
  };

  if (isLoading || oidcEnabled === null) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-background to-muted p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="mx-auto mb-4 p-3 rounded-full bg-primary/10 w-fit">
            <ShieldAlert className="h-8 w-8 text-primary" />
          </div>
          <CardTitle className="text-2xl">{t("title")}</CardTitle>
          <CardDescription>{oidcEnabled ? t("oidcDescription") : t("description")}</CardDescription>
        </CardHeader>
        <CardContent>
          {displayError && (
            <div className="mb-4 p-3 rounded-md bg-destructive/10 text-destructive text-sm">
              {displayError}
            </div>
          )}

          {oidcEnabled ? (
            <Button className="w-full" onClick={loginWithOIDC}>
              <LogIn className="mr-2 h-4 w-4" />
              {t("oidcButton")}
            </Button>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="token">{t("tokenLabel")}</Label>
                <div className="relative">
                  <Input
                    id="token"
                    type={showToken ? "text" : "password"}
                    placeholder={t("tokenPlaceholder")}
                    value={token}
                    onChange={(e) => setToken(e.target.value)}
                    disabled={isSubmitting}
                    autoComplete="off"
                    autoFocus
                    className="pr-10"
                  />
                  <button
                    type="button"
                    onClick={() => setShowToken(!showToken)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
                    tabIndex={-1}
                  >
                    {showToken ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
              </div>

              <Button
                type="submit"
                className="w-full"
                disabled={isSubmitting || !token}
              >
                {isSubmitting ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    {t("submitting")}
                  </>
                ) : (
                  t("submit")
                )}
              </Button>
            </form>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
