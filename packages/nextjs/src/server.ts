import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { verifyJwt } from "@bolkauth/core";
import * as React from "react";

// Safe wrapper for React cache() to deduplicate session/user lookups within a single render tree
const safeCache = <T extends (...args: any[]) => any>(fn: T): T => {
  try {
    const cacheFn = Reflect.get(React, "cache");
    if (typeof cacheFn === "function") {
      return cacheFn(fn);
    }
  } catch {
    // Fallback if cache is not available
  }
  return fn;
};

export function createServerHelpers(authInstance: { config: { secret: string; session?: { cookieName?: string }; adapter?: any } }) {
  const getSession = safeCache(async () => {
    const cookieStore = await cookies();
    const cookieName = authInstance.config.session?.cookieName ?? "bolkauth.session";
    const jwt = cookieStore.get(cookieName)?.value || cookieStore.get("authflow.session")?.value;
    if (!jwt) return null;
    try {
      const payload = (await verifyJwt(jwt, authInstance.config.secret)) as { sessionId: string; userId: string };
      if (!payload || !payload.sessionId || !payload.userId) return null;
      return { id: payload.sessionId, userId: payload.userId, token: jwt };
    } catch {
      return null;
    }
  });

  const getUser = safeCache(async () => {
    const session = await getSession();
    if (!session || !authInstance.config.adapter) return null;
    return await authInstance.config.adapter.findUserById(session.userId);
  });

  const requireAuth = async (signInUrl = "/sign-in") => {
    const user = await getUser();
    if (!user) redirect(signInUrl);
    return user;
  };

  return {
    getSession,
    getUser,
    requireAuth,
  };
}

export const getSession = safeCache(async () => {
  const cookieStore = await cookies();
  const jwt = cookieStore.get("bolkauth.session")?.value || cookieStore.get("authflow.session")?.value;
  if (!jwt) return null;

  const secret = process.env.BOLKAUTH_SECRET;
  if (!secret) {
    throw new Error("BOLKAUTH_SECRET is not set. A secret is required to verify session tokens.");
  }

  try {
    const payload = (await verifyJwt(jwt, secret)) as { sessionId: string; userId: string };
    if (!payload || !payload.sessionId || !payload.userId) return null;
    return { id: payload.sessionId, userId: payload.userId, token: jwt };
  } catch {
    return null;
  }
});

export const getUser = safeCache(async () => {
  const session = await getSession();
  if (!session) return null;
  return null;
});

export async function requireAuth(signInUrl = "/sign-in") {
  const user = await getUser();
  if (!user) redirect(signInUrl);
  return user;
}

