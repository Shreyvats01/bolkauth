import { describe, it, expect, vi, beforeEach } from "vitest";
import { signJwt } from "@bolkauth/core";
import { createServerHelpers, getSession, getUser, requireAuth } from "../server";

const mockCookiesStore = {
  get: vi.fn(),
};

vi.mock("next/headers", () => ({
  cookies: vi.fn(async () => mockCookiesStore),
}));

vi.mock("next/navigation", () => ({
  redirect: vi.fn((url: string) => {
    throw new Error(`NEXT_REDIRECT:${url}`);
  }),
}));

const cacheMap = new Map<any, any>();

vi.mock("react", async () => {
  const actual = await vi.importActual<typeof import("react")>("react");
  return {
    ...actual,
    cache: vi.fn((fn: any) => {
      return async (...args: any[]) => {
        if (!cacheMap.has(fn)) {
          cacheMap.set(fn, await fn(...args));
        }
        return cacheMap.get(fn);
      };
    }),
  };
});

describe("createServerHelpers", () => {
  const secret = "server-helpers-secret-key-12345";
  let mockAdapter: { findUserById: ReturnType<typeof vi.fn> };
  let authInstance: any;

  beforeEach(() => {
    cacheMap.clear();
    vi.clearAllMocks();
    mockAdapter = {
      findUserById: vi.fn().mockResolvedValue({ id: "usr_100", email: "alice@example.com" }),
    };
    authInstance = {
      config: {
        secret,
        session: {
          cookieName: "bolkauth.session",
        },
        adapter: mockAdapter,
      },
    };
  });

  describe("getSession", () => {
    it("returns null if no session cookie exists", async () => {
      mockCookiesStore.get.mockReturnValue(undefined);
      const helpers = createServerHelpers(authInstance);

      const session = await helpers.getSession();
      expect(session).toBeNull();
    });

    it("returns session object for valid JWT token", async () => {
      const token = await signJwt({ sessionId: "sess_100", userId: "usr_100" }, secret);
      mockCookiesStore.get.mockReturnValue({ value: token });

      const helpers = createServerHelpers(authInstance);
      const session = await helpers.getSession();

      expect(session).toEqual({
        id: "sess_100",
        userId: "usr_100",
        token,
      });
    });

    it("returns null for invalid or corrupted JWT token", async () => {
      mockCookiesStore.get.mockReturnValue({ value: "invalid.jwt.token" });
      const helpers = createServerHelpers(authInstance);

      const session = await helpers.getSession();
      expect(session).toBeNull();
    });

    it("supports custom session cookie name configured in authInstance", async () => {
      const customAuth = {
        config: {
          secret,
          session: { cookieName: "my_custom_session" },
        },
      };
      const token = await signJwt({ sessionId: "sess_200", userId: "usr_200" }, secret);
      mockCookiesStore.get.mockImplementation((name: string) => {
        if (name === "my_custom_session") return { value: token };
        return undefined;
      });

      const helpers = createServerHelpers(customAuth);
      const session = await helpers.getSession();

      expect(session).toEqual({
        id: "sess_200",
        userId: "usr_200",
        token,
      });
    });
  });

  describe("getUser", () => {
    it("returns user from adapter when session is valid", async () => {
      const token = await signJwt({ sessionId: "sess_100", userId: "usr_100" }, secret);
      mockCookiesStore.get.mockReturnValue({ value: token });

      const helpers = createServerHelpers(authInstance);
      const user = await helpers.getUser();

      expect(user).toEqual({ id: "usr_100", email: "alice@example.com" });
      expect(mockAdapter.findUserById).toHaveBeenCalledWith("usr_100");
    });

    it("returns null if session is invalid or missing", async () => {
      mockCookiesStore.get.mockReturnValue(undefined);

      const helpers = createServerHelpers(authInstance);
      const user = await helpers.getUser();

      expect(user).toBeNull();
      expect(mockAdapter.findUserById).not.toHaveBeenCalled();
    });

    it("returns null if no adapter is configured", async () => {
      const token = await signJwt({ sessionId: "sess_100", userId: "usr_100" }, secret);
      mockCookiesStore.get.mockReturnValue({ value: token });

      const helpers = createServerHelpers({ config: { secret } });
      const user = await helpers.getUser();

      expect(user).toBeNull();
    });
  });

  describe("requireAuth", () => {
    it("returns user when user is authenticated", async () => {
      const token = await signJwt({ sessionId: "sess_100", userId: "usr_100" }, secret);
      mockCookiesStore.get.mockReturnValue({ value: token });

      const helpers = createServerHelpers(authInstance);
      const user = await helpers.requireAuth();

      expect(user).toEqual({ id: "usr_100", email: "alice@example.com" });
    });

    it("redirects to signInUrl when user is not authenticated", async () => {
      mockCookiesStore.get.mockReturnValue(undefined);
      const { redirect } = await import("next/navigation");

      const helpers = createServerHelpers(authInstance);

      await expect(helpers.requireAuth("/custom-sign-in")).rejects.toThrow("NEXT_REDIRECT:/custom-sign-in");
      expect(redirect).toHaveBeenCalledWith("/custom-sign-in");
    });
  });

  describe("React cache() request deduplication", () => {
    it("deduplicates getSession and getUser calls across multiple invocations", async () => {
      const token = await signJwt({ sessionId: "sess_dedup", userId: "usr_dedup" }, secret);
      mockCookiesStore.get.mockReturnValue({ value: token });

      const helpers = createServerHelpers(authInstance);

      // Multiple calls to getSession
      const session1 = await helpers.getSession();
      const session2 = await helpers.getSession();
      const session3 = await helpers.getSession();

      expect(session1).toBe(session2);
      expect(session2).toBe(session3);

      // Multiple calls to getUser
      const user1 = await helpers.getUser();
      const user2 = await helpers.getUser();

      expect(user1).toBe(user2);
      expect(mockAdapter.findUserById).toHaveBeenCalledTimes(1);
    });
  });
});

describe("standalone getSession, getUser, and requireAuth exports", () => {
  beforeEach(() => {
    cacheMap.clear();
    vi.clearAllMocks();
  });

  it("standalone getSession returns null when cookie is missing", async () => {
    mockCookiesStore.get.mockReturnValue(undefined);
    const session = await getSession();
    expect(session).toBeNull();
  });

  it("standalone getSession throws error when BOLKAUTH_SECRET is not set", async () => {
    mockCookiesStore.get.mockReturnValue({ value: "some-jwt-token" });
    const originalSecret = process.env.BOLKAUTH_SECRET;
    delete process.env.BOLKAUTH_SECRET;

    await expect(getSession()).rejects.toThrow("BOLKAUTH_SECRET is not set. A secret is required to verify session tokens.");

    process.env.BOLKAUTH_SECRET = originalSecret;
  });

  it("standalone getSession returns session when cookie exists and secret is set", async () => {
    const secret = "test-secret-key-12345";
    const originalSecret = process.env.BOLKAUTH_SECRET;
    process.env.BOLKAUTH_SECRET = secret;
    const token = await signJwt({ sessionId: "session", userId: "user" }, secret);

    mockCookiesStore.get.mockImplementation((name: string) => {
      if (name === "bolkauth.session") return { value: token };
      return undefined;
    });

    const session = await getSession();
    expect(session).toEqual({
      id: "session",
      userId: "user",
      token,
    });

    process.env.BOLKAUTH_SECRET = originalSecret;
  });

  it("standalone getUser returns null when session exists but no adapter attached", async () => {
    const secret = "test-secret-key-12345";
    const originalSecret = process.env.BOLKAUTH_SECRET;
    process.env.BOLKAUTH_SECRET = secret;
    const token = await signJwt({ sessionId: "session", userId: "user" }, secret);

    mockCookiesStore.get.mockImplementation((name: string) => {
      if (name === "bolkauth.session") return { value: token };
      return undefined;
    });

    const user = await getUser();
    expect(user).toBeNull(); // Default standalone has no adapter attached

    process.env.BOLKAUTH_SECRET = originalSecret;
  });

  it("standalone requireAuth redirects when user is null", async () => {
    mockCookiesStore.get.mockReturnValue(undefined);
    const { redirect } = await import("next/navigation");

    await expect(requireAuth()).rejects.toThrow("NEXT_REDIRECT:/sign-in");
    expect(redirect).toHaveBeenCalledWith("/sign-in");
  });
});
