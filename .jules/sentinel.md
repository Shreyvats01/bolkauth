## 2026-08-16 - [Hardcoded JWT Secret Fallback in Nextjs Standalone Helper]
**Vulnerability:** A hardcoded development fallback for BOLKAUTH_SECRET was used if the environment variable was not set, allowing potential attackers to forge JWT tokens if the application was deployed to production without the secret defined.
**Learning:** Developers can easily miss environment variables in production. Providing a fallback secret gives a false sense of security while leaving the application fundamentally broken from a security perspective.
**Prevention:** Always fail securely by throwing an explicit, helpful error when essential security configuration variables like JWT signing keys are missing.
