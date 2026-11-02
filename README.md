# Security & Authentication Capstone — ASP.NET Core Order API

ASP.NET Core Web API built for the Coursera course *Security and Authentication with Microsoft Copilot* (capstone).

## Features

- **ASP.NET Core Identity** for authentication (hardened password policy, lockout, username character whitelist)
- **JWT bearer authentication** with fully validated claims, 15-minute access tokens, HMAC-SHA256, ClockSkew zero
- **Role-based authorization** (Admin, Manager, User) plus claims-based policies on every endpoint
- **Data Protection API** with a dedicated key ring and a persisted key path
- **HTTPS enforced** (HSTS + HTTPS redirection), generic RFC 7807 error responses, no stack-trace leakage
- **Rate limiting** on the login endpoint (5/min per IP) to block brute-force, 120/min for the API
- **Injection-safe persistence**: parameterized EF Core queries only, no string SQL anywhere
- **Static data masking** for card data before it reaches logs or storage

## Security review — vulnerabilities identified and fixes applied

1. Plaintext connection string and JWT signing key in appsettings.json -> moved to environment variables; the signing key never lives in source.
2. Weak password hashing (MD5-style) -> switched to ASP.NET Identity PasswordHasher (PBKDF2 / HMAC-SHA512 with per-user salt).
3. JWT validated without checking signature or lifetime -> TokenValidationParameters with ValidateIssuer, ValidateAudience, ValidateLifetime, RequireSignedTokens and ClockSkew = 0.
4. IDOR on GET /orders/{id} (role-only check) -> policy-based ownership assertion (sub == order owner) in addition to the role check.
5. No rate limiting on /auth/login -> fixed-window rate limiter, 5 requests/min per IP.
6. Missing HSTS and HTTPS redirection -> UseHsts + UseHttpsRedirection.
7. Verbose stack traces in error responses -> UseExceptionHandler returning generic RFC 7807 payloads.
8. Full card numbers in logs -> masked before logging; card data stored masked (static masking).

## How Copilot helped

Copilot scaffolded the Identity configuration block and generated the TokenValidationParameters wiring from the OWASP checklist I shared. During debugging it caught that the login token was missing ValidateLifetime (a real finding from my security review) and proposed fixing the middleware registration order so the rate limiter runs before authentication. It also drafted this README security-review section from my commit messages. Every generated line was reviewed and verified against OWASP and Microsoft guidance before committing.

## Running

    cd src
    export Jwt__Key=$(openssl rand -base64 32)
    export ConnectionStrings__Default="DataSource=app.db"
    dotnet run   # https://localhost:5001, Swagger at /swagger
