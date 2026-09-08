# Instructor Answer Key — Selected Challenges

## Part A

| Scenario | Primary decision |
|---|---|
| Username/password login | Authentication |
| Can Alice delete a user? | Authorization |
| Verify JWT | Authentication |
| Student opens admin dashboard | Authorization |
| Who owns resource 123? | Authorization |
| Logout | Authentication/session state |

## Part F

Alice authenticated as 101 should not automatically access 102.

The server must establish:

1. identity of the requester
2. identity/ownership of the target resource
3. whether that requester has permission

The vulnerable API fails the ownership check.

## Part H mapping

| Vulnerability | Suggested category |
|---|---|
| Plaintext passwords | Cryptographic Failures |
| Any authenticated user can delete users | Broken Access Control |
| Raw user input in database query | Injection |
| Detailed database errors | Security Misconfiguration / information exposure context |
| Hardcoded JWT secret | Security Misconfiguration / Cryptographic Failures context |

The exact OWASP mapping should be discussed as a reasoned classification rather than treated as a memorization exercise.

## Important caveat about JWT logout

The reference implementation uses short-lived JWTs and does not maintain a server-side revocation list. Therefore `/auth/logout` tells the client to discard the token; an already-issued JWT remains cryptographically valid until expiration unless a revocation mechanism is added.

This is intentional for teaching the distinction between stateless JWT authentication and server-side session invalidation.
