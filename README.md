# attendance-common-lib

Shared Spring Boot auto-configuration for the services of the
[Attendance Platform](https://github.com/nikolaev13nik/attendance-project-common). Adding the dependency is
all a service does; there are no switches to turn on.

```xml
<dependency>
    <groupId>co.il.attendance</groupId>
    <artifactId>attendance-common-lib</artifactId>
    <version>${attendance-common-lib.version}</version>
</dependency>
```

## What it provides

**Security** (`co.il.attendance.security`), active in servlet applications with Spring Security and an
OAuth2 resource server on the classpath:

- `SecurityConstants`: the roles `USER`, `ADMINISTRATOR`, `PLATFORM_ADMIN`, the JWT claim names and the
  platform tenant id 0.
- A `RoleHierarchy` (`PLATFORM_ADMIN > ADMINISTRATOR > USER`) and a `JwtAuthenticationConverter` that reads
  roles from the `authorities` claim.
- `TenantInterceptor`: on every path listed in `attendance.security.tenant.path-patterns` (required), the
  `{tenantId}` path variable must equal the token's `tenantId` claim, or the request gets 403. Only the
  platform administrator — the role together with tenant 0 — may name another tenant. A matched path with
  no `{tenantId}` is rejected too.
- `@AdminOnly`, `@AdminOrSelf` and `@PlatformAdminOnly`: the method-security rules the services use on
  their controllers.
- `JwtClaimsResolver` for reading the tenant and roles from the current authentication, one handler that
  answers every 403 with the same JSON body, and an entry point that logs every 401.

**Logging** (`co.il.attendance.logging`):

- A request filter that puts `userId`, `tenantId` and `pathTenantId` into the MDC and writes one
  `ApiRequest` line per request with method, path, status and duration, plus an `audit` line for every
  platform-administrator request.
- `LogContextScope`, a try-with-resources helper that adds keys to the MDC and removes exactly those keys
  afterwards; Kafka consumers use it to carry the event's tenant and user.
- Micrometer Tracing (Brave), so every line carries a `traceId` that follows the request across HTTP and
  Kafka.

Services without Spring Security, like the AI service, get the tracing and `LogContextScope` but none of
the security beans.

## Build and release

```bash
./mvnw test        # Spring Boot test application with real JWTs over HTTP
```

Every push to `main` runs the tests and publishes the next patch version to GitHub Packages, tagging it in
git. Consumers need a GitHub token with `read:packages` under server id `github` in
`~/.m2/settings.xml`; their CI uses its own `GITHUB_TOKEN`.
