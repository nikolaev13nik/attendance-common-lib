package co.il.attendance.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import tools.jackson.databind.json.JsonMapper;

import static co.il.attendance.security.SecurityConstants.AUTHORITIES;
import static co.il.attendance.security.SecurityConstants.FORBIDDEN;
import static co.il.attendance.security.SecurityConstants.PLATFORM_TENANT_ID;
import static co.il.attendance.security.SecurityConstants.SecurityRoles.ADMINISTRATOR;
import static co.il.attendance.security.SecurityConstants.SecurityRoles.PLATFORM_ADMIN;
import static co.il.attendance.security.SecurityConstants.SecurityRoles.USER;
import static co.il.attendance.security.SecurityConstants.TENANT_ID;
import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class TenantSecurityTest {

    private static final int TENANT = 100;
    private static final int OTHER_TENANT = 200;

    @LocalServerPort
    private int port;

    @Autowired
    private JwtEncoder jwtEncoder;

    private final RestTemplate rest = createRestTemplate();

    private static RestTemplate createRestTemplate() {
        RestTemplate restTemplate = new RestTemplate();
        restTemplate.setErrorHandler(new DefaultResponseErrorHandler() {
            @Override
            public boolean hasError(ClientHttpResponse response) {
                return false;
            }
        });
        return restTemplate;
    }

    private String token(Integer tenantId, String... roles) {
        JwtClaimsSet.Builder claims = JwtClaimsSet.builder()
                .subject("1")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .claim(AUTHORITIES, List.of(roles));
        if (tenantId != null) {
            claims.claim(TENANT_ID, tenantId);
        }
        return jwtEncoder.encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(), claims.build()))
                .getTokenValue();
    }

    private ResponseEntity<String> get(String path, String token) {
        HttpHeaders headers = new HttpHeaders();
        if (token != null) {
            headers.setBearerAuth(token);
        }
        return rest.exchange(URI.create("http://localhost:" + port + path), HttpMethod.GET, new HttpEntity<>(headers),
                String.class);
    }

    private static Map<?, ?> body(ResponseEntity<String> response) {
        return JsonMapper.builder().build().readValue(response.getBody(), Map.class);
    }

    @Test
    @DisplayName("GET /test/tenant/{tenantId} with a token of that tenant passes the tenant check")
    void sameTenantPassesTest() {
        ResponseEntity<String> response = get("/test/tenant/" + TENANT + "/ping", token(TENANT, USER.name()));

        assertEquals(HttpStatus.OK, response.getStatusCode(), "Reason: path tenant equals the JWT tenant");
        assertEquals("pong " + TENANT, response.getBody());
    }

    @Test
    @DisplayName("GET /test/tenant/{tenantId} with a token of another tenant returns 403 Forbidden")
    void otherTenantForbiddenTest() {
        ResponseEntity<String> response = get("/test/tenant/" + OTHER_TENANT + "/ping",
                token(TENANT, ADMINISTRATOR.name()));

        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode(),
                "Reason: an administrator of one tenant must not reach another tenant");
        assertEquals(FORBIDDEN, body(response).get("message"), "Reason: every 403 carries the same message");
        assertEquals("/test/tenant/" + OTHER_TENANT + "/ping", body(response).get("path"));
    }

    @Test
    @DisplayName("GET /test/tenant/{tenantId} with a token without a tenant claim returns 403 Forbidden")
    void missingTenantClaimForbiddenTest() {
        ResponseEntity<String> response = get("/test/tenant/" + TENANT + "/ping", token(null, USER.name()));

        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode(),
                "Reason: a token without a tenant cannot match any path tenant");
        assertEquals(FORBIDDEN, body(response).get("message"));
    }

    @Test
    @DisplayName("GET a tenant URL without a {tenantId} variable returns 403 Forbidden")
    void noPathTenantForbiddenTest() {
        ResponseEntity<String> response = get("/test/tenant/no-tenant", token(TENANT, USER.name()));

        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode(),
                "Reason: the interceptor fails closed when a matched endpoint has no tenant in its path");
        assertEquals(FORBIDDEN, body(response).get("message"));
    }

    @Test
    @DisplayName("GET /test/tenant/{tenantId} as platform admin of tenant 0 may name any tenant")
    void platformAdminAnyTenantTest() {
        ResponseEntity<String> response = get("/test/tenant/" + OTHER_TENANT + "/ping",
                token(PLATFORM_TENANT_ID, PLATFORM_ADMIN.name()));

        assertEquals(HttpStatus.OK, response.getStatusCode(), "Reason: the platform admin skips the tenant check");
    }

    @Test
    @DisplayName("GET /test/tenant/{tenantId} with PLATFORM_ADMIN outside tenant 0 returns 403 Forbidden")
    void platformAdminRoleOutsidePlatformTenantForbiddenTest() {
        ResponseEntity<String> response = get("/test/tenant/" + OTHER_TENANT + "/ping",
                token(TENANT, PLATFORM_ADMIN.name()));

        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode(),
                "Reason: the bypass needs both the role and the platform tenant");
    }

    @Test
    @DisplayName("GET an ADMINISTRATOR endpoint as USER returns 403 Forbidden with the shared body")
    void userOnAdminEndpointForbiddenTest() {
        ResponseEntity<String> response = get("/test/tenant/" + TENANT + "/admin", token(TENANT, USER.name()));

        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode(), "Reason: USER does not imply ADMINISTRATOR");
        assertEquals(FORBIDDEN, body(response).get("message"),
                "Reason: method security denials use the same handler as the tenant check");
    }

    @Test
    @DisplayName("GET an ADMINISTRATOR endpoint as platform admin passes through the role hierarchy")
    void platformAdminImpliesAdministratorTest() {
        ResponseEntity<String> response = get("/test/tenant/" + TENANT + "/admin",
                token(PLATFORM_TENANT_ID, PLATFORM_ADMIN.name()));

        assertEquals(HttpStatus.OK, response.getStatusCode(), "Reason: PLATFORM_ADMIN implies ADMINISTRATOR");
    }

    @Test
    @DisplayName("GET a URL outside the tenant patterns skips the tenant check")
    void nonTenantUrlSkipsCheckTest() {
        ResponseEntity<String> response = get("/test/open", token(null, USER.name()));

        assertEquals(HttpStatus.OK, response.getStatusCode(),
                "Reason: the interceptor applies only to the configured path patterns");
    }

    @Test
    @DisplayName("GET a tenant URL without a token returns 401 Unauthorized")
    void anonymousUnauthorizedTest() {
        ResponseEntity<String> response = get("/test/tenant/" + TENANT + "/ping", null);

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode(),
                "Reason: authentication runs before the tenant check");
    }
}
