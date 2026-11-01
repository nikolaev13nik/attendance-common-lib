package co.il.attendance.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import static co.il.attendance.security.SecurityConstants.ADMINISTRATOR_AUTHORITY;
import static co.il.attendance.security.SecurityConstants.PLATFORM_ADMIN_AUTHORITY;
import static co.il.attendance.security.SecurityConstants.PLATFORM_TENANT_ID;
import static co.il.attendance.security.SecurityConstants.ROLE_PREFIX;
import static co.il.attendance.security.SecurityConstants.SecurityRoles.USER;
import static co.il.attendance.security.SecurityConstants.TENANT_ID;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtClaimsResolverTest {

    private static final int TENANT = 100;

    private static Authentication jwtAuth(Integer tenantId, String... authorities) {
        Jwt.Builder jwt = Jwt.withTokenValue("token").header("alg", "HS256").subject("1");
        if (tenantId != null) {
            jwt.claim(TENANT_ID, tenantId);
        }
        return new JwtAuthenticationToken(jwt.build(), AuthorityUtils.createAuthorityList(authorities));
    }

    @Test
    @DisplayName("currentTenantId reads the tenantId claim as a string")
    void currentTenantIdTest() {
        assertEquals(String.valueOf(TENANT), JwtClaimsResolver.currentTenantId(jwtAuth(TENANT)));
    }

    @Test
    @DisplayName("currentTenantId is null without a JWT principal or without the claim")
    void currentTenantIdMissingTest() {
        assertNull(JwtClaimsResolver.currentTenantId(null), "Reason: no authentication at all");
        assertNull(JwtClaimsResolver.currentTenantId(new UsernamePasswordAuthenticationToken("user", "pwd")),
                "Reason: the principal is not a JWT");
        assertNull(JwtClaimsResolver.currentTenantId(jwtAuth(null)), "Reason: the token has no tenant claim");
    }

    @Test
    @DisplayName("isPlatformAdmin needs both the PLATFORM_ADMIN authority and tenant 0")
    void isPlatformAdminTest() {
        assertTrue(JwtClaimsResolver.isPlatformAdmin(jwtAuth(PLATFORM_TENANT_ID, PLATFORM_ADMIN_AUTHORITY)));
        assertFalse(JwtClaimsResolver.isPlatformAdmin(jwtAuth(TENANT, PLATFORM_ADMIN_AUTHORITY)),
                "Reason: the role outside tenant 0 is not the platform admin");
        assertFalse(JwtClaimsResolver.isPlatformAdmin(jwtAuth(PLATFORM_TENANT_ID, ADMINISTRATOR_AUTHORITY)),
                "Reason: tenant 0 without the role is not the platform admin");
        assertFalse(JwtClaimsResolver.isPlatformAdmin(null), "Reason: no authentication at all");
    }

    @Test
    @DisplayName("isAdministratorOf is true only for an ADMINISTRATOR of that same tenant")
    void isAdministratorOfTest() {
        Authentication admin = jwtAuth(TENANT, ADMINISTRATOR_AUTHORITY);

        assertTrue(JwtClaimsResolver.isAdministratorOf(admin, TENANT));
        assertFalse(JwtClaimsResolver.isAdministratorOf(admin, 200), "Reason: administrator of another tenant");
        assertFalse(JwtClaimsResolver.isAdministratorOf(admin, null), "Reason: no tenant to compare with");
        assertFalse(JwtClaimsResolver.isAdministratorOf(jwtAuth(TENANT, ROLE_PREFIX + USER.name()), TENANT),
                "Reason: USER of the tenant is not its administrator");
    }

    @Test
    @DisplayName("isAdministrator follows the role hierarchy, so PLATFORM_ADMIN counts as ADMINISTRATOR")
    void isAdministratorTest() {
        assertTrue(JwtClaimsResolver.isAdministrator(jwtAuth(TENANT, ADMINISTRATOR_AUTHORITY)));
        assertTrue(JwtClaimsResolver.isAdministrator(jwtAuth(PLATFORM_TENANT_ID, PLATFORM_ADMIN_AUTHORITY)),
                "Reason: PLATFORM_ADMIN implies ADMINISTRATOR");
        assertFalse(JwtClaimsResolver.isAdministrator(jwtAuth(TENANT, ROLE_PREFIX + USER.name())),
                "Reason: USER does not imply ADMINISTRATOR");
        assertFalse(JwtClaimsResolver.isAdministrator(null), "Reason: no authentication at all");
    }
}
