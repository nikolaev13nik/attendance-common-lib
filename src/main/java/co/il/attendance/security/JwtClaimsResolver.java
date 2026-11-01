package co.il.attendance.security;

import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.Objects;
import java.util.Optional;

import static co.il.attendance.security.SecurityConstants.ADMINISTRATOR_AUTHORITY;
import static co.il.attendance.security.SecurityConstants.PLATFORM_ADMIN_AUTHORITY;
import static co.il.attendance.security.SecurityConstants.PLATFORM_TENANT_ID;
import static co.il.attendance.security.SecurityConstants.TENANT_ID;

public final class JwtClaimsResolver {

    private static final RoleHierarchy ROLE_HIERARCHY = AttendanceSecurityAutoConfiguration.roleHierarchy();

    private JwtClaimsResolver() {
    }

    public static Optional<Jwt> currentJwt(Authentication auth) {
        if (auth != null && auth.getPrincipal() instanceof Jwt jwt) {
            return Optional.of(jwt);
        }
        return Optional.empty();
    }

    public static String currentTenantId(Authentication auth) {
        return currentJwt(auth).map(jwt -> jwt.getClaimAsString(TENANT_ID)).orElse(null);
    }

    public static boolean isPlatformAdmin(Authentication auth) {
        return PLATFORM_TENANT_ID.toString().equals(currentTenantId(auth))
                && hasAuthority(auth.getAuthorities(), PLATFORM_ADMIN_AUTHORITY);
    }

    public static boolean isAdministratorOf(Authentication auth, Integer tenantId) {
        return tenantId != null && tenantId.toString().equals(currentTenantId(auth))
                && hasAuthority(auth.getAuthorities(), ADMINISTRATOR_AUTHORITY);
    }

    public static boolean isAdministrator(Authentication auth) {
        return auth != null
                && hasAuthority(ROLE_HIERARCHY.getReachableGrantedAuthorities(auth.getAuthorities()),
                ADMINISTRATOR_AUTHORITY);
    }

    private static boolean hasAuthority(Collection<? extends GrantedAuthority> authorities, String authority) {
        return authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .filter(Objects::nonNull)
                .anyMatch(authority::equals);
    }
}
