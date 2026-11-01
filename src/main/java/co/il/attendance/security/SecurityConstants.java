package co.il.attendance.security;

public final class SecurityConstants {

    public static final String AUTHORITIES = "authorities";
    public static final String TENANT_ID = "tenantId";
    public static final String ROLE_PREFIX = "ROLE_";
    public static final String FORBIDDEN = "Forbidden";
    public static final Integer PLATFORM_TENANT_ID = 0;
    public static final String ADMINISTRATOR_AUTHORITY = ROLE_PREFIX + SecurityRoles.ADMINISTRATOR.name();
    public static final String PLATFORM_ADMIN_AUTHORITY = ROLE_PREFIX + SecurityRoles.PLATFORM_ADMIN.name();

    public enum SecurityRoles {
        USER,
        ADMINISTRATOR,
        PLATFORM_ADMIN
    }

    private SecurityConstants() {
    }
}
