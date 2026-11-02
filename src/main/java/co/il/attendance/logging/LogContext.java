package co.il.attendance.logging;

public final class LogContext {

    public static final String TRACE_ID = "traceId";
    public static final String USER_ID = "userId";
    public static final String TENANT_ID = "tenantId";
    public static final String PATH_TENANT_ID = "pathTenantId";
    public static final String TARGET_USER_ID = "targetUserId";
    public static final String TRACE_ID_HEADER = "X-Trace-Id";
    public static final String AUDIT_LOGGER = "audit";
    public static final String API_REQUEST_LOGGER = "ApiRequest";

    private LogContext() {
    }
}
