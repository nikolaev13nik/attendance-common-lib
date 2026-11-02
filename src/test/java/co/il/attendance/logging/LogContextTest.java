package co.il.attendance.logging;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;

import co.il.attendance.security.BaseSecurityTest;

import static co.il.attendance.logging.LogContext.PATH_TENANT_ID;
import static co.il.attendance.logging.LogContext.TENANT_ID;
import static co.il.attendance.logging.LogContext.TRACE_ID;
import static co.il.attendance.logging.LogContext.TRACE_ID_HEADER;
import static co.il.attendance.logging.LogContext.USER_ID;
import static co.il.attendance.security.SecurityConstants.PLATFORM_TENANT_ID;
import static co.il.attendance.security.SecurityConstants.SecurityRoles.ADMINISTRATOR;
import static co.il.attendance.security.SecurityConstants.SecurityRoles.PLATFORM_ADMIN;
import static co.il.attendance.security.SecurityConstants.SecurityRoles.USER;
import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(OutputCaptureExtension.class)
class LogContextTest extends BaseSecurityTest {

    private static final String AUDIT_LINE = "platform admin request GET ";
    private static final String TRACE_ID_FORMAT = "[0-9a-f]{32}";
    private static final String INCOMING_TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736";
    private static final String TRACEPARENT = "traceparent";
    private static final String API_REQUEST_LINE = " ApiRequest ";

    private static String findApiRequestLine(CapturedOutput output, String request) {
        return output.getOut().lines()
                .filter(line -> line.contains(API_REQUEST_LINE) && line.contains(request))
                .findFirst()
                .orElse("");
    }

    private static String awaitApiRequestLine(CapturedOutput output, String request) {
        return await().atMost(Duration.ofSeconds(5))
                .until(() -> findApiRequestLine(output, request), line -> line.length() > 0);
    }

    private static String logContextUrl(int tenantId) {
        return "/test/tenant/" + tenantId + "/log-context";
    }

    private static HttpHeaders withTraceparent(String traceparent) {
        HttpHeaders headers = new HttpHeaders();
        headers.set(TRACEPARENT, traceparent);
        return headers;
    }

    @Test
    @DisplayName("An authenticated tenant request logs with its trace id, user, JWT tenant and path tenant")
    void tenantRequestFillsLogContextTest() {
        ResponseEntity<String> response = get(logContextUrl(TENANT), token(TENANT, USER.name()));

        assertEquals(HttpStatus.OK, response.getStatusCode());
        Map<?, ?> context = body(response);
        assertEquals(SUBJECT, context.get(USER_ID), "Reason: the user id comes from the JWT sub");
        assertEquals(String.valueOf(TENANT), context.get(TENANT_ID), "Reason: the tenant comes from the JWT claim");
        assertEquals(String.valueOf(TENANT), context.get(PATH_TENANT_ID),
                "Reason: the tenant interceptor records the tenant named in the URL");
        String traceId = (String) context.get(TRACE_ID);
        assertTrue(traceId != null && traceId.matches(TRACE_ID_FORMAT),
                "Reason: Micrometer Tracing puts a 32-hex trace id into the log context");
        assertEquals(traceId, response.getHeaders().getFirst(TRACE_ID_HEADER),
                "Reason: the response returns the trace id so a client can quote it");
    }

    @Test
    @DisplayName("An incoming W3C traceparent header continues that trace, so one id follows a request across services")
    void incomingTraceIsContinuedTest() {
        ResponseEntity<String> response = get(logContextUrl(TENANT), token(TENANT, USER.name()),
                withTraceparent("00-" + INCOMING_TRACE_ID + "-00f067aa0ba902b7-01"));

        assertEquals(INCOMING_TRACE_ID, body(response).get(TRACE_ID), "Reason: the caller's trace id is kept");
        assertEquals(INCOMING_TRACE_ID, response.getHeaders().getFirst(TRACE_ID_HEADER));
    }

    @Test
    @DisplayName("A malformed traceparent header starts a new trace instead of being logged")
    void malformedTraceparentStartsNewTraceTest() {
        String malformed = "not a trace {forged}";

        ResponseEntity<String> response = get(logContextUrl(TENANT), token(TENANT, USER.name()), withTraceparent(malformed));

        String traceId = (String) body(response).get(TRACE_ID);
        assertNotEquals(malformed, traceId, "Reason: only a valid W3C traceparent is trusted");
        assertTrue(traceId.matches(TRACE_ID_FORMAT), "Reason: a rejected header falls back to a new trace id");
    }

    @Test
    @DisplayName("The log context of one request does not leak into the next one")
    void logContextIsClearedBetweenRequestsTest() {
        get(logContextUrl(TENANT), token(TENANT, USER.name()));

        Map<?, ?> context = body(get("/test/open/log-context", token(null, USER.name())));

        assertFalse(context.containsKey(TENANT_ID), "Reason: this token has no tenant claim to log");
        assertFalse(context.containsKey(PATH_TENANT_ID), "Reason: this URL is outside the tenant patterns");
        assertEquals(SUBJECT, context.get(USER_ID), "Reason: the caller of this request is still logged");
    }

    @Test
    @DisplayName("A platform admin request writes one audit line with method, path and status")
    void platformAdminRequestIsAuditedTest(CapturedOutput output) {
        ResponseEntity<String> response = get("/test/tenant/" + OTHER_TENANT + "/ping",
                token(PLATFORM_TENANT_ID, PLATFORM_ADMIN.name()));

        assertEquals(HttpStatus.OK, response.getStatusCode());
        awaitApiRequestLine(output, "/test/tenant/" + OTHER_TENANT + "/ping status=200");
        assertTrue(output.getOut().contains(AUDIT_LINE + "/test/tenant/" + OTHER_TENANT + "/ping status=200"),
                "Reason: every platform admin request leaves an audit line");
    }

    @Test
    @DisplayName("A denied platform admin request is audited with its 403 status")
    void deniedPlatformAdminRequestIsAuditedTest(CapturedOutput output) {
        get("/test/tenant/no-tenant", token(PLATFORM_TENANT_ID, PLATFORM_ADMIN.name()));

        awaitApiRequestLine(output, "/test/tenant/no-tenant status=403");
        assertTrue(output.getOut().contains(AUDIT_LINE + "/test/tenant/no-tenant status=403"),
                "Reason: rejected platform admin requests are audited too");
    }

    @Test
    @DisplayName("A company administrator request writes no audit line")
    void companyAdminRequestIsNotAuditedTest(CapturedOutput output) {
        get("/test/tenant/" + TENANT + "/admin", token(TENANT, ADMINISTRATOR.name()));

        awaitApiRequestLine(output, "/test/tenant/" + TENANT + "/admin status=200");
        assertFalse(output.getOut().contains(AUDIT_LINE + "/test/tenant/" + TENANT + "/admin"),
                "Reason: only the platform admin is audited");
    }

    @Test
    @DisplayName("Every API request writes one ApiRequest line at INFO with method, path and status")
    void apiRequestIsLoggedTest(CapturedOutput output) {
        get("/test/tenant/" + TENANT + "/ping", token(TENANT, USER.name()));

        String line = awaitApiRequestLine(output, "GET /test/tenant/" + TENANT + "/ping status=200 durationMs=");
        assertTrue(line.contains(" INFO "), "Reason: a successful request is logged at INFO, line: " + line);
    }

    @Test
    @DisplayName("A rejected API request writes its ApiRequest line at WARN")
    void rejectedApiRequestIsLoggedAtWarnTest(CapturedOutput output) {
        get("/test/tenant/" + OTHER_TENANT + "/ping", token(TENANT, USER.name()));

        String line = awaitApiRequestLine(output, "GET /test/tenant/" + OTHER_TENANT + "/ping status=403");
        assertTrue(line.contains(" WARN "), "Reason: a 4xx answer is logged at WARN, line: " + line);
    }

    @Test
    @DisplayName("The ApiRequest line leaves out the query string, which may carry personal data")
    void queryStringIsNotLoggedTest(CapturedOutput output) {
        get("/test/tenant/" + TENANT + "/ping?email=someone@example.com", token(TENANT, USER.name()));

        awaitApiRequestLine(output, "/test/tenant/" + TENANT + "/ping status=200");
        assertFalse(output.getOut().contains("someone@example.com"), "Reason: only the path is logged");
    }

    @Test
    @DisplayName("Actuator requests such as Kubernetes health probes write no ApiRequest line")
    void actuatorIsNotLoggedTest(CapturedOutput output) {
        get("/actuator/health", token(TENANT, USER.name()));

        assertEquals("", findApiRequestLine(output, "/actuator/health"), "Reason: probes would bury the real requests");
    }

    @Test
    @DisplayName("A request without a token writes an ApiRequest line at WARN with status 401 and the trace id header")
    void missingTokenIsLoggedTest(CapturedOutput output) {
        ResponseEntity<String> response = get("/test/tenant/" + TENANT + "/ping?missing", null);

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        String line = awaitApiRequestLine(output, "GET /test/tenant/" + TENANT + "/ping status=401 reason=");
        assertTrue(line.contains(" WARN "), "Reason: an unauthenticated request is logged at WARN, line: " + line);
        assertTrue(response.getHeaders().getFirst(TRACE_ID_HEADER).matches(TRACE_ID_FORMAT),
                "Reason: a rejected caller can still quote the trace id");
    }

    @Test
    @DisplayName("An expired token writes an ApiRequest 401 line that names the expiry")
    void expiredTokenIsLoggedTest(CapturedOutput output) {
        String expired = token(Instant.now().minusSeconds(600), TENANT, USER.name());

        ResponseEntity<String> response = get("/test/tenant/" + TENANT + "/admin", expired);

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        String line = awaitApiRequestLine(output, "GET /test/tenant/" + TENANT + "/admin status=401 reason=");
        assertTrue(line.contains("expired"), "Reason: the line says why the token was refused, line: " + line);
        assertFalse(output.getOut().contains(expired), "Reason: the token itself is never logged");
    }

    @Test
    @DisplayName("A token with a forged signature writes an ApiRequest 401 line without the token")
    void forgedTokenIsLoggedTest(CapturedOutput output) {
        String valid = token(TENANT, PLATFORM_ADMIN.name());
        String forged = valid.substring(0, valid.lastIndexOf('.') + 1) + "forgedSignatureForgedSignatureForgedSig";

        ResponseEntity<String> response = get("/test/tenant/" + OTHER_TENANT + "/ping", forged);

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        awaitApiRequestLine(output, "GET /test/tenant/" + OTHER_TENANT + "/ping status=401 reason=");
        assertFalse(output.getOut().contains(forged), "Reason: the token itself is never logged");
    }
}
