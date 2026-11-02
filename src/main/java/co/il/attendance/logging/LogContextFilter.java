package co.il.attendance.logging;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.slf4j.event.Level;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import co.il.attendance.security.JwtClaimsResolver;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import static co.il.attendance.logging.LogContext.API_REQUEST_LOGGER;
import static co.il.attendance.logging.LogContext.AUDIT_LOGGER;
import static co.il.attendance.logging.LogContext.PATH_TENANT_ID;
import static co.il.attendance.logging.LogContext.TENANT_ID;
import static co.il.attendance.logging.LogContext.TRACE_ID;
import static co.il.attendance.logging.LogContext.TRACE_ID_HEADER;
import static co.il.attendance.logging.LogContext.USER_ID;

public class LogContextFilter extends OncePerRequestFilter {

    private static final Logger audit = LoggerFactory.getLogger(AUDIT_LOGGER);
    private static final Logger apiRequest = LoggerFactory.getLogger(API_REQUEST_LOGGER);
    private static final String ACTUATOR_PATH = "/actuator";

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return request.getRequestURI().startsWith(ACTUATOR_PATH);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        setTraceIdHeader(response);
        long start = System.nanoTime();
        Throwable failure = null;
        try (LogContextScope ignored = LogContextScope.open()
                .with(USER_ID, JwtClaimsResolver.currentJwt(auth).map(Jwt::getSubject).orElse(null))
                .with(TENANT_ID, JwtClaimsResolver.currentTenantId(auth))
                .ownsKey(PATH_TENANT_ID)) {
            try {
                chain.doFilter(request, response);
            } catch (ServletException | IOException | RuntimeException e) {
                failure = e;
                throw e;
            } finally {
                int status = failure == null ? response.getStatus() : statusOf(failure);
                long durationMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
                if (JwtClaimsResolver.isPlatformAdmin(auth)) {
                    audit.info("platform admin request {} {} status={} durationMs={}", request.getMethod(),
                            request.getRequestURI(), status, durationMs);
                }
                apiRequest.atLevel(levelOf(status)).log("{} {} status={} durationMs={}", request.getMethod(),
                        request.getRequestURI(), status, durationMs);
            }
        }
    }

    static void setTraceIdHeader(HttpServletResponse response) {
        String traceId = MDC.get(TRACE_ID);
        if (traceId != null) {
            response.setHeader(TRACE_ID_HEADER, traceId);
        }
    }

    private static Level levelOf(int status) {
        HttpStatusCode code = HttpStatusCode.valueOf(status);
        if (code.is5xxServerError()) {
            return Level.ERROR;
        }
        if (code.is4xxClientError()) {
            return Level.WARN;
        }
        return Level.INFO;
    }

    private static int statusOf(Throwable failure) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause instanceof AccessDeniedException) {
                return HttpStatus.FORBIDDEN.value();
            }
        }
        return HttpStatus.INTERNAL_SERVER_ERROR.value();
    }
}
