package co.il.attendance.logging;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import static co.il.attendance.logging.LogContext.API_REQUEST_LOGGER;

public class LoggingAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private static final Logger apiRequest = LoggerFactory.getLogger(API_REQUEST_LOGGER);

    private final AuthenticationEntryPoint delegate = new BearerTokenAuthenticationEntryPoint();

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {
        LogContextFilter.setTraceIdHeader(response);
        delegate.commence(request, response, authException);
        apiRequest.warn("{} {} status={} reason={}", request.getMethod(), request.getRequestURI(),
                response.getStatus(), authException.getMessage());
    }
}
