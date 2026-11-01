package co.il.attendance.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.HandlerMapping;

import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import static co.il.attendance.security.SecurityConstants.FORBIDDEN;
import static co.il.attendance.security.SecurityConstants.TENANT_ID;
import static org.apache.commons.lang3.BooleanUtils.isFalse;

public class TenantInterceptor implements HandlerInterceptor {

    private static final Logger log = LoggerFactory.getLogger(TenantInterceptor.class);

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if (isFalse(handler instanceof HandlerMethod)) {
            return true;
        }
        String pathTenantId = pathTenantId(request);
        if (pathTenantId == null) {
            log.warn("Request rejected: no tenant in path {}", request.getRequestURI());
            throw new AccessDeniedException(FORBIDDEN);
        }
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (JwtClaimsResolver.isPlatformAdmin(auth)) {
            log.info("Platform admin {} acting on tenant {}: {} {}", auth.getName(), pathTenantId,
                    request.getMethod(), request.getRequestURI());
            return true;
        }
        String jwtTenantId = JwtClaimsResolver.currentTenantId(auth);
        if (isFalse(pathTenantId.equals(jwtTenantId))) {
            log.warn("Request rejected: JWT tenant {} does not match path tenant {} on {}", jwtTenantId, pathTenantId,
                    request.getRequestURI());
            throw new AccessDeniedException(FORBIDDEN);
        }
        return true;
    }

    private static String pathTenantId(HttpServletRequest request) {
        if (request.getAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE) instanceof Map<?, ?> pathVars) {
            Object tenantId = pathVars.get(TENANT_ID);
            return tenantId == null ? null : tenantId.toString();
        }
        return null;
    }
}
