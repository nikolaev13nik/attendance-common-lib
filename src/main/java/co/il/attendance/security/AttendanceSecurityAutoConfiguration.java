package co.il.attendance.security;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import static co.il.attendance.security.SecurityConstants.AUTHORITIES;
import static co.il.attendance.security.SecurityConstants.ROLE_PREFIX;
import static co.il.attendance.security.SecurityConstants.SecurityRoles.ADMINISTRATOR;
import static co.il.attendance.security.SecurityConstants.SecurityRoles.PLATFORM_ADMIN;
import static co.il.attendance.security.SecurityConstants.SecurityRoles.USER;

@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@EnableConfigurationProperties(AttendanceSecurityProperties.class)
public class AttendanceSecurityAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    static RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.withDefaultRolePrefix()
                .role(PLATFORM_ADMIN.name()).implies(ADMINISTRATOR.name())
                .role(ADMINISTRATOR.name()).implies(USER.name())
                .build();
    }

    @Bean
    @ConditionalOnMissingBean
    JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
        authoritiesConverter.setAuthoritiesClaimName(AUTHORITIES);
        authoritiesConverter.setAuthorityPrefix(ROLE_PREFIX);
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
        return converter;
    }

    @Bean
    @ConditionalOnMissingBean
    AccessDeniedHandler accessDeniedHandler() {
        return new JsonAccessDeniedHandler();
    }

    @Bean
    TenantInterceptor tenantInterceptor() {
        return new TenantInterceptor();
    }

    @Bean
    WebMvcConfigurer tenantInterceptorConfigurer(TenantInterceptor tenantInterceptor,
                                                 AttendanceSecurityProperties properties) {
        if (properties.getPathPatterns().isEmpty()) {
            throw new IllegalStateException("attendance.security.tenant.path-patterns must name the tenant URLs");
        }
        return new WebMvcConfigurer() {
            @Override
            public void addInterceptors(InterceptorRegistry registry) {
                registry.addInterceptor(tenantInterceptor).addPathPatterns(properties.getPathPatterns());
            }
        };
    }
}
