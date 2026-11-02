package co.il.attendance.logging;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.security.autoconfigure.web.servlet.SecurityFilterProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;

@AutoConfiguration
public class AttendanceLoggingAutoConfiguration {

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    @ConditionalOnClass({Jwt.class, SecurityFilterProperties.class, BearerTokenAuthenticationEntryPoint.class})
    static class ServletLogContextConfiguration {

        @Bean
        FilterRegistrationBean<LogContextFilter> logContextFilter() {
            FilterRegistrationBean<LogContextFilter> registration = new FilterRegistrationBean<>(new LogContextFilter());
            registration.setOrder(SecurityFilterProperties.DEFAULT_FILTER_ORDER + 1);
            return registration;
        }

        @Bean
        @ConditionalOnMissingBean
        AuthenticationEntryPoint authenticationEntryPoint() {
            return new LoggingAuthenticationEntryPoint();
        }
    }
}
