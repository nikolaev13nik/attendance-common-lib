package co.il.attendance.security;

import com.nimbusds.jose.jwk.source.ImmutableSecret;

import org.slf4j.MDC;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import javax.crypto.spec.SecretKeySpec;

@SpringBootApplication
@EnableMethodSecurity
public class TestSecurityApplication {

    static final String SECRET = "test-secret-for-attendance-security-common";

    @Bean
    SecretKeySpec jwtSecretKey() {
        return new SecretKeySpec(SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
    }

    @Bean
    JwtEncoder jwtEncoder(SecretKeySpec jwtSecretKey) {
        return new NimbusJwtEncoder(new ImmutableSecret<>(jwtSecretKey));
    }

    @Bean
    JwtDecoder jwtDecoder(SecretKeySpec jwtSecretKey) {
        return NimbusJwtDecoder.withSecretKey(jwtSecretKey).macAlgorithm(MacAlgorithm.HS256).build();
    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http, JwtAuthenticationConverter jwtAuthenticationConverter,
                                    AccessDeniedHandler accessDeniedHandler,
                                    AuthenticationEntryPoint authenticationEntryPoint) {
        http.csrf(AbstractHttpConfigurer::disable)
                .oauth2ResourceServer(oauth2 -> oauth2
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter)))
                .exceptionHandling(ex -> ex.accessDeniedHandler(accessDeniedHandler))
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
        return http.build();
    }

    @RestController
    static class TestController {

        @GetMapping("/test/tenant/{tenantId}/ping")
        String ping(@PathVariable Integer tenantId) {
            return "pong " + tenantId;
        }

        @GetMapping("/test/tenant/no-tenant")
        String noTenant() {
            return "no tenant";
        }

        @PreAuthorize("hasRole('ADMINISTRATOR')")
        @GetMapping("/test/tenant/{tenantId}/admin")
        String admin(@PathVariable Integer tenantId) {
            return "admin " + tenantId;
        }

        @GetMapping("/test/open")
        String open() {
            return "open";
        }

        @GetMapping("/test/tenant/{tenantId}/log-context")
        Map<String, String> tenantLogContext(@PathVariable Integer tenantId) {
            return logContext();
        }

        @GetMapping("/test/open/log-context")
        Map<String, String> openLogContext() {
            return logContext();
        }

        private static Map<String, String> logContext() {
            Map<String, String> context = MDC.getCopyOfContextMap();
            return context == null ? Map.of() : context;
        }
    }
}
