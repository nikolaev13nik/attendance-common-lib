package co.il.attendance.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.web.SecurityFilterChain;

import static org.assertj.core.api.Assertions.assertThat;

class AttendanceSecurityAutoConfigurationTest {

    private static final String PATH_PATTERNS = "attendance.security.tenant.path-patterns=/x/tenant/**";

    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(AttendanceSecurityAutoConfiguration.class));

    @Test
    @DisplayName("Without Spring Security on the classpath the shared security beans are not created")
    void noSpringSecurityTest() {
        runner.withClassLoader(new FilteredClassLoader(SecurityFilterChain.class)).run(context -> assertThat(context).hasNotFailed()
                .doesNotHaveBean(TenantInterceptor.class)
                .doesNotHaveBean(JsonAccessDeniedHandler.class));
    }

    @Test
    @DisplayName("Startup fails when no tenant path patterns are configured")
    void missingPathPatternsFailsStartupTest() {
        runner.run(context -> assertThat(context).hasFailed()
                        .getFailure().rootCause().hasMessageContaining("attendance.security.tenant.path-patterns"));
    }

    @Test
    @DisplayName("Path patterns start the context with the shared beans")
    void pathPatternsStartContextTest() {
        runner.withPropertyValues(PATH_PATTERNS)
                .run(context -> assertThat(context).hasNotFailed()
                        .hasSingleBean(TenantInterceptor.class)
                        .hasSingleBean(JsonAccessDeniedHandler.class)
                        .hasSingleBean(RoleHierarchy.class));
    }

    @Test
    @DisplayName("A service's own RoleHierarchy bean replaces the shared one")
    void ownRoleHierarchyWinsTest() {
        RoleHierarchy own = RoleHierarchyImpl.fromHierarchy("ROLE_A > ROLE_B");
        runner.withPropertyValues(PATH_PATTERNS)
                .withBean(RoleHierarchy.class, () -> own)
                .run(context -> assertThat(context.getBean(RoleHierarchy.class)).isSameAs(own));
    }
}
