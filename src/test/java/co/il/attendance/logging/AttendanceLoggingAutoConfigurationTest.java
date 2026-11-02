package co.il.attendance.logging;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.security.oauth2.jwt.Jwt;

import static org.assertj.core.api.Assertions.assertThat;

class AttendanceLoggingAutoConfigurationTest {

    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(AttendanceLoggingAutoConfiguration.class));

    @Test
    @DisplayName("Without JWT support on the classpath no log context filter is registered")
    void noJwtSupportTest() {
        runner.withClassLoader(new FilteredClassLoader(Jwt.class)).run(context -> assertThat(context).hasNotFailed().doesNotHaveBean(FilterRegistrationBean.class));
    }

    @Test
    @DisplayName("The log context filter is registered right after security")
    void logContextFilterRegisteredTest() {
        runner.run(context -> assertThat(context).hasNotFailed()
                        .getBean(FilterRegistrationBean.class)
                        .satisfies(registration -> assertThat(registration.getFilter())
                                .isInstanceOf(LogContextFilter.class)));
    }
}
