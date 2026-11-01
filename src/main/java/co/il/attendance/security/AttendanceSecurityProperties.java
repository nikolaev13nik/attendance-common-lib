package co.il.attendance.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties(prefix = "attendance.security.tenant")
public class AttendanceSecurityProperties {

    private List<String> pathPatterns = new ArrayList<>();

    public List<String> getPathPatterns() {
        return pathPatterns;
    }

    public void setPathPatterns(List<String> pathPatterns) {
        this.pathPatterns = pathPatterns;
    }
}
