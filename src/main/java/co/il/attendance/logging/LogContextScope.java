package co.il.attendance.logging;

import org.slf4j.MDC;

import java.util.ArrayList;
import java.util.List;

public final class LogContextScope implements AutoCloseable {

    private final List<String> keys = new ArrayList<>();

    private LogContextScope() {
    }

    public static LogContextScope open() {
        return new LogContextScope();
    }

    public LogContextScope with(String key, Object value) {
        if (value != null) {
            MDC.put(key, value.toString());
            keys.add(key);
        }
        return this;
    }

    public LogContextScope ownsKey(String key) {
        keys.add(key);
        return this;
    }

    @Override
    public void close() {
        keys.forEach(MDC::remove);
    }
}
