package dev.neutron.probe;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.Arrays;

final class Request {
    private static final int MAX_DELAY_MS = 5_000;
    private static final Map<String, Set<String>> PARAMETERS;
    static {
        Map<String, Set<String>> values = new HashMap<>();
        for (String action : Arrays.asList("gpu", "bluetooth", "wifi")) {
            values.put(action, Collections.emptySet());
        }
        values.put("keymint", new HashSet<>(Arrays.asList("operation", "delay_ms")));
        values.put("camera", new HashSet<>(Collections.singletonList("camera_id")));
        values.put("media-codec", new HashSet<>(Collections.singletonList("mime")));
        values.put("usb", new HashSet<>(Collections.singletonList("usb_device_id")));
        PARAMETERS = Collections.unmodifiableMap(values);
    }

    static Map<String, String> validate(String action, Map<String, String> parameters) {
        Set<String> allowed = PARAMETERS.get(action);
        if (allowed == null || !allowed.containsAll(parameters.keySet()) || parameters.size() > 8) {
            throw new IllegalArgumentException("unsupported action or parameter");
        }
        for (Map.Entry<String, String> entry : parameters.entrySet()) {
            String value = entry.getValue();
            if (value == null || value.isEmpty() || value.length() > 256 || value.chars().anyMatch(Character::isISOControl)) {
                throw new IllegalArgumentException("invalid parameter value");
            }
        }
        String operation = parameters.get("operation");
        if (operation != null && !"lookup".equals(operation)) {
            throw new IllegalArgumentException("unsupported keymint operation");
        }
        if (parameters.containsKey("delay_ms")) {
            if (operation == null) {
                throw new IllegalArgumentException("keymint delay requires read-only lookup");
            }
            int delay;
            try {
                delay = Integer.parseInt(parameters.get("delay_ms"));
            } catch (NumberFormatException error) {
                throw new IllegalArgumentException("invalid keymint delay", error);
            }
            if (delay < 0 || delay > MAX_DELAY_MS) {
                throw new IllegalArgumentException("keymint delay is out of range");
            }
        }
        return Collections.unmodifiableMap(new HashMap<>(parameters));
    }

    private Request() {}
}
