package dev.neutron.probe;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.Arrays;

final class Request {
    private static final Map<String, Set<String>> PARAMETERS;
    static {
        Map<String, Set<String>> values = new HashMap<>();
        for (String action : Arrays.asList("keymint", "gpu", "bluetooth", "wifi")) {
            values.put(action, Collections.emptySet());
        }
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
        return Collections.unmodifiableMap(parameters);
    }

    private Request() {}
}
