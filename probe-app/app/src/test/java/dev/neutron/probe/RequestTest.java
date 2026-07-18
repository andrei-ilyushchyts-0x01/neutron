package dev.neutron.probe;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import java.util.Map;
import org.junit.Test;

public class RequestTest {
    @Test public void acceptsOnlyTypedActionParameters() {
        assertEquals("0", Request.validate("camera", Map.of("camera_id", "0")).get("camera_id"));
        assertThrows(IllegalArgumentException.class,
                () -> Request.validate("camera", Map.of("argv", "sh -c id")));
        assertThrows(IllegalArgumentException.class,
                () -> Request.validate("shell", Map.of()));
    }

    @Test public void acceptsBoundedReadOnlyKeymintLookup() {
        Map<String, String> request = Request.validate("keymint", Map.of(
                "operation", "lookup",
                "delay_ms", "2000"));

        assertEquals("lookup", request.get("operation"));
        assertEquals("2000", request.get("delay_ms"));
        assertEquals("0", Request.validate("keymint", Map.of(
                "operation", "lookup", "delay_ms", "0")).get("delay_ms"));
        assertEquals("5000", Request.validate("keymint", Map.of(
                "operation", "lookup", "delay_ms", "5000")).get("delay_ms"));
    }

    @Test public void rejectsUnboundedOrUntypedKeymintControls() {
        assertThrows(IllegalArgumentException.class,
                () -> Request.validate("keymint", Map.of("operation", "shell")));
        assertThrows(IllegalArgumentException.class,
                () -> Request.validate("keymint", Map.of("operation", "generate")));
        assertThrows(IllegalArgumentException.class,
                () -> Request.validate("keymint", Map.of("delay_ms", "1")));
        assertThrows(IllegalArgumentException.class,
                () -> Request.validate("keymint", Map.of(
                        "operation", "lookup", "delay_ms", "5001")));
        assertThrows(IllegalArgumentException.class,
                () -> Request.validate("keymint", Map.of(
                        "operation", "lookup", "delay_ms", "soon")));
        assertThrows(IllegalArgumentException.class,
                () -> Request.validate("gpu", Map.of("delay_ms", "1")));
    }
}
