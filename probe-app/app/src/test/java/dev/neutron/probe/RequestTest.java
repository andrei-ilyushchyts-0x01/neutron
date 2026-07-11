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
}
