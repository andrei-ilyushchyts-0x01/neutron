package dev.neutron.probe;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import android.hardware.camera2.CameraAccessException;
import org.junit.Test;

public class ResearchReceiverTest {
    @Test public void uses_the_standard_usb_device_descriptor_type() {
        assertEquals(0x01, ResearchReceiver.USB_DESCRIPTOR_DEVICE);
    }

    @Test public void classifies_expected_camera_access_rejections_as_unavailable() {
        assertTrue(ResearchReceiver.isCameraUnavailable(new SecurityException()));
        assertTrue(ResearchReceiver.isCameraUnavailable(
                new CameraAccessException(CameraAccessException.CAMERA_DISABLED)));
        assertFalse(ResearchReceiver.isCameraUnavailable(new IllegalStateException()));
    }
}
