package dev.neutron.probe;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class ResearchReceiverTest {
    @Test public void uses_the_standard_usb_device_descriptor_type() {
        assertEquals(0x01, ResearchReceiver.USB_DESCRIPTOR_DEVICE);
    }
}
