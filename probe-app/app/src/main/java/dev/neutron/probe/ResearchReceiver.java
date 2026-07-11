package dev.neutron.probe;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothManager;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanResult;
import android.bluetooth.le.BluetoothLeScanner;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.graphics.ImageFormat;
import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CameraManager;
import android.hardware.camera2.CaptureRequest;
import android.hardware.usb.UsbConstants;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbManager;
import android.media.Image;
import android.media.ImageReader;
import android.media.MediaCodec;
import android.media.MediaCodecInfo;
import android.media.MediaFormat;
import android.net.wifi.WifiManager;
import android.opengl.EGL14;
import android.opengl.EGLConfig;
import android.opengl.EGLContext;
import android.opengl.EGLDisplay;
import android.opengl.EGLSurface;
import android.opengl.GLES20;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.KeyGenerator;

public final class ResearchReceiver extends BroadcastReceiver {
    static final int COMPLETE = 0;
    static final int FAILED = 1;
    static final int UNSUPPORTED = 3;

    @Override public void onReceive(Context context, Intent intent) {
        PendingResult pending = goAsync();
        new Thread(() -> {
            int result = FAILED;
            try {
                String action = intent.getStringExtra("action");
                result = dispatch(context, action, parameters(intent.getExtras()));
            } catch (UnsupportedOperationException error) {
                result = UNSUPPORTED;
            } catch (Exception error) {
                result = FAILED;
            } finally {
                pending.setResultCode(result);
                pending.finish();
            }
        }, "neutron-research").start();
    }

    private static Map<String, String> parameters(Bundle extras) {
        Map<String, String> values = new HashMap<>();
        if (extras == null) return values;
        for (String key : extras.keySet()) {
            if (!"action".equals(key) && extras.get(key) instanceof String) {
                values.put(key, (String) extras.get(key));
            }
        }
        return values;
    }

    static int dispatch(Context context, String action, Map<String, String> raw) throws Exception {
        Map<String, String> params = Request.validate(action, raw);
        switch (action) {
            case "keymint": keymint(); break;
            case "gpu": gpu(); break;
            case "camera": camera(context, params.get("camera_id")); break;
            case "media-codec": codec(params.getOrDefault("mime", "video/avc")); break;
            case "bluetooth": bluetooth(context); break;
            case "wifi": wifi(context); break;
            case "usb": usb(context, params.get("usb_device_id")); break;
            default: throw new IllegalArgumentException("unknown action");
        }
        return COMPLETE;
    }

    private static void keymint() throws Exception {
        String alias = "neutron-ephemeral-" + Long.toUnsignedString(System.nanoTime());
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        try {
            KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            generator.init(new KeyGenParameterSpec.Builder(alias,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256).build());
            generator.generateKey();
        } finally {
            if (store.containsAlias(alias)) store.deleteEntry(alias);
        }
    }

    private static void gpu() {
        EGLDisplay display = EGL14.eglGetDisplay(EGL14.EGL_DEFAULT_DISPLAY);
        int[] version = new int[2];
        if (display == EGL14.EGL_NO_DISPLAY || !EGL14.eglInitialize(display, version, 0, version, 1)) unsupported();
        EGLConfig[] configs = new EGLConfig[1];
        int[] count = new int[1];
        int[] attrs = {EGL14.EGL_RENDERABLE_TYPE, EGL14.EGL_OPENGL_ES2_BIT, EGL14.EGL_SURFACE_TYPE,
                EGL14.EGL_PBUFFER_BIT, EGL14.EGL_RED_SIZE, 8, EGL14.EGL_GREEN_SIZE, 8,
                EGL14.EGL_BLUE_SIZE, 8, EGL14.EGL_NONE};
        if (!EGL14.eglChooseConfig(display, attrs, 0, configs, 0, 1, count, 0) || count[0] != 1) unsupported();
        EGLContext context = EGL14.eglCreateContext(display, configs[0], EGL14.EGL_NO_CONTEXT,
                new int[]{EGL14.EGL_CONTEXT_CLIENT_VERSION, 2, EGL14.EGL_NONE}, 0);
        EGLSurface surface = EGL14.eglCreatePbufferSurface(display, configs[0],
                new int[]{EGL14.EGL_WIDTH, 32, EGL14.EGL_HEIGHT, 32, EGL14.EGL_NONE}, 0);
        try {
            if (!EGL14.eglMakeCurrent(display, surface, surface, context)) unsupported();
            GLES20.glClearColor(0, 0, 0, 1);
            GLES20.glClear(GLES20.GL_COLOR_BUFFER_BIT);
            ByteBuffer pixels = ByteBuffer.allocateDirect(32 * 32 * 4);
            GLES20.glReadPixels(0, 0, 32, 32, GLES20.GL_RGBA, GLES20.GL_UNSIGNED_BYTE, pixels);
        } finally {
            EGL14.eglMakeCurrent(display, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_CONTEXT);
            EGL14.eglDestroySurface(display, surface);
            EGL14.eglDestroyContext(display, context);
            EGL14.eglTerminate(display);
        }
    }

    private static void camera(Context context, String selectedId) throws Exception {
        CameraManager manager = context.getSystemService(CameraManager.class);
        String[] ids = manager.getCameraIdList();
        if (ids.length == 0) unsupported();
        String id = selectedId == null ? ids[0] : selectedId;
        boolean found = false;
        for (String candidate : ids) found |= candidate.equals(id);
        if (!found) unsupported();
        HandlerThread thread = new HandlerThread("neutron-camera");
        thread.start();
        Handler handler = new Handler(thread.getLooper());
        ImageReader reader = ImageReader.newInstance(320, 240, ImageFormat.YUV_420_888, 1);
        CountDownLatch done = new CountDownLatch(1);
        AtomicBoolean captured = new AtomicBoolean(false);
        CameraDevice[] opened = new CameraDevice[1];
        CameraCaptureSession[] session = new CameraCaptureSession[1];
        reader.setOnImageAvailableListener(source -> {
            try (Image image = source.acquireLatestImage()) { captured.set(image != null); }
            done.countDown();
        }, handler);
        try {
            manager.openCamera(id, new CameraDevice.StateCallback() {
                @Override public void onOpened(CameraDevice camera) {
                    opened[0] = camera;
                    try {
                        camera.createCaptureSession(Collections.singletonList(reader.getSurface()), new CameraCaptureSession.StateCallback() {
                            @Override public void onConfigured(CameraCaptureSession value) {
                                session[0] = value;
                                try {
                                    CaptureRequest.Builder request = camera.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW);
                                    request.addTarget(reader.getSurface());
                                    value.capture(request.build(), null, handler);
                                } catch (Exception error) { done.countDown(); }
                            }
                            @Override public void onConfigureFailed(CameraCaptureSession value) { done.countDown(); }
                        }, handler);
                    } catch (Exception error) { done.countDown(); }
                }
                @Override public void onDisconnected(CameraDevice camera) { camera.close(); done.countDown(); }
                @Override public void onError(CameraDevice camera, int error) { camera.close(); done.countDown(); }
            }, handler);
            if (!done.await(8, TimeUnit.SECONDS)) unsupported();
            if (!captured.get()) unsupported();
        } finally {
            if (session[0] != null) session[0].close();
            if (opened[0] != null) opened[0].close();
            reader.close();
            thread.quitSafely();
        }
    }

    private static void codec(String mime) throws Exception {
        MediaCodec codec;
        try { codec = MediaCodec.createEncoderByType(mime); }
        catch (Exception error) { unsupported(); return; }
        try {
            MediaFormat format = MediaFormat.createVideoFormat(mime, 32, 32);
            format.setInteger(MediaFormat.KEY_COLOR_FORMAT, MediaCodecInfo.CodecCapabilities.COLOR_FormatYUV420Flexible);
            format.setInteger(MediaFormat.KEY_BIT_RATE, 64_000);
            format.setInteger(MediaFormat.KEY_FRAME_RATE, 1);
            format.setInteger(MediaFormat.KEY_I_FRAME_INTERVAL, 1);
            codec.configure(format, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE);
            codec.start();
            int index = codec.dequeueInputBuffer(2_000);
            if (index >= 0) {
                ByteBuffer input = codec.getInputBuffer(index);
                if (input == null || input.remaining() < 1536) unsupported();
                for (int i = 0; i < 1536; i++) input.put((byte) 0);
                codec.queueInputBuffer(index, 0, 1536, 0, MediaCodec.BUFFER_FLAG_END_OF_STREAM);
            }
        } finally {
            try { codec.stop(); } catch (Exception ignored) {}
            codec.release();
        }
    }

    private static void bluetooth(Context context) throws Exception {
        BluetoothManager manager = context.getSystemService(BluetoothManager.class);
        BluetoothAdapter adapter = manager == null ? null : manager.getAdapter();
        if (adapter == null || !adapter.isEnabled()) unsupported();
        BluetoothLeScanner scanner = adapter.getBluetoothLeScanner();
        if (scanner == null) unsupported();
        AtomicBoolean failed = new AtomicBoolean(false);
        ScanCallback callback = new ScanCallback() {
            @Override public void onScanResult(int callbackType, ScanResult result) { /* discard */ }
            @Override public void onScanFailed(int errorCode) { failed.set(true); }
        };
        scanner.startScan(callback);
        try { Thread.sleep(3000); } finally { scanner.stopScan(callback); }
        if (failed.get()) unsupported();
    }

    private static void wifi(Context context) {
        WifiManager manager = context.getSystemService(WifiManager.class);
        if (manager == null || !manager.isWifiEnabled() || !manager.startScan()) unsupported();
    }

    private static void usb(Context context, String selector) {
        UsbManager manager = context.getSystemService(UsbManager.class);
        List<UsbDevice> candidates = new ArrayList<>();
        for (UsbDevice device : manager.getDeviceList().values()) {
            if (device.getDeviceClass() != UsbConstants.USB_CLASS_HUB) candidates.add(device);
        }
        UsbDevice selected = null;
        if (selector == null && candidates.size() == 1) selected = candidates.get(0);
        if (selector != null) {
            for (UsbDevice candidate : candidates) {
                if (selector.equals(Integer.toString(candidate.getDeviceId())) || selector.equals(candidate.getDeviceName())) selected = candidate;
            }
        }
        if (selected == null || !manager.hasPermission(selected)) unsupported();
        UsbDeviceConnection connection = manager.openDevice(selected);
        try {
            if (connection == null) unsupported();
            byte[] descriptor = new byte[18];
            int read = connection.controlTransfer(UsbConstants.USB_DIR_IN | UsbConstants.USB_TYPE_STANDARD,
                    6, UsbConstants.USB_DT_DEVICE << 8, 0, descriptor, descriptor.length, 2000);
            if (read < 0) unsupported();
        } finally {
            if (connection != null) connection.close();
        }
    }

    private static void unsupported() { throw new UnsupportedOperationException(); }
}
