package pe.edu.pucp.sdn.topology;

import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Link;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.link.LinkEvent;
import org.onosproject.net.link.LinkListener;
import org.onosproject.net.link.LinkService;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Dictionary;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import static org.slf4j.LoggerFactory.getLogger;

@Component(immediate = true, service = TopologyEventComponent.class)
public class TopologyEventComponent {

    private static final String APP_NAME = "pe.edu.pucp.sdn.topology-events";
    private static final int DEFAULT_TIMEOUT_MS = 15000;
    private static final int EVENT_QUEUE_CAPACITY = 256;

    private final Logger log = getLogger(getClass());
    private final InternalDeviceListener deviceListener = new InternalDeviceListener();
    private final InternalLinkListener linkListener = new InternalLinkListener();
    private final ExecutorService executor = new ThreadPoolExecutor(
            1, 1, 0L, TimeUnit.MILLISECONDS,
            new ArrayBlockingQueue<>(EVENT_QUEUE_CAPACITY),
            runnable -> {
                Thread thread = new Thread(runnable, "pucp-topology-events-m6");
                thread.setDaemon(true);
                return thread;
            },
            (runnable, pool) -> log.warn("Dropping topology event because M6 notification queue is full"));
    private final Map<String, Long> recentlySent = new ConcurrentHashMap<>();

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected LinkService linkService;

    private ApplicationId appId;
    private volatile boolean enabled = true;
    private volatile String m6Url = "http://192.168.201.251:8080/m6/failover/event";
    private volatile String securityToken = "change-me";
    private volatile int timeoutMs = DEFAULT_TIMEOUT_MS;
    private volatile int dedupWindowSeconds = 15;

    @Activate
    protected void activate(ComponentContext context) {
        appId = coreService.registerApplication(APP_NAME);
        readConfiguration(context);
        deviceService.addListener(deviceListener);
        linkService.addListener(linkListener);
        log.info("Started {} appId={} enabled={} m6Url={}", APP_NAME, appId.id(), enabled, m6Url);
    }

    @Modified
    protected void modified(ComponentContext context) {
        readConfiguration(context);
        log.info("Reconfigured {} enabled={} m6Url={} timeoutMs={} dedupWindowSeconds={}",
                APP_NAME, enabled, m6Url, timeoutMs, dedupWindowSeconds);
    }

    @Deactivate
    protected void deactivate() {
        deviceService.removeListener(deviceListener);
        linkService.removeListener(linkListener);
        recentlySent.clear();
        executor.shutdownNow();
        log.info("Stopped {}", APP_NAME);
    }

    private void readConfiguration(ComponentContext context) {
        Dictionary<?, ?> properties = context == null ? null : context.getProperties();
        enabled = getBoolean(properties, "enabled", enabled);
        m6Url = getString(properties, "m6Url", m6Url);
        securityToken = getString(properties, "securityToken", securityToken);
        timeoutMs = Math.max(250, getInteger(properties, "timeoutMs", timeoutMs));
        dedupWindowSeconds = Math.max(1, getInteger(properties, "dedupWindowSeconds", dedupWindowSeconds));
    }

    private void handleDeviceEvent(DeviceEvent event) {
        if (!enabled || event == null || event.subject() == null) {
            return;
        }
        String eventType = null;
        switch (event.type()) {
            case DEVICE_REMOVED:
                eventType = "device_down";
                break;
            case DEVICE_AVAILABILITY_CHANGED:
                if (!deviceService.isAvailable(event.subject().id())) {
                    eventType = "device_down";
                }
                break;
            default:
                break;
        }
        if (eventType == null) {
            return;
        }
        DeviceId deviceId = event.subject().id();
        String payload = "{"
                + jsonPair("event_type", eventType) + ","
                + jsonPair("device_id", deviceId.toString()) + ","
                + jsonPair("onos_event", event.type().name()) + ","
                + jsonPair("source", "onos-device-listener")
                + "}";
        submit("device:" + eventType + ":" + deviceId, payload);
    }

    private void handleLinkEvent(LinkEvent event) {
        if (!enabled || event == null || event.subject() == null) {
            return;
        }
        String eventType = null;
        switch (event.type()) {
            case LINK_REMOVED:
                eventType = "link_down";
                break;
            case LINK_UPDATED:
                if (event.subject().state() != Link.State.ACTIVE) {
                    eventType = "link_down";
                }
                break;
            default:
                break;
        }
        if (eventType == null) {
            return;
        }
        Link link = event.subject();
        String payload = "{"
                + jsonPair("event_type", eventType) + ","
                + "\"failed_links\":[{"
                + jsonPair("src_device", link.src().deviceId().toString()) + ","
                + jsonPair("src_port", link.src().port().toString()) + ","
                + jsonPair("dst_device", link.dst().deviceId().toString()) + ","
                + jsonPair("dst_port", link.dst().port().toString())
                + "}],"
                + jsonPair("onos_event", event.type().name()) + ","
                + jsonPair("source", "onos-link-listener")
                + "}";
        submit("link:" + eventType + ":" + link.src() + ">" + link.dst(), payload);
    }

    private void submit(String dedupKey, String payload) {
        if (isDuplicate(dedupKey)) {
            log.debug("Suppressing duplicate topology event {}", dedupKey);
            return;
        }
        executor.submit(() -> postToM6(dedupKey, payload));
    }

    private boolean isDuplicate(String key) {
        long now = System.currentTimeMillis();
        long cutoff = now - Duration.ofSeconds(dedupWindowSeconds).toMillis();
        recentlySent.entrySet().removeIf(entry -> entry.getValue() < cutoff);
        Long last = recentlySent.put(key, now);
        return last != null && last >= cutoff;
    }

    private void postToM6(String eventKey, String payload) {
        HttpURLConnection connection = null;
        try {
            URL url = new URL(m6Url);
            connection = (HttpURLConnection) url.openConnection();
            connection.setConnectTimeout(timeoutMs);
            connection.setReadTimeout(timeoutMs);
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("X-Security-Token", securityToken);
            byte[] body = payload.getBytes(StandardCharsets.UTF_8);
            connection.setFixedLengthStreamingMode(body.length);
            try (OutputStream output = connection.getOutputStream()) {
                output.write(body);
            }
            int status = connection.getResponseCode();
            if (status >= 200 && status < 300) {
                log.info("Forwarded topology event {} to M6 status={}", eventKey, status);
            } else {
                log.warn("M6 rejected topology event {} status={}", eventKey, status);
            }
        } catch (Exception e) {
            log.warn("Failed to forward topology event {} to M6: {}", eventKey, e.toString());
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private static String jsonPair(String key, String value) {
        return "\"" + escape(key) + "\":\"" + escape(value) + "\"";
    }

    private static String escape(String value) {
        return Objects.toString(value, "")
                .replace("\\", "\\\\")
                .replace("\"", "\\\"");
    }

    private static String getString(Dictionary<?, ?> properties, String key, String defaultValue) {
        Object value = properties == null ? null : properties.get(key);
        return value == null ? defaultValue : value.toString();
    }

    private static boolean getBoolean(Dictionary<?, ?> properties, String key, boolean defaultValue) {
        Object value = properties == null ? null : properties.get(key);
        return value == null ? defaultValue : Boolean.parseBoolean(value.toString());
    }

    private static int getInteger(Dictionary<?, ?> properties, String key, int defaultValue) {
        Object value = properties == null ? null : properties.get(key);
        if (value == null) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(value.toString());
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    private final class InternalDeviceListener implements DeviceListener {
        @Override
        public void event(DeviceEvent event) {
            handleDeviceEvent(event);
        }
    }

    private final class InternalLinkListener implements LinkListener {
        @Override
        public void event(LinkEvent event) {
            handleLinkEvent(event);
        }
    }
}
