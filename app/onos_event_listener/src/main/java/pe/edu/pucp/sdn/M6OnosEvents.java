package pe.edu.pucp.sdn;

import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.TCP;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleEvent;
import org.onosproject.net.flow.FlowRuleListener;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.EthCriterion;
import org.onosproject.net.flow.criteria.PortCriterion;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficSelector;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class M6OnosEvents {
    private static final int PRIO_T1_SESSION_GATE = 39900;
    private static final int PACKET_PROCESSOR_PRIORITY = 20;
    private static final int PRIO_T4_PACKET_IN = 5;
    private static final int TABLE_REACTIVE_FALLBACK = 4;
    private static final long DEDUP_MS = 2000L;
    protected CoreService coreService;

    protected PacketService packetService;

    protected FlowRuleService flowRuleService;

    private final InternalPacketProcessor packetProcessor = new InternalPacketProcessor();
    private final InternalFlowListener flowListener = new InternalFlowListener();
    private final Map<String, Long> recentPackets = new ConcurrentHashMap<>();

    private ApplicationId appId;
    private String m6Url;
    private String securityToken;
    private String edgeSwitches;
    private boolean dryRun;
    private boolean packetInEnabled;

    protected void activate() {
        appId = coreService.registerApplication("pe.edu.pucp.sdn.m6-onos-events");
        m6Url = System.getProperty("m6.url", "http://192.168.201.251:8080");
        securityToken = System.getProperty("m6.token", "change-me");
        edgeSwitches = System.getProperty("m6.edgeSwitches", "of:00006a0757adfc4e");
        dryRun = Boolean.parseBoolean(System.getProperty("m6.dryRun", "false"));
        packetInEnabled = Boolean.parseBoolean(System.getProperty("m6.packetIn", "true"));

        flowRuleService.addListener(flowListener);
        if (packetInEnabled) {
            packetService.addProcessor(packetProcessor, PACKET_PROCESSOR_PRIORITY);
            installReactiveFallbackFlows();
            log("active with T4 packet-in enabled. edgeSwitches=" + edgeSwitches
                    + " selector=tcp_ipv4_wildcard"
                    + " m6Url=" + m6Url + " dryRun=" + dryRun);
        } else {
            log("active in flow-listener mode. m6Url=" + m6Url + " dryRun=" + dryRun);
        }
    }

    protected void deactivate() {
        if (packetInEnabled) {
            flowRuleService.removeFlowRulesById(appId);
            packetService.removeProcessor(packetProcessor);
        }
        flowRuleService.removeListener(flowListener);
        recentPackets.clear();
        log("stopped");
    }

    public void bindCoreService(CoreService service) {
        coreService = service;
    }

    public void unbindCoreService(CoreService service) {
        coreService = null;
    }

    public void bindPacketService(PacketService service) {
        packetService = service;
    }

    public void unbindPacketService(PacketService service) {
        packetService = null;
    }

    public void bindFlowRuleService(FlowRuleService service) {
        flowRuleService = service;
    }

    public void unbindFlowRuleService(FlowRuleService service) {
        flowRuleService = null;
    }

    private TrafficSelector reactiveSelector() {
        return DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPProtocol(IPv4.PROTOCOL_TCP)
                .build();
    }

    private void installReactiveFallbackFlows() {
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                .punt()
                .build();
        for (String rawDeviceId : edgeSwitches.split(",")) {
            String device = rawDeviceId.trim();
            if (device.isEmpty()) {
                continue;
            }
            DeviceId deviceId = DeviceId.deviceId(device);
            FlowRule rule = DefaultFlowRule.builder()
                    .forDevice(deviceId)
                    .fromApp(appId)
                    .withSelector(reactiveSelector())
                    .withTreatment(treatment)
                    .withPriority(PRIO_T4_PACKET_IN)
                    .makePermanent()
                    .forTable(TABLE_REACTIVE_FALLBACK)
                    .build();
            flowRuleService.applyFlowRules(rule);
        }
    }

    private final class InternalFlowListener implements FlowRuleListener {
        @Override
        public void event(FlowRuleEvent event) {
            if (event.type() != FlowRuleEvent.Type.RULE_REMOVED) {
                return;
            }
            FlowRule rule = event.subject();
            if (rule.tableId() != 1 || rule.priority() != PRIO_T1_SESSION_GATE) {
                return;
            }

            Map<String, Object> body = new HashMap<>();
            body.put("event", "RULE_REMOVED");
            body.put("deviceId", rule.deviceId().toString());
            body.put("tableId", rule.tableId());
            body.put("priority", rule.priority());
            body.put("flowId", rule.id().toString());
            body.put("timestamp", Instant.now().toString());

            for (Criterion criterion : rule.selector().criteria()) {
                if (criterion.type() == Criterion.Type.ETH_SRC) {
                    body.put("mac", ((EthCriterion) criterion).mac().toString());
                } else if (criterion.type() == Criterion.Type.IN_PORT) {
                    body.put("in_port", ((PortCriterion) criterion).port().toLong());
                }
            }
            postJson("/m6/flow_expired", body);
        }
    }

    private final class InternalPacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            if (context.isHandled()) {
                return;
            }
            InboundPacket packet = context.inPacket();
            Ethernet eth = packet.parsed();
            if (eth == null || eth.getEtherType() != Ethernet.TYPE_IPV4) {
                return;
            }
            IPv4 ipv4 = (IPv4) eth.getPayload();
            if (ipv4.getProtocol() != IPv4.PROTOCOL_TCP) {
                return;
            }
            TCP tcp = (TCP) ipv4.getPayload();
            String srcIp = IPv4.fromIPv4Address(ipv4.getSourceAddress());
            String dstIp = IPv4.fromIPv4Address(ipv4.getDestinationAddress());
            int dstPort = tcp.getDestinationPort();
            String key = eth.getSourceMAC() + "|" + srcIp + "|" + dstIp + "|" + dstPort
                    + "|" + packet.receivedFrom().deviceId() + "|" + packet.receivedFrom().port();
            if (isDuplicate(key)) {
                return;
            }

            Map<String, Object> body = new HashMap<>();
            body.put("src_ip", srcIp);
            body.put("src_mac", eth.getSourceMAC().toString());
            body.put("dst_mac", eth.getDestinationMAC().toString());
            body.put("dst_ip", dstIp);
            body.put("dst_port", dstPort);
            body.put("protocol", "TCP");
            body.put("switch_dpid", packet.receivedFrom().deviceId().toString());
            body.put("in_port", packet.receivedFrom().port().toLong());
            body.put("idle_timeout", 300);
            body.put("timestamp", Instant.now().toString());
            postJson("/m6/packet-in", body);
        }
    }

    private boolean isDuplicate(String key) {
        long now = System.currentTimeMillis();
        Long last = recentPackets.put(key, now);
        if (last != null && now - last < DEDUP_MS) {
            return true;
        }
        if (recentPackets.size() > 1000) {
            Iterator<Map.Entry<String, Long>> it = recentPackets.entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry<String, Long> entry = it.next();
                if (now - entry.getValue() > 30000L) {
                    it.remove();
                }
            }
        }
        return false;
    }

    private void postJson(String path, Map<String, Object> body) {
        if (dryRun) {
            log("DRY-RUN POST " + m6Url + path + " " + body);
            return;
        }
        try {
            URL url = new URL(m6Url + path);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(2000);
            conn.setReadTimeout(3000);
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-Security-Token", securityToken);
            byte[] payload = toJson(body).getBytes(StandardCharsets.UTF_8);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(payload);
            }
            int code = conn.getResponseCode();
            if (code < 200 || code >= 300) {
                log("M6 returned HTTP " + code + " for " + path);
            }
            conn.disconnect();
        } catch (Exception e) {
            log("Could not post event to M6 " + path + ": " + e);
        }
    }

    private void log(String message) {
        System.out.println("[m6-onos-events] " + message);
    }

    private String toJson(Map<String, Object> body) {
        StringBuilder sb = new StringBuilder();
        sb.append('{');
        boolean first = true;
        for (Map.Entry<String, Object> entry : body.entrySet()) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append('"').append(escape(entry.getKey())).append('"').append(':');
            Object value = entry.getValue();
            if (value == null) {
                sb.append("null");
            } else if (value instanceof Number || value instanceof Boolean) {
                sb.append(value);
            } else {
                sb.append('"').append(escape(String.valueOf(value))).append('"');
            }
        }
        sb.append('}');
        return sb.toString();
    }

    private String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
