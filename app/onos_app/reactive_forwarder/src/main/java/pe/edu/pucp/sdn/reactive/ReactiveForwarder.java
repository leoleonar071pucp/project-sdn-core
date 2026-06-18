package pe.edu.pucp.sdn.reactive;

import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.TCP;
import org.onlab.packet.UDP;
import org.onlab.packet.VlanId;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Component(immediate = true)
public class ReactiveForwarder {

    private final Logger log = LoggerFactory.getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    private ReactivePacketProcessor processor = new ReactivePacketProcessor();
    private ApplicationId appId;
    
    // Ejecutor para no bloquear el hilo de procesamiento de paquetes de ONOS
    private ExecutorService executorService;
    
    // URL del Módulo 6
    private static final String M6_URL = "http://192.168.100.1:8080/m6/packet_in";

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("pe.edu.pucp.sdn.reactive");
        packetService.addProcessor(processor, PacketProcessor.director(2));
        executorService = Executors.newFixedThreadPool(4);
        log.info("ReactiveForwarder Started");
    }

    @Deactivate
    protected void deactivate() {
        packetService.removeProcessor(processor);
        executorService.shutdown();
        log.info("ReactiveForwarder Stopped");
    }

    private class ReactivePacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            if (context.isHandled()) {
                return;
            }

            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            if (ethPkt == null) {
                return;
            }

            // Solo nos interesa tráfico IPv4
            if (ethPkt.getEtherType() != Ethernet.TYPE_IPV4) {
                return;
            }

            IPv4 ipv4Packet = (IPv4) ethPkt.getPayload();
            
            // Ignorar broadcast/multicast. Algunas versiones de ONOS no exponen
            // IPv4.isMulticast()/isBroadcast(), asi que lo validamos por direccion.
            int dstAddress = ipv4Packet.getDestinationAddress();
            boolean isBroadcast = dstAddress == 0xFFFFFFFF;
            boolean isMulticast = (dstAddress & 0xF0000000) == 0xE0000000;
            if (isMulticast || isBroadcast) {
                return;
            }

            // Extraer VLAN
            short vlanId = ethPkt.getVlanID();
            if (vlanId == Ethernet.VLAN_UNTAGGED) {
                // Si no tiene VLAN, lo ignoramos para la Tabla 2
                return;
            }

            String ipDst = IPv4.fromIPv4Address(ipv4Packet.getDestinationAddress());
            String ipSrc = IPv4.fromIPv4Address(ipv4Packet.getSourceAddress());
            String srcMac = ethPkt.getSourceMAC().toString();
            int tcpPort = 0;

            if (ipv4Packet.getProtocol() == IPv4.PROTOCOL_TCP) {
                TCP tcpPacket = (TCP) ipv4Packet.getPayload();
                tcpPort = tcpPacket.getDestinationPort();
            } else if (ipv4Packet.getProtocol() == IPv4.PROTOCOL_UDP) {
                UDP udpPacket = (UDP) ipv4Packet.getPayload();
                tcpPort = udpPacket.getDestinationPort();
            }

            String deviceId = pkt.receivedFrom().deviceId().toString();
            String inPort = pkt.receivedFrom().port().toString();

            // Enviar notificación a M6 de forma asíncrona
            final int finalVlanId = vlanId;
            final int finalTcpPort = tcpPort;
            
            executorService.execute(() -> {
                try {
                    URL url = new URL(M6_URL);
                    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                    conn.setRequestMethod("POST");
                    conn.setRequestProperty("Content-Type", "application/json; utf-8");
                    conn.setRequestProperty("Accept", "application/json");
                    conn.setDoOutput(true);

                    String jsonInputString = String.format(
                        "{\"src_mac\": \"%s\", \"src_ip\": \"%s\", \"vlan_id\": %d, \"ip_dst\": \"%s\", \"tcp_port\": %d, \"device_id\": \"%s\", \"in_port\": \"%s\"}",
                        srcMac, ipSrc, finalVlanId, ipDst, finalTcpPort, deviceId, inPort
                    );

                    try(OutputStream os = conn.getOutputStream()) {
                        byte[] input = jsonInputString.getBytes(StandardCharsets.UTF_8);
                        os.write(input, 0, input.length);			
                    }

                    int code = conn.getResponseCode();
                    log.debug("Notificado M6 para VLAN {} a {}:{} -> HTTP {}", finalVlanId, ipDst, finalTcpPort, code);
                } catch (Exception e) {
                    log.error("Error contactando M6: {}", e.getMessage());
                }
            });

            // No hacemos context.block() para permitir que otras apps vean el paquete si lo necesitan.
        }
    }
}
