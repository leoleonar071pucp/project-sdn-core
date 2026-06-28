#!/usr/bin/env sh
set -eu

ONOS_HOME="${ONOS_HOME:-/root/onos}"
KARAF_HOME="${KARAF_HOME:-$ONOS_HOME/apache-karaf-4.2.9}"
APP_NAME="m6-onos-events"
APP_VERSION="1.0.0"
GROUP_PATH="pe/edu/pucp/sdn"
SRC_DIR="${SRC_DIR:-/tmp/m6-onos-events-src}"
BUILD_DIR="${BUILD_DIR:-/tmp/m6-onos-events-build}"
OAR_DIR="${OAR_DIR:-/tmp/m6-oar}"

CP="$KARAF_HOME/system/org/onosproject/onos-api/2.7.0/onos-api-2.7.0.jar:$KARAF_HOME/system/org/onosproject/onlab-misc/2.7.0/onlab-misc-2.7.0.jar"

rm -rf "$BUILD_DIR" "$OAR_DIR" "/tmp/$APP_NAME.jar" "/tmp/$APP_NAME.oar"
mkdir -p "$BUILD_DIR/classes/OSGI-INF"

javac -cp "$CP" -d "$BUILD_DIR/classes" \
  "$SRC_DIR/src/main/java/pe/edu/pucp/sdn/M6OnosEvents.java"
cp "$SRC_DIR/src/main/resources/OSGI-INF/m6-onos-events.xml" \
  "$BUILD_DIR/classes/OSGI-INF/"

cat > "$BUILD_DIR/MANIFEST.MF" <<EOF
Manifest-Version: 1.0
Bundle-ManifestVersion: 2
Bundle-SymbolicName: pe.edu.pucp.sdn.m6-onos-events
Bundle-Version: $APP_VERSION
Bundle-Name: M6 ONOS Events
Bundle-RequiredExecutionEnvironment: JavaSE-11
Service-Component: OSGI-INF/m6-onos-events.xml
Import-Package: org.onlab.packet,org.onosproject.core,org.onosproject.event,org.onosproject.net,org.onosproject.net.flow,org.onosproject.net.flow.criteria,org.onosproject.net.packet
EOF

jar cfm "/tmp/$APP_NAME.jar" "$BUILD_DIR/MANIFEST.MF" -C "$BUILD_DIR/classes" .

mkdir -p "$OAR_DIR/m2/$GROUP_PATH/$APP_NAME/$APP_VERSION"
cp "/tmp/$APP_NAME.jar" "$OAR_DIR/m2/$GROUP_PATH/$APP_NAME/$APP_VERSION/$APP_NAME-$APP_VERSION.jar"

cat > "$OAR_DIR/m2/$GROUP_PATH/$APP_NAME/$APP_VERSION/$APP_NAME-$APP_VERSION-features.xml" <<EOF
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<features xmlns="http://karaf.apache.org/xmlns/features/v1.2.0" name="pe.edu.pucp.sdn-m6-onos-events">
  <feature name="m6-onos-events" version="$APP_VERSION" description="M6 ONOS Events dry-run listener">
    <feature>onos-api</feature>
    <bundle>mvn:pe.edu.pucp.sdn/m6-onos-events/$APP_VERSION</bundle>
  </feature>
</features>
EOF

cat > "$OAR_DIR/app.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<app name="pe.edu.pucp.sdn.m6-onos-events" origin="PUCP SDN" version="$APP_VERSION"
     title="M6 ONOS Events" category="Security" url="http://pucp.edu.pe"
     featuresRepo="mvn:pe.edu.pucp.sdn/m6-onos-events/$APP_VERSION/xml/features"
     features="m6-onos-events" apps="">
  <description>Dry-run listener for M6 flow expiration and packet-in events.</description>
  <artifact>mvn:pe.edu.pucp.sdn/m6-onos-events/$APP_VERSION</artifact>
</app>
EOF

(cd "$OAR_DIR" && jar cf "/tmp/$APP_NAME.oar" app.xml m2)
ls -lh "/tmp/$APP_NAME.jar" "/tmp/$APP_NAME.oar"
