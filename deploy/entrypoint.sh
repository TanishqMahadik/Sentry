#!/bin/bash
# Sentry Mininet container entrypoint.
# Starts OVS daemon, runs the topology in run-mode (keeps network alive),
# then keeps the container alive so attacks can be launched via `docker exec`.

set -e

echo "=== Starting OVS ==="
mkdir -p /var/run/openvswitch /etc/openvswitch
ovsdb-tool create /etc/openvswitch/conf.db 2>/dev/null || true
ovsdb-server --remote=punix:/var/run/openvswitch/db.sock \
    --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
    --pidfile --detach --log-file
ovs-vsctl --no-wait init
ovs-vswitchd --pidfile --detach --log-file
echo "=== OVS started ==="

echo "=== Starting Mininet topology (run mode) ==="
cd /lab
python3 topo_lab.py --run &
TOPO_PID=$!

# Give the topology time to build and connect to ONOS
sleep 15

echo "=== Topology running in background (PID $TOPO_PID) ==="
echo "=== Container ready. Launch attacks via: docker exec sentry-mininet python3 /lab/attacks.py <type> ==="
tail --pid=$TOPO_PID -f /dev/null || true