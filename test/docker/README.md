# QUIC Distribution Docker Tests

This directory contains Docker-based tests for QUIC distribution across multiple nodes.

## Prerequisites

- Docker 20.10+
- Docker Compose 2.0+

## Quick Start

### 5-Node Cluster Test

Start a 5-node cluster with QUIC distribution:

```bash
cd test/docker

# Generate certificates (if not already done)
./scripts/generate_certs.sh

# Build and start the cluster
docker-compose up --build

# Or run in detached mode
docker-compose up -d --build

# View logs
docker-compose logs -f

# Run tests manually
docker-compose exec node1 erl_call -n node1@node1 -c quic_dist_test -a "nodes []"

# Stop the cluster
docker-compose down
```

### Run Automated Tests

```bash
# Full cluster test
docker-compose run --rm test_runner

# Or start cluster and run tests separately
docker-compose up -d node1 node2 node3 node4 node5
docker-compose run --rm test_runner /scripts/run_5node_cluster_test.sh
```

### NAT Traversal Test

Test nodes behind NAT:

```bash
cd test/docker

# Start NAT simulation
docker-compose -f docker-compose.nat.yml up --build

# Run NAT tests
docker-compose -f docker-compose.nat.yml run --rm nat_test_runner
```

### Failover Test

Test node failure and recovery:

```bash
cd test/docker
docker-compose up -d
docker-compose exec test_runner /scripts/run_failover_test.sh
```

## Test Scenarios

### 5-Node Cluster Test

Tests performed:
1. All nodes start successfully
2. Full mesh forms (each node connects to all others)
3. RPC calls work between all node pairs
4. Large message transfer (1MB)
5. Concurrent message handling (100 messages)
6. Node disconnection and reconnection
7. 0-RTT reconnection timing

### NAT Traversal Test

Tests performed:
1. Internal node discovers external address via STUN
2. External nodes can communicate
3. Internal node attempts NAT traversal
4. Connection migration capability

### Failover Test

Tests performed:
1. Single node failure handling
2. Mesh recovery after node restart
3. Network partition simulation
4. Partition healing
5. Rapid reconnection (0-RTT performance)

## Directory Structure

```
test/docker/
├── Dockerfile.node           # Erlang node image
├── docker-compose.yml        # 5-node cluster
├── docker-compose.nat.yml    # NAT simulation
├── certs/                    # Test certificates
│   ├── cert.pem
│   └── key.pem
├── scripts/
│   ├── start_node.sh         # Node startup script
│   ├── run_5node_cluster_test.sh
│   ├── run_failover_test.sh
│   └── run_nat_test.sh
└── README.md
```

## Configuration

### Environment Variables

Each node accepts these environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `NODE_NAME` | Erlang node name | `node@localhost` |
| `QUIC_DIST_PORT` | QUIC distribution port | `4433` |
| `CLUSTER_NODES` | Comma-separated node list | - |
| `NAT_ENABLED` | Enable NAT traversal | `false` |
| `STUN_SERVERS` | STUN server addresses | - |

### Network Configuration

The docker-compose files define these networks:

- `quic_mesh` (172.28.0.0/16): Main cluster network
- `external` (172.29.0.0/24): External network (NAT tests)
- `internal` (172.30.0.0/24): Internal NAT network

## Troubleshooting

### Nodes don't connect

1. Check certificates are valid:
   ```bash
   openssl x509 -in certs/cert.pem -text -noout
   ```

2. Check UDP connectivity:
   ```bash
   docker-compose exec node1 nc -uvz node2 4433
   ```

3. View node logs:
   ```bash
   docker-compose logs node1
   ```

### Test runner fails

1. Ensure all nodes are healthy:
   ```bash
   docker-compose ps
   ```

2. Check erl_call connectivity:
   ```bash
   docker-compose exec test_runner erl_call -n node1@node1 -c quic_dist_test -a "erlang node []"
   ```

### NAT tests fail

1. Verify NAT router is working:
   ```bash
   docker-compose -f docker-compose.nat.yml exec nat_router iptables -t nat -L
   ```

2. Check internal node can reach external:
   ```bash
   docker-compose -f docker-compose.nat.yml exec internal_node ping external_node1
   ```

## Manual Testing

Connect to a running node:

```bash
# From host
docker-compose exec node1 erl -remsh node1@node1 -setcookie quic_dist_test

# Check connected nodes
(node1@node1)1> nodes().

# Ping another node
(node1@node1)2> net_adm:ping('node2@node2').

# RPC call
(node1@node1)3> rpc:call('node3@node3', erlang, node, []).
```

## Performance Testing

Run a load test:

```bash
docker-compose exec node1 erl_call -n node1@node1 -c quic_dist_test -a "
    [rpc:call('node2@node2', erlang, now, []) || _ <- lists:seq(1, 1000)]
"
```

Measure reconnection time:

```bash
docker-compose exec test_runner /scripts/run_failover_test.sh 2>&1 | grep "Reconnection time"
```
