# Kubernetes deployment

On Kubernetes you can drop `ssagent` entirely: mount the bundle from a ConfigMap and let Vector's
`--watch-config` pick up changes. The agent exists for virtual machine and Compose deployments,
where something has to fetch the config.

If you do keep the agent, it needs no extra permissions. It polls the control plane over mutual
TLS and writes to an `emptyDir`.

## Shape

- **control**: one replica, a PersistentVolumeClaim for SQLite, a Service on 8000.
- **node**: a Deployment or DaemonSet, N replicas, no state. A Service of type LoadBalancer on
  UDP 5514 with `externalTrafficPolicy: Local` so the source address survives the hop.
- Node pods run non-root with a read-only root filesystem and all capabilities dropped. Add
  `CAP_NET_BIND_SERVICE` only if you bind port 514 rather than 5514.

## Before cutover

Verify that nothing downstream keys off the packet source IP address (D-16). After insertion,
every packet reaches ELK from the proxy. It is cheap to check and expensive to discover late.


## Sizing

Measured with `ssperf --scale`. See the architecture document for the full curve.

```yaml
resources:
  requests: { cpu: "2", memory: "512Mi" }
  limits:   { cpu: "2", memory: "1Gi" }
```

Two cores per replica, not more. Throughput does not scale with Vector worker threads, because a
single UDP socket is drained by a single reader. One core meets the 20,000 EPS target but shows
hundreds of milliseconds of p99 latency; a second core removes that. A fourth buys nothing.

**Scale with replicas, and the measured numbers are unambiguous:**

| Configuration | Throughput | Efficiency |
|---|---|---|
| 8 threads, 1 process | 1.05x | 13% |
| 4 processes | **4.17x** | **104%** |

Four replicas sustained 99,999 EPS with zero loss and zero kernel drops. Size at roughly one
replica per 30,000 EPS of expected peak, plus one for headroom.

Disable session stickiness on the Service or load balancer. UDP has no sessions, and stickiness
pins all traffic to one replica, which is the configuration that measured 1.05x.

Raise the receive buffer on the node before adding replicas. Every overload we measured was a
socket buffer overflow, not a CPU shortage:

```yaml
# Requires a privileged init container or a node-level sysctl DaemonSet.
sysctls:
  - name: net.core.rmem_max
    value: "33554432"
```

The generated Vector config already requests 25 MB via `receive_buffer_bytes`, but the kernel
silently caps it at `net.core.rmem_max`. If those disagree, you lose events and only the kernel
counters will tell you (D-24).
