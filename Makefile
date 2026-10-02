.PHONY: check fmt test build perf scale e2e e2e-subnet e2e-exit e2e-nat e2e-nat-matrix e2e-nat-topologies e2e-ipv6-discovery e2e-candidates e2e-interfaces e2e-pmtu e2e-neighbors e2e-boot e2e-dhcp e2e-dhcp-policy e2e-membership e2e-weaknet

check:
	cargo fmt --check
	cargo clippy --locked --all-targets -- -D warnings
	cargo test --locked --all-targets
	python3 -m unittest discover -s tests/scale -p 'test_*.py'
	python3 -m unittest discover -s tests/perf -p 'test_*.py'

fmt:
	cargo fmt

test:
	cargo test --locked --all-targets

build:
	cargo build --locked --release

# Measurement only, not an acceptance threshold. Full raw iperf and CPU counters.
perf: build
	python3 tests/perf/throughput.py

# Extended real TUN matrix: four FEC/RTX policies, eight kernel fault profiles.
e2e-weaknet: build
	python3 tests/e2e/weaknet_netns.py --output target/e2e-weaknet.json

# Actual Linux GSO/GRO datagram boundaries, and plain/offloaded adapter fallback.
.PHONY: e2e-offload e2e-tun-io
e2e-offload: build
	python3 tests/e2e/offload_netns.py --output target/e2e-offload.json

e2e-tun-io:
	python3 tests/e2e/tun_io_netns.py

# Actual cold boots in two isolated NixOS VMs; separate from host-netns suites.
e2e-boot:
	nix build .\#checks.$$(nix eval --impure --raw --expr builtins.currentSystem).boot --out-link target/boot-result -L

e2e-dhcp:
	nix build .\#checks.$$(nix eval --impure --raw --expr builtins.currentSystem).dhcp --out-link target/dhcp-result -L

e2e-dhcp-policy: build
	python3 tests/e2e/dhcp_policy_netns.py --output target/e2e-dhcp-policy.json

e2e-membership: build
	python3 tests/e2e/membership_netns.py --output target/e2e-membership.json

# Isolated namespaces; requires non-interactive sudo or root.
e2e: build
	python3 tests/e2e/membership_netns.py --output target/e2e-membership.json
	python3 tests/e2e/overlay_netns.py --collision --output target/e2e-overlay-collision.json
	python3 tests/e2e/subnet_netns.py --output target/e2e-subnet.json
	python3 tests/e2e/exit_netns.py --output target/e2e-exit.json
	python3 tests/e2e/nat_netns.py --output target/e2e-nat.json
	python3 tests/e2e/candidates_netns.py --output target/e2e-candidates.json
	python3 tests/e2e/pmtu_netns.py --output target/e2e-pmtu.json
	python3 tests/e2e/offload_netns.py --output target/e2e-offload.json
	python3 tests/e2e/neighbors_netns.py --output target/e2e-neighbors.json
	python3 tests/e2e/dhcp_policy_netns.py --output target/e2e-dhcp-policy.json

# Duplicate dual-stack LANs, explicit route selection, restart and crash guards.
e2e-subnet: build
	python3 tests/e2e/subnet_netns.py --output target/e2e-subnet.json

# Dual-stack exit, DNS bootstrap, strict RPF and persistent fail-closed guards.
e2e-exit: build
	python3 tests/e2e/exit_netns.py --output target/e2e-exit.json

# Measured UDP mapping/filtering behavior, direct upgrades and relay recovery.
e2e-nat: build
	python3 tests/e2e/nat_netns.py --output target/e2e-nat.json

# All 81 ordered endpoint pairs, including heterogeneous NATs and both roles.
e2e-nat-matrix: build
	python3 tests/e2e/nat_netns.py --case matrix --output target/e2e-nat-matrix.json

# Both sides behind two routers; shared public IP with hairpin on/off.
e2e-nat-topologies: build
	python3 tests/e2e/nat_topologies_netns.py --output target/e2e-nat-topologies.json

# Dead IPv4 candidate, IPv6 stateful opening, relay fallback and bootstrap loss.
e2e-ipv6-discovery: build
	python3 tests/e2e/ipv6_discovery_netns.py --output target/e2e-ipv6-discovery.json
	python3 tests/e2e/ipv6_discovery_netns.py --ipv4-mode delay --output target/e2e-ipv6-delayed-candidate.json

# Repeated real NAT rebinding and host interface candidate lifecycle.
e2e-candidates: build
	python3 tests/e2e/candidates_netns.py --output target/e2e-candidates.json

# Event-driven interface churn, snapshot timeout/failure, periodic resync.
e2e-interfaces: build
	python3 tests/e2e/interfaces_netns.py --output target/e2e-interfaces.json

# Real MTU shrink/growth, ICMP filtering and asymmetric datagram sizes.
e2e-pmtu: build
	python3 tests/e2e/pmtu_netns.py --output target/e2e-pmtu.json

# Production idle timer, capacity reuse, essential bridges and concurrent pruning.
e2e-neighbors: build
	python3 tests/e2e/neighbors_netns.py --output target/e2e-neighbors.json

# Real daemon processes; no TUN or host network modifications.
scale: build
	python3 tests/scale/daemon_scale.py --nodes 100 --output target/daemon-scale-100.json

.PHONY: scale-rekey
# Natural 120 s rotation; verify every outgoing epoch, PMTU and multihop traffic.
scale-rekey: build
	python3 tests/scale/daemon_scale.py --nodes 100 --seconds 135 --verify-rekey --output target/daemon-scale-100-rekey.json

.PHONY: perf-crossed-rekey
# Real 120 s rotation, handshake-only delay; sustained TUN traffic on crossed epochs.
perf-crossed-rekey: build
	python3 tests/perf/crossed_rekey.py --output target/perf-crossed-rekey.json

.PHONY: perf-rekey-transition
# Keep TCP and 50 ICMP/s running across rotation; do not hide its transient in warmup.
perf-rekey-transition: build
	python3 tests/perf/crossed_rekey.py --transition --output target/perf-rekey-transition.json

.PHONY: scale-tun
# Real TUN in 100 isolated namespaces: collision merge, partition/rejoin, relay restart.
scale-tun: build
	python3 tests/scale/tun_scale.py --nodes 100 --output target/tun-scale-100.json

.PHONY: e2e-tun-routes
# Kernel route ACKs, exclusive adds and interface-bound deletes in an owned netns.
e2e-tun-routes:
	python3 tests/e2e/tun_routes_netns.py

.PHONY: e2e-scale-ping
# Fixed-count scale probes: high RTT must pass; deterministic loss must fail.
e2e-scale-ping:
	python3 tests/scale/ping_netns.py

.PHONY: perf-gigabit
# Same-host comparison with both fixture WAN egresses shaped to 1000 Mbit/s.
perf-gigabit: build
	python3 tests/perf/throughput.py --underlay-mbps 1000 --warmup 10 --seconds 15 --repeats 3 --output target/perf-nnlan-underlay-1000.json

.PHONY: perf-compare
# Same-host IPv4 direct-path comparison against kernel WireGuard and wireguard-go.
# Use compare.py --cases ipv4 ipv6 ipv4_reverse for the full direction matrix.
perf-compare: build
	python3 tests/perf/compare.py --cases ipv4 --output target/perf-comparison.json

# Saturated TUN ingress must keep UDP/admin alive and revalidate policy on retry.
.PHONY: e2e-backpressure
e2e-backpressure: build
	python3 tests/e2e/backpressure_netns.py --output target/e2e-backpressure.json
