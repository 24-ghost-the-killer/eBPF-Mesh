# eBPF Mesh

A lab-scale anycast DDoS-scrubbing platform. Every PoP announces the same
anycast prefix with BIRD 2, an XDP program on the PoP's NIC filters traffic
per customer, and clean packets are tunnelled (IPIP) to the customer's origin.
Analysis is distributed over NATS workers, which share Ed25519-signed
mitigation decisions with every PoP.

**Lab only.** Uses documentation/private address ranges and private ASNs.

## Status

**Phase 0 (scaffolding): done.** The XDP program parses Ethernet / 802.1Q /
QinQ / IPv4 / IPv6 (+ extension headers) / TCP / UDP / ICMP with bounded loops,
classifies every frame into per-CPU counters, and passes everything
(observe-only). `meshctl` attaches, detaches and reads counters. The agent
and worker crates exist as config-validating stubs.

Roadmap and design: [docs/architecture.md](docs/architecture.md).

## Quick start

```sh
make test                 # host dataplane tests + cargo test (Linux or macOS)
make docker-test          # full suite incl. verifier + veth test, in Docker

# on Linux
make
sudo make test-bpf
sudo make test-integration
sudo target/linux-$(uname -m)/release/meshctl attach -i <iface> \
     --obj build/linux-$(uname -m)/em_xdp.bpf.o
sudo target/linux-$(uname -m)/release/meshctl stats -i <iface> --watch 1
```

Details, the VM setup and known limitations: [docs/running.md](docs/running.md).
Design records: [docs/decisions.md](docs/decisions.md).

## Layout

```
ebpf/          XDP program (C)
userspace/     Rust workspace: common, ctl (meshctl), agent, worker
tests/         bpf/ (host + BPF_PROG_TEST_RUN), integration/ (veth/netns)
configs/       example configs
lab/           anycast lab (Phase 4)
scripts/       dev VM setup, dev container
docs/          architecture, running, decisions
```

## License

Per directory, see [LICENSE](LICENSE): the BPF code is
GPL-2.0-only OR BSD-2-Clause; everything else is MIT OR Apache-2.0.
