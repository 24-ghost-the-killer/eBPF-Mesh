# 0003 Parse in-band VLAN tags; disable rx-vlan offload on PoPs

**Status:** Accepted (phase 1)

**Context.** Spec §5.1 asks to parse up to 2 VLAN tags. On most physical NICs
the driver strips the outer tag into skb/descriptor metadata (rx-vlan offload)
before XDP sees it, so an in-packet parser alone would see untagged frames on
real hardware and tagged frames in veth tests.

**Decision.** The parser handles up to two in-band tags (802.1Q, 802.1ad); a
third tag is malformed. On PoPs with tagged uplinks, rx-vlan offload is
disabled (`ethtool -K <iface> rxvlan off`); from phase 4 the agent does this
on start and refuses to run if it cannot. Reading the stripped tag with the
`bpf_xdp_metadata_rx_vlan_tag` kfunc (kernel 6.8+, driver support varies) is
a possible later alternative.

**Consequences.** Same parser behaviour in tests and on hardware.
