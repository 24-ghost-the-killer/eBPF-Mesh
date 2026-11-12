#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Sets up a PoP server from the control-plane host, in three steps:
#   1. a NATS user for the PoP (created and loaded into the running NATS if
#      it has none; init.sh already made one per SENTINEL_POPS id),
#   2. the PoP binaries and XDP object, built in Docker (deploy/docker/Dockerfile.pop),
#   3. the Ansible playbook (deploy/ansible) from a container: guard rails,
#      firewall, BIRD, agent, health check.
# Dry run by default: BGP sessions come up, nothing is announced.
#
#   scripts/add-pop.sh --id pop-1 --host 192.168.1.52 --user ubuntu --ask-pass
#
#   --id ID               PoP id: a-z, 0-9 and -, up to 32 characters
#   --host ADDR           the server's management address (SSH)
#   --user NAME           SSH user with sudo (default: root)
#   --ask-pass            log in with a password (SSH and sudo) instead of a key
#   --region NAME         shown in the admin panel (default: the id)
#   --uplink IFACE        interface for XDP (default: the server's default-route interface)
#   --pop-ip IP           the PoP's own IPv4 on the uplink (default: that interface's address)
#   --upstream NAME,IP,ASN[,MAX]   a BGP neighbour (repeat). Lab mode may have none.
#   --mgmt CIDR           may reach SSH and metrics on the PoP (repeat; default: this host)
#   --nats-ip IP          put NATS_HOSTNAME -> IP into the PoP's /etc/hosts (no DNS)
#   --nexthop-mac MAC     where XDP sends packets (default: back to each frame's sender)
#   --generic-xdp         allow generic XDP (labs; drivers without native XDP)
#   --production          real ASN and prefixes (SENTINEL_ASN, ANYCAST_PREFIX4/6 in
#                         state/.env); refuses documentation ranges. Default: lab mode.
#   --announce            go-live: announce the prefixes (asks to confirm in production)
#   -- ARGS               passed to ansible-playbook (--check, -v, ...)
#
# Site data stays in state/ (git-ignored): the inventory with the PoP's NATS
# seed (state/pops/<id>.yml, mode 600) and the SSH known_hosts.
set -euo pipefail
C="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(cd "$C/../.." && pwd)"
S="$C/state"
N="$S/nats"
die() { echo "add-pop: $*" >&2; exit 1; }
usage() { sed -n '3,30p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

ID="" HOST="" USER_="root" REGION="" UPLINK="" POP_IP="" NATS_IP="" NEXTHOP="" ASK=0
GENERIC=false PROD=0 ANNOUNCE=0 UPSTREAMS=() MGMT=() EXTRA=()
while [ $# -gt 0 ]; do
	case $1 in
	--id) ID=$2; shift ;;
	--host) HOST=$2; shift ;;
	--user) USER_=$2; shift ;;
	--ask-pass) ASK=1 ;;
	--region) REGION=$2; shift ;;
	--uplink) UPLINK=$2; shift ;;
	--pop-ip) POP_IP=$2; shift ;;
	--upstream) UPSTREAMS+=("$2"); shift ;;
	--mgmt) MGMT+=("$2"); shift ;;
	--nats-ip) NATS_IP=$2; shift ;;
	--nexthop-mac) NEXTHOP=$2; shift ;;
	--generic-xdp) GENERIC=true ;;
	--production) PROD=1 ;;
	--announce) ANNOUNCE=1 ;;
	-h | --help) usage ;;
	--) shift; EXTRA=("$@"); break ;;
	*) echo "add-pop: unknown option $1" >&2; usage 2 ;;
	esac
	shift
done

# ---- checks -------------------------------------------------------------------------------------
[ -f "$S/api.env" ] || die "no control-plane state in $S: run scripts/init.sh first"
[[ $ID =~ ^[a-z0-9-]{1,32}$ ]] || die "--id: a-z, 0-9 and -, up to 32 characters"
[ -n "$HOST" ] || die "--host is required"
ip4='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
for v in "$POP_IP" "$NATS_IP"; do [ -z "$v" ] || [[ $v =~ $ip4 ]] || die "not an IPv4 address: $v"; done
[ -z "$NEXTHOP" ] || [[ $NEXTHOP =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]] || die "--nexthop-mac: aa:bb:cc:dd:ee:ff"
[[ $UPLINK =~ ^[A-Za-z0-9._-]{0,15}$ ]] || die "--uplink: not an interface name"
[[ $USER_ =~ ^[a-z_][a-z0-9_.-]*$ ]] || die "--user: not a user name"
command -v docker >/dev/null || die "needs docker"
set -a
# shellcheck disable=SC1091
. "$S/.env"
set +a
: "${NATS_HOSTNAME:?}" "${ANYCAST_PREFIX4:?}" "${TUNNEL_EP4:?}"
if [ "$PROD" = 1 ]; then
	: "${SENTINEL_ASN:?production: set SENTINEL_ASN in state/.env}"
	[ ${#UPSTREAMS[@]} -gt 0 ] || die "production: give at least one --upstream"
fi
ASN=${SENTINEL_ASN:-65010}
PREFIXES="\"$ANYCAST_PREFIX4\"${ANYCAST_PREFIX6:+, \"$ANYCAST_PREFIX6\"}"

# This host as the PoP sees it: the default for --mgmt and the Prometheus source.
SELF=$(ip -4 route get "$(getent ahostsv4 "$HOST" | awk 'NR == 1 { print $1 }')" 2>/dev/null |
	sed -n 's/.* src \([0-9.]*\).*/\1/p')
[ -n "$SELF" ] || die "cannot find a route to $HOST"
[ ${#MGMT[@]} -gt 0 ] || MGMT=("$SELF/32")

if [ "$ANNOUNCE" = 1 ] && [ "$PROD" = 1 ]; then
	echo "This announces $ANYCAST_PREFIX4${ANYCAST_PREFIX6:+ and $ANYCAST_PREFIX6} from AS$ASN on the internet via $ID."
	read -r -p "Type the PoP id to confirm: " answer
	[ "$answer" = "$ID" ] || die "not confirmed"
fi

dc() { docker compose -f "$C/docker-compose.yml" --env-file "$S/.env" "$@"; }

# ---- 1. NATS user -------------------------------------------------------------------------------
if [ ! -s "$N/$ID.nk" ]; then
	echo "creating the NATS user $ID..."
	docker image inspect sentinel-control:local >/dev/null 2>&1 || dc build -q bootstrap
	pub=$(docker run --rm --user "$(id -u):$(id -g)" -v "$N:/out" sentinel-control:local \
		sentinel-worker nkey generate --out "/out/$ID.nk")
	chmod 600 "$N/$ID.nk"
	# Rewrite in place: the file is bind-mounted into the NATS container.
	python3 - "$N/server.json" "$ID" "$pub" "$REPO/deploy/nats/render-config.py" <<'PY'
import importlib.util, json, sys
path, pop, nkey, rc = sys.argv[1:]
spec = importlib.util.spec_from_file_location("render_config", rc)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
if not m.NKEY.match(nkey):
    sys.exit(f"not a user nkey: {nkey!r}")
with open(path) as f:
    conf = json.load(f)
conf["authorization"]["users"].append(m.pop_user(pop, nkey))
text = json.dumps(conf, indent=2) + "\n"
with open(path, "w") as f:
    f.write(text)
PY
	if ! grep -Eq "^SENTINEL_POPS=\"?([^\"]* )?$ID( |\"|\$)" "$S/.env"; then
		sed -i.bak -E "s/^SENTINEL_POPS=\"?([^\"#]*[^\" #])\"?/SENTINEL_POPS=\"\1 $ID\"/" "$S/.env"
		rm -f "$S/.env.bak"
	fi
	dc kill -s HUP nats >/dev/null
	echo "NATS reloaded with the user $ID"
fi

# ---- 2. PoP binaries ------------------------------------------------------------------------------
ART="$REPO/build/pop"
echo "building the PoP binaries (first time: several minutes)..."
docker build -q -f "$REPO/deploy/docker/Dockerfile.pop" --target out --output "type=local,dest=$ART" "$REPO" >/dev/null
docker build -q -t sentinel-ansible:local -f "$REPO/deploy/docker/Dockerfile.ansible" "$REPO/deploy/docker" >/dev/null

# ---- 3. inventory and playbook --------------------------------------------------------------------
mkdir -p "$S/pops"
chmod 700 "$S/pops"
INV="$S/pops/$ID.yml"
# Unset: Ansible takes them from the server's facts (default-route interface).
if [ -n "$UPLINK" ]; then UPLINK_V=$UPLINK; else UPLINK_V='{{ ansible_default_ipv4.interface }}'; fi
if [ -n "$POP_IP" ]; then POP_IP_V=$POP_IP; else
	POP_IP_V="{{ hostvars[inventory_hostname]['ansible_' ~ pop_uplink_iface | regex_replace('[.-]', '_')].ipv4.address }}"
fi
yaml_list() { local out="" x; for x in "$@"; do out+="${out:+, }\"$x\""; done; echo "[$out]"; }
{
	echo "# Generated by scripts/add-pop.sh: holds the PoP's NATS seed (secret)."
	echo "all:"
	echo "  children:"
	echo "    pops:"
	echo "      hosts:"
	echo "        $ID:"
	echo "          ansible_host: \"$HOST\""
	echo "          ansible_user: \"$USER_\""
	echo "          pop_id: \"$ID\""
	echo "          pop_region: \"${REGION:-$ID}\""
	echo "          pop_uplink_iface: \"$UPLINK_V\""
	echo "          pop_ip4: \"$POP_IP_V\""
	echo "          bgp_router_id: \"{{ pop_ip4 }}\""
	[ -z "$NEXTHOP" ] || echo "          pop_nexthop_mac: \"$NEXTHOP\""
	echo "          sentinel_nats_nkey_seed: \"$(tr -d '\n' <"$N/$ID.nk")\""
	echo "          bgp_upstreams:"
	[ ${#UPSTREAMS[@]} -gt 0 ] || echo "            []"
	for u in "${UPSTREAMS[@]}"; do
		IFS=, read -r name nb asn max <<<"$u"
		[[ $name =~ ^[A-Za-z0-9_]{1,32}$ && -n $nb && $asn =~ ^[0-9]+$ ]] || die "--upstream NAME,IP,ASN[,MAX]: $u"
		echo "            - {name: $name, neighbor: \"$nb\", asn: $asn, max_prefix: ${max:-10}}"
	done
	echo "  vars:"
	echo "    sentinel_lab_mode: $([ "$PROD" = 1 ] && echo false || echo true)"
	echo "    sentinel_asn: $ASN"
	echo "    sentinel_prefixes: [$PREFIXES]"
	echo "    sentinel_tunnel_ep4: \"$TUNNEL_EP4\""
	echo "    bgp_export_enabled: $([ "$ANNOUNCE" = 1 ] && echo true || echo false)"
	echo "    mgmt_cidrs: $(yaml_list "${MGMT[@]}")"
	echo "    prometheus_cidrs: [\"$SELF/32\"]"
	echo "    nats_url: \"tls://$NATS_HOSTNAME:${NATS_PORT:-4222}\""
	[ -z "$NATS_IP" ] || echo "    nats_host_ip: \"$NATS_IP\""
	echo "    nats_ca_file: /nats-ca.pem"
	echo "    sentinel_artifacts_dir: /artifacts"
	echo "    agent_allow_generic_xdp: $GENERIC"
	echo "    ansible_ssh_common_args: \"-o UserKnownHostsFile=/pops/known_hosts\""
} >"$INV.tmp"
chmod 600 "$INV.tmp"
mv "$INV.tmp" "$INV"

pass=()
[ "$ASK" = 1 ] && pass=(--ask-pass --ask-become-pass)
tty=()
[ -t 0 ] && tty=(-it)
ssh_mount=()
[ -d "$HOME/.ssh" ] && ssh_mount=(-v "$HOME/.ssh:/ssh-host:ro")
echo "running the PoP playbook against $USER_@$HOST..."
docker run --rm "${tty[@]}" --network host \
	-v "$REPO/deploy:/deploy:ro" -v "$S/pops:/pops" -v "$N/ca.pem:/nats-ca.pem:ro" -v "$ART:/artifacts:ro" \
	"${ssh_mount[@]}" \
	-e ANSIBLE_CONFIG=/deploy/ansible/ansible.cfg \
	-e ANSIBLE_SSH_ARGS="-o ControlMaster=auto -o ControlPersist=60s -o StrictHostKeyChecking=accept-new" \
	-e ANSIBLE_HOST_KEY_CHECKING=False \
	-e HOST_UID="$(id -u):$(id -g)" \
	sentinel-ansible:local sh -c '
		mkdir -p /root/.ssh && chmod 700 /root/.ssh
		for k in /ssh-host/id_*; do [ -f "$k" ] && cp "$k" /root/.ssh/ && chmod 600 "/root/.ssh/${k##*/}"; done
		ansible-playbook "$@"; rc=$?
		chown "$HOST_UID" /pops/known_hosts 2>/dev/null
		exit $rc' sh \
	-i "/pops/$ID.yml" /deploy/ansible/playbooks/pop.yml "${pass[@]}" "${EXTRA[@]}"

# ---- Prometheus target -----------------------------------------------------------------------------
T="$C/prometheus/targets/pops.json"
python3 - "$T" "$ID" "$HOST" <<'PY'
import json, sys
path, pop, host = sys.argv[1:]
try:
    with open(path) as f:
        targets = json.load(f)
except (OSError, ValueError):
    targets = []
target = f"{host}:9466"
# One entry per PoP and per address (a server re-used under another id).
targets = [t for t in targets if t.get("labels", {}).get("pop") != pop and target not in t.get("targets", [])]
targets.append({"targets": [target], "labels": {"pop": pop}})
with open(path, "w") as f:
    json.dump(targets, f, indent=2)
    f.write("\n")
PY

cat <<MSG

PoP $ID is set up ($([ "$ANNOUNCE" = 1 ] && echo "announcing" || echo "dry run: nothing announced")).
  on the PoP:   sudo sentinelctl stats; systemctl status sentinel-agent; sudo birdc show protocols
  admin panel:  Platform admin -> PoPs shows $ID as up within a few seconds
  metrics:      Prometheus scrapes $HOST:9466 (state: Grafana)
MSG
