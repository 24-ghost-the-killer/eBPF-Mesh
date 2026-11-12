#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Render the NATS server configuration (ADR 0014).

One account, one user per component, each identified by an nkey and allowed
to publish/subscribe only to its own subjects:

  admin      everything (operators)
  api        write the KV buckets; read config.ack.>, health.>, stats.>,
             attack.>, decision.global; request probe.> (ADR 0020); publish
             decision.global (admin decisions, ADR 0021)
  pop <id>   publish  telemetry.<id>.>, stats.<id>, health.<id>, config.ack.<id>
             read     the KV buckets tenants, services, rules, platform, keys
             subscribe decision.global, probe.<id> (and answer it)
             (writing to KV is NOT allowed)
  worker <id> subscribe telemetry.>, stats.>; read KV rules (allowlists);
             publish attack.>, decision.global

TLS is mandatory; JetStream stores the KV buckets.

Usage:
  render-config.py --listen 127.0.0.1:4222 --cert server.pem --key server.key \\
      --store /var/lib/nats --admin UADMIN... [--api UAPI...] --pop lab1=UPOP1... [--pop ...]
      [--worker worker-1=UWORKER...]
The output is JSON, which nats-server accepts as configuration.
"""
import argparse
import json
import re
import sys

KV_BUCKETS = ["tenants", "services", "rules", "platform", "keys"]
POP_ID = re.compile(r"^[a-z0-9-]{1,32}$")
NKEY = re.compile(r"^U[A-Z2-7]{55}$")


def kv_read_permissions(buckets=KV_BUCKETS):
    """JetStream API subjects needed to read (get, watch, list) KV buckets."""
    subjects = ["$JS.API.INFO"]
    for b in buckets:
        s = f"KV_{b}"
        subjects += [
            f"$JS.API.STREAM.INFO.{s}",
            f"$JS.API.STREAM.MSG.GET.{s}",
            f"$JS.API.DIRECT.GET.{s}",
            f"$JS.API.DIRECT.GET.{s}.>",
            f"$JS.API.CONSUMER.CREATE.{s}",
            f"$JS.API.CONSUMER.CREATE.{s}.>",
            f"$JS.API.CONSUMER.INFO.{s}.>",
            f"$JS.API.CONSUMER.DELETE.{s}.>",
            f"$JS.FC.{s}.>",
        ]
    return subjects


def api_user(nkey):
    """The control-plane API: writes KV, reads what the agents publish."""
    publish = ["$JS.API.INFO", "probe.>", "decision.global"]
    for b in KV_BUCKETS:
        publish += [f"$KV.{b}.>", f"$JS.API.STREAM.INFO.KV_{b}", f"$JS.API.STREAM.MSG.GET.KV_{b}"]
    return {
        "nkey": nkey,
        "permissions": {
            "publish": {"allow": publish},
            "subscribe": {"allow": ["config.ack.>", "health.>", "stats.>", "attack.>",
                                    "decision.global", "_INBOX.>"]},
        },
    }


def pop_user(pop, nkey):
    return {
        "nkey": nkey,
        "permissions": {
            "publish": {
                "allow": [
                    f"telemetry.{pop}.>",
                    f"stats.{pop}",
                    f"health.{pop}",
                    f"config.ack.{pop}",
                ]
                + kv_read_permissions()
            },
            "subscribe": {"allow": ["decision.global", f"probe.{pop}", "_INBOX.>"]},
            # Lets the agent answer probe requests (reply subjects only).
            "allow_responses": {"max": 1, "expires": "10s"},
        },
    }


def worker_user(worker, nkey):
    """An analysis worker: reads telemetry, stats and allowlists; publishes
    attacks and signed decisions (ADR 0021)."""
    return {
        "nkey": nkey,
        "permissions": {
            "publish": {"allow": ["attack.>", "decision.global"]
                        + kv_read_permissions(["rules"])},
            "subscribe": {"allow": ["telemetry.>", "stats.>", "_INBOX.>"]},
        },
    }


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--listen", required=True)
    p.add_argument("--cert", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--store", required=True)
    p.add_argument("--admin", required=True, help="admin user's public nkey")
    p.add_argument("--api", help="the API's public nkey")
    p.add_argument("--pop", action="append", default=[], metavar="ID=NKEY")
    p.add_argument("--worker", action="append", default=[], metavar="ID=NKEY")
    a = p.parse_args()

    users = []
    for nk in [a.admin]:
        if not NKEY.match(nk):
            sys.exit(f"render-config: not a user nkey: {nk!r}")
        users.append({"nkey": nk})
    if a.api:
        if not NKEY.match(a.api):
            sys.exit(f"render-config: not a user nkey: {a.api!r}")
        users.append(api_user(a.api))
    for spec in a.pop:
        pop, _, nk = spec.partition("=")
        if not POP_ID.match(pop) or not NKEY.match(nk):
            sys.exit(f"render-config: bad --pop {spec!r} (id=UNKEY...)")
        users.append(pop_user(pop, nk))
    for spec in a.worker:
        w, _, nk = spec.partition("=")
        if not POP_ID.match(w) or not NKEY.match(nk):
            sys.exit(f"render-config: bad --worker {spec!r} (id=UNKEY...)")
        users.append(worker_user(w, nk))

    conf = {
        "listen": a.listen,
        "server_name": "sentinel",
        "tls": {"cert_file": a.cert, "key_file": a.key, "timeout": 2},
        "jetstream": {"store_dir": a.store, "max_memory_store": 67108864,
                      "max_file_store": 268435456},
        "authorization": {"users": users},
    }
    json.dump(conf, sys.stdout, indent=2)
    print()


if __name__ == "__main__":
    main()
