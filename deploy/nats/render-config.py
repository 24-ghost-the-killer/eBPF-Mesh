#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Render the NATS server configuration (ADR 0014).

One account, one user per component, each identified by an nkey and allowed
to publish/subscribe only to its own subjects:

  admin      everything (operators; the API gets its own user in phase 5)
  pop <id>   publish  telemetry.<id>.>, stats.<id>, health.<id>, config.ack.<id>
             read     the KV buckets tenants, services, rules, platform
             subscribe decision.global
             (writing to KV is NOT allowed)

TLS is mandatory; JetStream stores the KV buckets.

Usage:
  render-config.py --listen 127.0.0.1:4222 --cert server.pem --key server.key \\
      --store /var/lib/nats --admin UADMIN... --pop lab1=UPOP1... [--pop ...]
The output is JSON, which nats-server accepts as configuration.
"""
import argparse
import json
import re
import sys

KV_BUCKETS = ["tenants", "services", "rules", "platform"]
POP_ID = re.compile(r"^[a-z0-9-]{1,32}$")
NKEY = re.compile(r"^U[A-Z2-7]{55}$")


def kv_read_permissions():
    """JetStream API subjects needed to read (get, watch, list) KV buckets."""
    subjects = ["$JS.API.INFO"]
    for b in KV_BUCKETS:
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
            "subscribe": {"allow": ["decision.global", "_INBOX.>"]},
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
    p.add_argument("--pop", action="append", default=[], metavar="ID=NKEY")
    a = p.parse_args()

    users = []
    for nk in [a.admin]:
        if not NKEY.match(nk):
            sys.exit(f"render-config: not a user nkey: {nk!r}")
        users.append({"nkey": nk})
    for spec in a.pop:
        pop, _, nk = spec.partition("=")
        if not POP_ID.match(pop) or not NKEY.match(nk):
            sys.exit(f"render-config: bad --pop {spec!r} (id=UNKEY...)")
        users.append(pop_user(pop, nk))

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
