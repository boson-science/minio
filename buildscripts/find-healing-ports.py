#!/usr/bin/env python3
"""Select a free API and console port range for the healing test cluster."""

import random
import socket
import sys

# Stay below Linux's usual ephemeral range. Check IPv4 and IPv6 wildcard
# bindings together so an existing listener on either family is detected.
for base in random.SystemRandom().sample(range(10000, 29994), 256):
    sockets = []
    try:
        for port in range(base + 1, base + 7):
            for family, address in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
                listener = socket.socket(family, socket.SOCK_STREAM)
                sockets.append(listener)
                if family == socket.AF_INET6:
                    listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                listener.bind((address, port))
        print(base)
        break
    except OSError:
        continue
    finally:
        for listener in sockets:
            listener.close()
else:
    print("Could not find six free healing-test ports", file=sys.stderr)
    sys.exit(1)
