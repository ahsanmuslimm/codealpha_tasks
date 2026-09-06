"""PyNIDS - a self-contained Network Intrusion Detection System.

The package provides:

* ``engine``          - the detection orchestrator (capture -> detect -> respond)
* ``packet_capture``  - live sniffing, pcap reading and paced replay (scapy based)
* ``rule_engine``     - a Suricata/Snort-style signature parser and matcher
* ``detectors``       - stateful behavioural detectors (scan, brute force, DoS,
                        ARP spoofing, DNS tunnelling, web attacks)
* ``response``        - automated incident response (simulate/active blocking,
                        escalation policy, notifications)
* ``alert_store``     - SQLite persistence shared with the web dashboard

The dashboard lives in the sibling ``dashboard`` package and reads the same
SQLite database, so the engine and the web UI can run as separate processes.
"""

from nids.version import __version__, PRODUCT  # noqa: F401

__all__ = ["__version__", "PRODUCT"]
