"""
Deploy Bluecat OVA as lab env
"""
import os
import sys
import yaml
import dns.zone
import dns.query

from tools.toolbox import (
    find_ova,
    VMPreparer,
    abort,
    stage,
    substage,
    title,
)
from tools.toolbox.internals import redprint, greenprint
from tools.vmware import (
    get_all_vm_snapshots,
    revert_to_snapshot,
)

from tools.toolbox.ipam import network_zone_name, IpamAPIError

debug = False

if debug:
    import logging
    import http.client as http_client

    http_client.HTTPConnection.debuglevel = 1
    # You must initialize logging, otherwise you'll not see debug output.
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True

stage("Reading environment")
if os.path.isfile("/etc/bluecat.yaml"):
    with open("/etc/bluecat.yaml", "r") as stream:
        try:
            config = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)
            sys.exit(1)
elif os.path.isfile(os.environ["HOME"] + "/.bluecat_config.yaml"):
    with open(os.environ["HOME"] + "/.bluecat_config.yaml", "r") as stream:
        try:
            config = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)
            sys.exit(1)
else:
    print("No bluecat_config.yaml")
    sys.exit(1)


servers = None
OPTIONS = [
    "ALLOW_NOTIFY",
    "ALLOW_QUERY",
    "ALLOW_RECURSION",
    "ALLOW_XFER",
    "ALSO_NOTIFY",
    "NOTIFY",
]


def show_delegation(base, target, ns):
    print("Checking for delegation from %s to %s on %s" % (base, target, ns))

    print("Fetching zone %s via AXFR" % base)
    zone_axfr = dns.query.xfr(ns, base)
    z1 = dns.zone.from_xfr(zone_axfr)
    subdomain = target.replace("." + base, "")
    print("Searching for NS to zone %s" % subdomain)
    try:
        delegation = z1.find_rdataset(subdomain, "NS")
        print(delegation)
    except KeyError:
        redprint("No delegation from %s to %s" % (base, target))
        print(z1.to_text())

    z2 = dns.zone.from_xfr(dns.query.xfr(ns, target))
    soa = z2.find_rdataset("@", "SOA")
    print(soa)


def get_children(conn, servers, entityId, type=None):
    # FIXME: this should actually come through a Class servers cache
    # global servers
    result = {}
    for t in servers:
        # init target zones list per server
        result[t] = {}
        # get zone options
        for opt in OPTIONS:
            # next, let's get all the current entity DNS options
            _res = conn.get_dns_option(entityId, opt, servers[t])
            if _res:
                result[t][opt] = _res
                continue
    res = conn.get_entities(entityId, type)
    if not res:
        # overrides = None
        for r in res:
            # filter servernames in getDeploymentRoles (local or inherited)
            # for srv in ... : getDeploymentOptions  (local or inherited)
            # add DNS options
            #
            # add MASTER or HIDDEN_MASTER
            # add master + SLAVE and STEALTH_SLAVE as dns_servers

            if r["type"] == "IP4Block":
                add = get_children(
                    r["id"], type=["IP4Block", "IP4Network", "IP6Block", "IP6Network"]
                )
            elif r["type"] == "IP6Block":
                add = get_children(r["id"], type=["IP6Block", "IP6Network"])
            elif r["type"] == "View" or r["type"] == "Zone":
                add = get_children(r["id"], type="Zone")
            # build zones from CIDR
            if add:
                # FIXME: actually implement
                pass
            # add overrides for dereferenced zones of CIDR
            # append add to r where not overridden
            # add r to children
    return result


bam_ova = find_ova("bam_")
bam_updates = []

if "bdds" not in config:
    abort("No BDDS config!")

dns_hm = config["bdds"][0]["name"]
print("Using BDDS: %s" % dns_hm)

try:
    with VMPreparer(config) as v:
        v.prepare_vm(config["bam"], bam_ova, bam_updates, "unittest")
        snapshots = get_all_vm_snapshots(v.vms[dns_hm])
        if v.snapshot_restored == "unittest":
            revert_to_snapshot(v.si, v.vm, "unittest")
        else:
            v.deploy_x509(config["bam"])
            # FIXME: force revert to empty BAM snapshot - after X.509 update

            v.reset_bam_account(config["bam_password"])
            v.snapshot("unittest", "base config with valid X.509")
        if dns_hm not in v.vms:
            abort("No such VM: %s!" % dns_hm)
        if not v.vms[dns_hm].snapshot:
            abort("VM %s not prepared using snapshots!" % dns_hm)
        snapshots = get_all_vm_snapshots(v.vms[dns_hm])
        if not snapshots:
            abort("VM %s has no snapshots!" % dns_hm)
        revert_to_snapshot(v.si, v.vms[dns_hm], snapshots[0])

        v.update_ipam_config("admin", config["bam_password"])

        # we now have a Configuration and a View
        v.bootstrap_ipam_config()

        print("Fetching servers")
        servers = v.get_all_servers()
        if servers:
            abort("Invalid starting point")

        payload = {"dummy": {"ipv4": "192.0.2.1", "ipv6": "2001:db8::1"}}
        # just add first BDDS from list
        _bdds = config["bdds"][0]
        payload[_bdds["name"]] = {
            "ipv4": _bdds["ipaddr"],
            "profile": "ADONIS_XMB3",
        }
        if "ip6addr" in _bdds:
            payload[_bdds["name"]]["ipv6"] = _bdds["ip6addr"]
        stage("Adding servers")
        v.add_servers(payload)
        v.deploy_servers([dns_hm], True)

        title("Refreshing serverlist")
        servers = v.get_all_servers()
        dns_hm_iface = v.connection.get_server_interface(servers[dns_hm]["id"])
        dummy_iface = v.connection.get_server_interface(servers["dummy"]["id"])

        stage("Adding zones")
        add_options = [v.connection._configuration_id]
        viewid = v.connection.get_extern_view_id()
        v.connection.add_dns_deployment_option(viewid, "allow-xfer", None, "0.0.0.0/0")
        if not viewid:
            print("No VIEW ID!")
            sys.exit(1)
        substage("Adding 'bluecat'")
        _z1 = v.connection.add_zone("bluecat", viewid, False)
        v.connection.add_dns_deployment_role(viewid, dns_hm_iface, "MASTER")
        add_options.append(_z1)
        substage("Adding 'lab.bluecat'")
        _z2 = v.connection.add_zone(
            "lab.bluecat",
            _z1,
        )
        add_options.append(_z2)
        substage("Adding 'dnssec.lab.bluecat'")
        _z3 = v.connection.add_zone(
            "dnssec.lab.bluecat",
            _z2,
        )
        add_options.append(_z3)

        stage("Adding deployment options and comparing results")
        for idx, _v in enumerate(add_options):
            substage("Adding deployment option at %s" % _v)
            v.connection.add_dns_deployment_option(
                _v, "allow-notify", None, "0.0.0.%d/32" % idx
            )
            print(
                "Current DNS options at 'dnssec.lab.bluecat':",
                v.connection.get_dns_option(_z3, "allow-notify", servers[dns_hm]["id"]),
            )

        # FIXME: add DNSSEC config to "lab.bluecat"
        # FIXME: add DNSSEC config to "dnssec.lab.bluecat"
        # FIXME: gracefully remove DNSSEC from "dnssec.lab.bluecat" ?
        # HINT: https://datatracker.ietf.org/doc/html/rfc8901

        substage("Adding 10/8 block")
        _b1 = v.connection.add_block(
            v.connection._configuration_id,
            "10.0.0.0/8",
        )
        add_options = [_b1]
        v.connection.add_dns_deployment_option(_b1, "allow-xfer", None, "0.0.0.0/0")
        substage("Adding DNS MASTER to 10/8 block")
        v.connection.add_dns_deployment_role(
            _b1, dns_hm_iface, "MASTER", {"view": viewid}
        )
        substage("Adding 10.0.0.0/24 network")
        _n1 = v.connection.add_network(_b1, "10.0.0.0/24")
        v.connection.add_dns_deployment_role(
            _n1, dns_hm_iface, "MASTER", {"view": viewid}
        )

        _v6_root = v.connection.find_network("2000::/3")["id"]
        substage("Adding 2001:7c0:2000::/40 block")
        _v6_b1 = v.connection.add_block(
            _v6_root,
            "2001:7c0:2000::/40",
        )
        v.connection.add_dns_deployment_option(_v6_b1, "allow-xfer", None, "0.0.0.0/0")
        substage("Adding DNS MASTER to 2001:7c0:2000::/40 block")
        v.connection.add_dns_deployment_role(
            _v6_b1, dns_hm_iface, "MASTER", {"view": viewid}
        )
        substage("Adding 2001:7c0:2000:1000::/64 network")
        _v6_n1 = v.connection.add_network(
            _v6_b1,
            "2001:7c0:2000:1000::/64",
        )
        v.connection.add_dns_deployment_role(
            _v6_n1, dns_hm_iface, "MASTER", {"view": viewid}
        )
        # FIXME: add DNSSEC config to "10/8"
        # FIXME: add DNSSEC config to "10/24"

        v.deploy_servers([dns_hm], True)

        stage("Checking delegations")
        substage("...from 10/8 to 10/24")
        show_delegation(
            network_zone_name("10.0.0.0/8"),
            network_zone_name("10.0.0.0/24"),
            payload[_bdds["name"]]["ipv4"],
        )
        substage("...from 2001:7c0:2000::/40 to 2001:7c0:2000:1000::/64")
        show_delegation(
            network_zone_name("2001:7c0:2000::/40"),
            network_zone_name("2001:7c0:2000:1000::/64"),
            payload[_bdds["name"]]["ipv4"],
        )
        # FIXME: verify DS delegation to 10/24 on 10/18

        parent = _b1
        nets = {"10.0.0.0/8": _b1}
        for idx, b in enumerate(["10.0.0.0/10", "10.0.0.0/16", "10.0.0.0/17"]):
            substage("Adding %s block" % b)
            parent = v.connection.add_block(parent, b)
            v.connection.add_dns_deployment_option(
                parent, "allow-notify", None, "0.0.0.%d/32" % idx
            )
            print(
                v.connection.get_dns_option(_n1, "allow-notify", servers[dns_hm]["id"])
            )
            nets[b] = parent
            v.deploy_servers([dns_hm], True)
            substage("Checking delegation from 10.0.0.0/8 to 10.0.0.0/24")
            show_delegation(
                network_zone_name("10.0.0.0/8"),
                network_zone_name("10.0.0.0/24"),
                payload[_bdds["name"]]["ipv4"],
            )
        dns_roles = {}
        for b in ["10.0.0.0/10", "10.0.0.0/16", "10.0.0.0/17"]:
            substage("Adding DNS role to %s" % b)
            dns_roles[b] = v.connection.add_dns_deployment_role(
                nets[b], dns_hm_iface, "MASTER", {"view": viewid}
            )
            print("New DNS master role at %s is:" % b, dns_roles[b])
            v.deploy_servers([dns_hm], True)
            substage("Checking delegation from 10.0.0.0/16 to 10.0.0.0/24")
            try:
                show_delegation(
                    network_zone_name("10.0.0.0/16"),
                    network_zone_name("10.0.0.0/24"),
                    payload[_bdds["name"]]["ipv4"],
                )
            except KeyError:
                redprint("FAILED! No valid delegation!")

        stage("Swapping DNS roles at documentation blocks to dummy")
        for b in ["10.0.0.0/10", "10.0.0.0/17"]:
            print("Removing DNS role at %s" % b, dns_roles[b])
            print(v.connection.get_entity_by_id(dns_roles[b]))
            v.connection.delete_dns_deployment_role(nets[b], dns_hm_iface)
            try:
                print(v.connection.get_entity_by_id(dns_roles[b]))
            except IpamAPIError:
                greenprint("No such role")
            print("Adding new DNS role at %s" % b)
            dns_roles[b] = v.connection.add_dns_deployment_role(
                nets[b], dummy_iface, "MASTER", {"view": viewid}
            )
            print("New DNS master role at %s is:" % b, dns_roles[b])

        v.deploy_servers([dns_hm], True)

        stage("Verifying delegations at DNS level")
        for f, to in [("10.0.0.0/8", "10.0.0.0/16"), ("10.0.0.0/16", "10.0.0.0/24")]:
            substage("Checking delegation from %s to %s" % (f, to))
            try:
                show_delegation(
                    network_zone_name(f),
                    network_zone_name(to),
                    payload[_bdds["name"]]["ipv4"],
                )
            except KeyError:
                redprint("FAILED! No valid delegation!")

        # FIXME: add DNSSEC config to "10/10"
        # FIXME: verify DS delegation to 10/24 on 10/8

        # FIXME: add DNSSEC config to "10/16"
        # FIXME: verify DS delegation to 10/24 on 10/16

except KeyboardInterrupt:
    print("")
    abort("Deployment aborted!")
