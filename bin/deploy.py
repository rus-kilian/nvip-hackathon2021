"""
Deploy Bluecat OVA as lab env
"""
import os
import sys
import yaml

from tools.toolbox import (
    extract_updates,
    find_ova,
    VMPreparer,
    centerprint,
    get_backups,
    abort,
    stage,
    substage,
    prompt_action,
    title,
)
from tools.toolbox.internals import greenprint, redprint
from tools.vmware import create_vm_from_iso

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

required_fields = [
    "server",
    "username",
    "password",
    "bam",
    "bdds",
    "root_pw",
    "admin_pw",
    "datacenter",
    "datastore",
    "cluster",
    "folder",
    "network",
    "dvs_network",
]

for _f in required_fields:
    if _f not in config:
        print("%s not found in config!" % _f)
        sys.exit(1)

stage("Checking deployment prerequisites")
substage("OVA files")
bam_ova = find_ova("bam_")
bdds_ova = find_ova("bdds_")
if bam_ova:
    greenprint(bam_ova, prefix="Found BAM OVA: ")
else:
    abort("Missing BAM OVA!")
if bdds_ova:
    greenprint(bam_ova, prefix="Found BDDS OVA: ")
else:
    abort("Missing BDDS OVA!")

substage("Updates")
bdds_updates = extract_updates("bdds_")
bam_updates = extract_updates("bam_")

if bam_updates:
    print("BAM will be updated with:")
    for b in bam_updates:
        greenprint(os.path.basename(b), prefix="- ")
if bdds_updates:
    print("BDDS will be updated with:")
    for b in bdds_updates:
        greenprint(os.path.basename(b), prefix="- ")

substage("Backup(s)")
backups = get_backups()
if backups:
    print("Backups found to consider for restore:")
    for b in backups:
        greenprint(b, prefix="- ")

stage("(Re)deploying VMs")
# deploy all BAM
try:
    # deploy all BDDS
    for _bdds in config["bdds"]:
        substage("Deploying BDDS '%s'" % _bdds["name"])
        with VMPreparer(config) as v:
            v.prepare_vm(_bdds, bdds_ova, bdds_updates)
    # then deploy the BAM
    with VMPreparer(config) as v:
        substage("Deploying BAM '%s'" % config["bam"]["name"])
        v.prepare_vm(config["bam"], bam_ova, bam_updates)

        stage("Updating X.509 for BAM '%s'" % config["bam"]["name"])
        v.deploy_x509(config["bam"])

        if not backups:
            greenprint("Loading BDDSes into BAM")
            # ensure that our "admin" account actually has API permissions
            v.reset_bam_account(config["bam_password"])
            v.update_ipam_config("admin", config["bam_password"])
            v.bootstrap_ipam_config()
        else:
            stage("Backup(s) for BAM '%s'" % config["bam"]["name"])
            _snapshot = v.get_current_snapshot()
            if _snapshot in map((lambda x: os.path.basename(x)), backups):
                backup = _snapshot
            else:
                backup = prompt_action(backups, "backup")
            if not backup:
                v.reset_bam_account(config["bam_password"])
                v.update_ipam_config("admin", config["bam_password"])
                v.bootstrap_ipam_config()
            else:
                v.restore_backup(backup)
                # ensure that our "admin" account actually has API permissions
                v.reset_bam_account(config["bam_password"])
                v.update_ipam_config("admin", config["bam_password"])
                substage("Adjusting Server objects in BAM '%s'" % config["bam"]["name"])
                if "suspend_servers" in config:
                    v.suspend_servers(config["suspend_servers"])
                if "replace_servers" in config:
                    # need to unmanage server first
                    v.suspend_servers(config["replace_servers"])
                    # and then replace
                    v.replace_servers(config["replace_servers"])
                    for key, val in config["replace_servers"].items():
                        if "deploy" in val:
                            _name = val['name'].split(".", 1)
                            create_vm_from_iso(
                                val['name'],
                                _name[1],
                                val["deploy"],
                                v.si,
                                v.dc,
                                v.ds,
                                config["server"],
                                config["folder"],
                                config["network"],
                                val["ipv4"],
                                val["netmask"],
                                val["gateway"],
                                config["root_pw"],
                                dvs_network=config["dvs_network"],
                                add_packages=None,
                            )
                            # FIXME: if we could, we would insert NSD, BIND9 etc. here
                            # and push our zones config
        substage("Adding new Server objects in BAM '%s'" % config["bam"]["name"])
        if "add_servers" in config:
            v.add_servers(config["add_servers"])
            for key, val in config["add_servers"].items():
                if "deploy" in val:
                    _name = key.split(".", 1)
                    create_vm_from_iso(
                        key,
                        _name[1],
                        val["deploy"],
                        v.si,
                        v.dc,
                        v.ds,
                        config["server"],
                        config["folder"],
                        config["network"],
                        val["ipv4"],
                        val["netmask"],
                        val["gateway"],
                        config["root_pw"],
                        dvs_network=config["dvs_network"],
                        add_packages=None,
                    )
                    # FIXME: if we could, we would insert NSD, BIND9 etc. here
                    # and push our zones config

        substage("Ensuring all BDDS are registered as Server objects in BAM")
        _servers = v.get_all_servers()
        payload = {}
        for _bdds in config["bdds"]:
            if _bdds["name"] in _servers.keys():
                # skip existing servers
                continue
            redprint("%s NOT FOUND IN SERVERS!" % _bdds["name"])
            payload[_bdds["name"]] = {
                "ipv4": _bdds["ipaddr"],
                "profile": "ADONIS_XMB3",
            }
            if "ip6addr" in _bdds:
                payload[_bdds["name"]]["ipv6"] = _bdds["ip6addr"]
        if payload:
            v.add_servers(payload)
        stage("Deploying migration XML (if any) to BAM '%s'" % config["bam"]["name"])
        v.migrate_xml("migration")

        # deploy all BDDS
        v.deploy_servers(map((lambda x: x["name"]), config["bdds"]))

        # ask whether any BAM snapshots should be cleaned up (if any)
        stage("Cleaning up snapshots (if desired)")
        v.cleanup_snapshots()
        for _bdds in config["bdds"]:
            # ask whether any BDDS snapshots should be cleaned up (if any)
            v.cleanup_snapshots(v.vms[_bdds["name"]])

    # configure DNS and NTP config on BAM
    # configure mailrelay on BAM
    # configure backup schedule and target on BAM
    # deploy secondary authoritative DNS servers
    # deploy dnsdist/unbound recursor
    # push zones config to secondaries, deploy and verify
    title("Done refreshing Bluecat lab")
    centerprint("[ FINISHED DEPLOYING VMs ]")
except KeyboardInterrupt:
    print("")
    abort("Deployment aborted!")
