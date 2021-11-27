import sys
import os
import shutil
import pycdlib
from gzip import decompress, compress
import tempfile
import subprocess  # nosec: B404
import hashlib
import ipaddress
from colorama.ansi import clear_line

try:
    from cStringIO import StringIO as BytesIO
except ImportError:
    from io import BytesIO
from tools.toolbox.internals import statusprint, yellowprint, abort


def remaster_iso(
    netinst_iso,
    ipaddr,
    netmask,
    gateway,
    hostname,
    root_pwhash,
    domain="example.com",
    ip6addr=None,
    add_packages=None,
):
    try:
        hostip = ipaddress.IPv4Interface("%s/%s" % (ipaddr, netmask))
        gwip = ipaddress.IPv4Interface(gateway)
        if ip6addr:
            ipaddress.IPv6Interface(ip6addr)
    except ipaddress.AddressValueError:
        abort("Invalid IP config given!")
    if not hostip.network.overlaps(gwip.network):
        yellowprint("Gateway outside access subnet?!")
    if not add_packages:
        add_packages = ""
    elif isinstance(add_packages, list):
        add_packages = " ".join(add_packages)
    elif isinstance(add_packages, str):
        pass
    else:
        print("Invalid format for add_packages!")
        sys.exit(1)
    original_cwd = os.getcwd()

    working_directory = tempfile.mkdtemp()

    iso = pycdlib.PyCdlib()
    iso.open(netinst_iso)

    # FIXME: actually perform input validation of IP config
    with open("lib/debian_preseed.cfg", "r") as p:
        preseed = p.read()

    preseed = preseed.format(
        ipaddress=hostip.ip,
        netmask=hostip.netmask,
        gateway=gwip.ip,
        hostname=hostname,
        domain=domain,
        root_pwhash=root_pwhash,
        add_packages=add_packages,
    ).encode()

    print("Switching to temp dir %s" % working_directory, end="")
    os.chdir(working_directory)
    initrd_b = BytesIO()
    iso.get_file_from_iso_fp(initrd_b, joliet_path="/install.amd/initrd.gz")
    initrd = decompress(initrd_b.getvalue())
    initrd_b.close()
    statusprint("Writing old initrd into tmpdir")
    with open("initrd", "wb") as i:
        i.write(initrd)

    statusprint("Adding preseed.cfg to initrd...")
    subprocess.run(  # nosec: B603
        "cpio -H newc -o -A -F initrd".split(), input=preseed, capture_output=True
    ).stdout
    iso.add_fp(
        BytesIO(preseed),
        len(preseed),
        iso_path="/PRESEED.CFG;1",
        joliet_path="/preseed.cfg",
        rr_name="preseed.cfg",
    )

    statusprint("Reading back updated initrd")
    with open("initrd", "rb") as i:
        initrd = i.read()
    statusprint("Compressing initrd")
    initrd_gz = compress(initrd)
    statusprint("Updating initrd in ISO")
    iso.rm_file(
        iso_path="/INSTALL.AMD/INITRD.GZ;1",
        joliet_path="/install.amd/initrd.gz",
        rr_name="initrd.gz",
    )
    iso.add_fp(
        BytesIO(initrd_gz),
        len(initrd_gz),
        iso_path="/INSTALL.AMD/INITRD.GZ;1",
        joliet_path="/install.amd/initrd.gz",
        rr_name="initrd.gz",
    )

    initrd_md5 = hashlib.md5(initrd_gz).hexdigest()  # nosec: B303
    statusprint("New MD5 for initrd.gz is: %s. Updating md5sum.txt" % initrd_md5)

    md5sum_b = BytesIO()
    iso.get_file_from_iso_fp(md5sum_b, joliet_path="/md5sum.txt")
    md5sum = md5sum_b.getvalue().decode()
    md5sum_b.close()

    md5_new = []
    for _m in md5sum.split("\n"):
        try:
            _file = _m.split()[1].strip()
        except IndexError:
            md5_new.append(_m)
        if _file.endswith("/install.amd/initrd.gz"):
            # print('Updating initrd.gz md5sum')
            md5_new.append("{}  {}".format(initrd_md5, _file))
        else:
            md5_new.append(_m)
    statusprint("Updating initrd in ISO")
    iso.rm_file(
        iso_path="/MD5SUM.TXT;1", joliet_path="/md5sum.txt", rr_name="md5sum.txt"
    )
    md5_new = "\n".join(md5_new).encode()
    iso.add_fp(
        BytesIO(md5_new),
        len(md5_new),
        iso_path="/MD5SUM.TXT;1",
        joliet_path="/md5sum.txt",
        rr_name="md5sum.txt",
    )

    statusprint("Updating isolinux")
    # in UEFI:
    # boot/grub/grub.cfg
    # set timeout_style=hidden
    # set timeout=0
    # set default=1

    isolinux_gtk = """
    default auto
    label auto
        menu label ^Automated install
        menu default
        kernel /install.amd/vmlinuz
        append auto=true priority=critical vga=788 initrd=/install.amd/initrd.gz file=/cdrom/preseed.cfg --- quiet

    """
    isolinux_gtk = isolinux_gtk.encode()
    statusprint("Updating isolinux/gtk.cfg in ISO")
    iso.rm_file(
        iso_path="/ISOLINUX/GTK.CFG;1",
        joliet_path="/isolinux/gtk.cfg",
        rr_name="gtk.cfg",
    )
    iso.add_fp(
        BytesIO(isolinux_gtk),
        len(isolinux_gtk),
        iso_path="/ISOLINUX/GTK.CFG;1",
        joliet_path="/isolinux/gtk.cfg",
        rr_name="gtk.cfg",
    )

    isolinux_cfg = """
    # D-I config version 2.0
    # search path for the c32 support libraries (libcom32, libutil etc.)
    path
    include menu.cfg
    default auto
    autoselect auto
    prompt 0
    timeout 4
    """
    isolinux_cfg = isolinux_cfg.encode()
    statusprint("Updating isolinux.cfg in ISO")
    iso.rm_file(
        iso_path="/ISOLINUX/ISOLINUX.CFG;1",
        joliet_path="/isolinux/isolinux.cfg",
        rr_name="isolinux.cfg",
    )
    iso.add_fp(
        BytesIO(isolinux_cfg),
        len(isolinux_cfg),
        iso_path="/ISOLINUX/ISOLINUX.CFG;1",
        joliet_path="/isolinux/isolinux.cfg",
        rr_name="isolinux.cfg",
    )

    pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAInyKl3kQTnv6DfMs8O2LoKF68MMe+GpqNxIaReGxkQ rusty@nkskk-pc"
    _late_commands = [
        "mkdir -p /target/root/.ssh",
        'echo "{}" >> /target/root/.ssh/authorized_keys'.format(pubkey),
        "chmod -R 600 /target/root/.ssh",
    ]
    if ip6addr:
        with open("lib/ipv6_postinst.sh", "r") as i:
            _late_commands.append(i.read().format(ip6addr))
    _lc_b = ("#!/bin/sh -e\n" + "\n".join(_late_commands)).encode()
    iso.add_fp(
        BytesIO(_lc_b),
        len(_lc_b),
        iso_path="/POSTINST.SH;1",
        joliet_path="/postinst.sh",
        rr_name="postinst.sh",
        file_mode=0o0100555,
    )

    fd, filename = tempfile.mkstemp(
        prefix="%s.%s_" % (hostname, domain), suffix="debian_netinst_preseed.iso"
    )
    statusprint("Writing out ISO to disk")
    iso.write(filename)
    iso.close()

    os.chdir(original_cwd)
    shutil.rmtree(working_directory)
    print(clear_line() + "\rCompleted creating preseeded VM ISO")
    return filename
