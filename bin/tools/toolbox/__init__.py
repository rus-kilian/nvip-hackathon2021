import sys
import select
import os
import json
import yaml
import time
import datetime
import threading
import hashlib
from zipfile import ZipFile
from .internals import (
    abort,
    redprint,
    greenprint,
    blueprint,
    yellowprint,
    prompt_action,
    timeout_input,
    statusprint,
)
from tools.vmware import (
    upload_ova,
    upload_file,
    boot_vm,
    reboot_vm,
    wait_for_tasks,
    get_dc,
    get_ds,
    get_vm,
    list_vms,
    update_cloudinit,
    spinner,
    snapshot_vm,
    get_all_vm_snapshots,
    get_snapshots_by_name_recursively,
    revert_to_snapshot,
)
from tools.toolbox.x509 import X509Updater
from tools.toolbox.ipam import IpamConnection, IpamUS, IpamAPIError
from pyVmomi import vim
from pyVim.connect import SmartConnect, Disconnect
from tools.filename import clean_filename
from paramiko import SSHClient, Ed25519Key, RSAKey, Agent, SSHException
from paramiko.client import AutoAddPolicy
from paramiko.ssh_exception import (
    ChannelException,
    NoValidConnectionsError,
    PasswordRequiredException,
)
from scp import SCPClient
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
from requests.exceptions import ConnectionError
import ssl
import socket
from colorama import Fore, Back, Style
from colorama.ansi import set_title, clear_line

_stage = 0
_substage = 0


def stage(text, f="%d", update=True):
    global _stage, _substage
    if update:
        _stage += 1
        _substage = 0
    _t = (f + ": %s") % (_stage, text)
    title(_t)
    centerprint(_t, left="~+", right="+~", highlight=True, background=True)


def substage(text, f="%d.%02d", update=True):
    global _stage, _substage
    if update:
        _substage += 1
    _t = (f + ": %s") % (_stage, _substage, text)
    title(_t)
    centerprint(_t, left="_.", right="._", highlight=True)


def title(text):
    sys.stdout.write(set_title("[%s] %s" % (os.path.basename(sys.argv[0]), text)))


def centerprint(text, width=76, left=">", right="<", highlight=False, background=False):
    textlen = len(text)
    if highlight:
        _text = Fore.WHITE + Style.BRIGHT + text + Style.RESET_ALL
    else:
        _text = text
    if textlen > width - 2:
        print(_text)
        return
    border = int((width - textlen) / 2)
    output = ""
    if background:
        output = Back.BLUE
    output += int(border / len(left)) * left
    if background:
        output += Style.RESET_ALL
    output += " " + _text + " "
    if background:
        output += Back.BLUE
    output += int(border / len(right)) * right
    if background:
        output += Style.RESET_ALL
    print(output)


def extract_updates(prefix, dirs=["updates", "patches"]):
    index = 0
    updates = []
    for _d in dirs:
        if os.path.exists(_d):
            files = sorted(os.scandir(_d), key=lambda d: d.stat().st_mtime)
            if not files:
                continue
            for _file in files:
                f = _file.name
                if f.startswith(prefix):
                    statusprint(
                        "Examining update file %s" % Fore.YELLOW
                        + Style.BRIGHT
                        + f
                        + Style.RESET_ALL
                    )
                    with ZipFile(_d + "/" + f) as _z:
                        result = list(
                            filter(
                                lambda x: (
                                    x.endswith(".run") or x.endswith(".run.zip")
                                ),
                                _z.namelist(),
                            )
                        )
                        if not result:
                            abort("No runnable entries found in ZIP %s" % f)
                        for _f in result:
                            with _z.open(_f) as _update:
                                if _f.endswith(".zip"):
                                    with ZipFile(_update) as _z2:
                                        _res2 = list(
                                            filter(
                                                lambda x: (x.endswith(".run")),
                                                _z2.namelist(),
                                            )
                                        )
                                        if not _res2:
                                            abort(
                                                "No runnable entries found in inner ZIP of %s"
                                                % f
                                            )
                                        for _f2 in _res2:
                                            with _z2.open(_f2) as _update:
                                                # FIXME: we might even want to use a private /tmp/
                                                statusprint(
                                                    "Extracing %s from %s"
                                                    % (
                                                        Fore.GREEN
                                                        + _f2
                                                        + Style.RESET_ALL,
                                                        Fore.GREEN
                                                        + f
                                                        + Style.RESET_ALL,
                                                    )
                                                )
                                                _upd_file = "/tmp/" + clean_filename(
                                                    "%03d_%s" % (index, _f2)
                                                )
                                                with open(_upd_file, "wb") as _out:
                                                    _out.write(_update.read())
                                                    updates.append(_upd_file)
                                                    index += 1
                                                os.chmod(_upd_file, 0o700)
                                else:
                                    yellowprint("Found non-zipped update")
                                    statusprint(
                                        "Extracing %s from %s"
                                        % (
                                            Fore.GREEN + _f + Style.RESET_ALL,
                                            Fore.GREEN + f + Style.RESET_ALL,
                                        )
                                    )
                                    # FIXME: we might even want to use a private /tmp/
                                    _upd_file = "/tmp/" + clean_filename(
                                        "%03d_%s" % (index, _f)
                                    )
                                    with open(_upd_file, "wb") as _out:
                                        _out.write(_update.read())
                                        updates.append(_upd_file)
                                        index += 1
                                    os.chmod(_upd_file, 0o700)
    statusprint("")
    return updates


def find_ova(prefix, ova_dir="ova"):
    if os.path.exists(ova_dir):
        files = os.listdir(ova_dir)
        for f in files:
            if f.startswith(prefix):
                return ova_dir + "/" + f


def get_backups(suffix=".bak", backup_dir="backup"):
    backups = []
    if os.path.exists(backup_dir):
        files = os.listdir(backup_dir)
        for f in files:
            if f.endswith(suffix):
                backups.append(backup_dir + "/" + f)
    return backups


class SSHConnectionClosed(Exception):
    pass


class VMPreparer:
    def __init__(self, config):
        self.config = config
        self._insecure = False
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.sshpubkey = []
        self.si = None
        self.dc = None
        self.ds = None
        self.name = None
        self.vm = None
        self.vms = None
        self.version = None
        self.ipaddr = None
        self.connection = None
        self.ipam_config = None
        self.snapshot_restored = None

    def __enter__(self):
        if self.config.get("ignore_cert_error"):
            # Disable the secure connection warning for demo purpose.
            # This is not recommended in a production environment.
            disable_warnings(InsecureRequestWarning)
            self._insecure = True
        else:
            if "root_ca" not in self.config:
                redprint(
                    "Missing 'root_ca' in config but instructed to verify remote https!"
                )
                sys.exit(1)
            if not os.path.exists(self.config["root_ca"]):
                redprint("No such file: %s" % self.config["root_ca"])
                sys.exit(1)
            # os.environ['REQUESTS_CA_BUNDLE'] = self.config['root_ca']  # Must be an existing file
            self.context.load_verify_locations(self.config["root_ca"])

        for algo in ["ed25519", "rsa"]:
            if os.path.isfile(os.environ["HOME"] + "/.ssh/id_%s.pub" % algo):
                with open(os.environ["HOME"] + "/.ssh/id_%s.pub" % algo, "r") as stream:
                    self.sshpubkey += [stream.read().strip()]
        # print("Loaded SSH pubkey as:")
        # print(self.sshpubkey)

        try:
            self.si = SmartConnect(
                host=self.config["server"],
                user=self.config["username"],
                pwd=self.config["password"],
                port=443,
                sslContext=self.context,
                disableSslCertValidation=self._insecure,
            )
        except IOError as io_error:
            abort(io_error)

        if not self.si:
            abort("Unable to connect to host with supplied credentials.")

        self.dc = get_dc(self.si, self.config["datacenter"])
        if not self.dc:
            abort("Unable to find datacenter %s" % self.config["datacenter"])

        self.ds = get_ds(self.dc, self.config["datastore"])
        if not self.ds:
            abort("Unable to find datastore %s" % self.config["datastore"])
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.si:
            Disconnect(self.si)

    def get_current_snapshot(self):
        return self.snapshot_restored

    def get_log_requests(self):
        if not self.connection:
            return
        return self.connection.logging_enabled()

    def set_log_requests(self, log_requests=False):
        if not self.ipam_config:
            return self.update_ipam_config(log_requests=log_requests)
        self.ipam_config["log_requests"] = log_requests
        if log_requests is True:
            self.connection._conn.enable_logging()
        else:
            self.connection._conn.disable_logging()

    def update_ipam_config(
        self, username=None, password=None, log_requests=False
    ):  # nosec: B107
        print(
            clear_line() + "\rRefreshing connection credentials to %s" % self.name,
            end="",
        )
        if not username:
            if "username" not in self.ipam_config:
                username = "admin"
            else:
                username = self.ipam_config["username"]
        if not password:
            if "password" not in self.ipam_config:
                password = "admin"
            else:
                password = self.ipam_config["password"]
        self.ipam_config["username"] = username
        self.ipam_config["password"] = password
        self.ipam_config["log_requests"] = log_requests
        if self.connection:
            if log_requests is True:
                self.connection._conn.enable_logging()
            else:
                self.connection._conn.disable_logging()
        print(clear_line() + "\r", end="")

    def tailf(self, vmu, running):
        while running.is_set():
            if not vmu.transport.is_active():
                raise SSHConnectionClosed("No transport")
            channel = vmu.transport.open_session()
            channel.exec_command("tail -F /var/log/update_installer.log")  # nosec: B601
            while True:
                if not running.is_set():
                    return
                rl, wl, xl = select.select([channel], [], [], 0.0)
                if len(rl) > 0:
                    # Must be stdout
                    print(channel.recv(1024).decode("utf-8"), end="")
            # FIXME: need to catch ssh connection closed still
            timeout_input("Reconnecting to server to resume tailing log")

    def prepare_vm(self, vmconfig, ova, updates, snapshot=None):
        vm = None
        self.vms = list_vms(self.si, self.dc)
        self.name = vmconfig["name"]
        self.ipaddr = vmconfig["ipaddr"]
        self.ipam_config = {
            "endpoint": "https://" + self.name,
            "parallel_requests": 2,
        }
        if self.name in self.vms:
            self.vm = self.vms[self.name]
            snapshots = get_all_vm_snapshots(self.vm)
            if snapshots:
                greenprint("Found existing VM with snapshots!")
                if snapshot not in snapshots:
                    print("No such snapshot '%s'" % snapshot)
                    snapshot = None
                if not snapshot:
                    snapshot = prompt_action(snapshots, "snapshot")
                if snapshot:
                    revert_to_snapshot(self.si, self.vm, snapshot)
                    self.snapshot_restored = snapshot
                    return
        _sshpubkey = self.sshpubkey
        if "ssh_root_pubkey" in self.config:
            _sshpubkey += self.config["ssh_root_pubkey"]
        vm = deploy_vm(
            si=self.si,
            dc=self.dc,
            ds=self.ds,
            name=vmconfig["name"],
            ova=ova,
            server=self.config["server"],
            folder=self.config["folder"],
            network=self.config["network"],
            dvs_network=self.config["dvs_network"],
            ipaddr=vmconfig["ipaddr"],
            netmask=vmconfig["netmask"],
            gateway=vmconfig["gateway"],
            ip6addr=vmconfig["ip6addr"],
            gateway6=vmconfig["gateway6"],
            root_pw=self.config["root_pw"],
            admin_pw=self.config["admin_pw"],
            sshpubkey=_sshpubkey,
            clientid=vmconfig["clientid"],
            activationid=vmconfig["activation_id"],
            ntp_servers=self.config.get("ntp_servers"),
            dns_resolvers=self.config.get("dns_resolvers"),
            mailrelay=self.config.get("mailrelay"),
            hostmaster=self.config.get("hostmaster"),
            backup=self.config.get("backup"),
        )
        if vm.guest.toolsRunningStatus == "guestToolsRunning":
            if vm.guest.ipAddress is not None:
                if (
                    vm.guest.ipAddress == "192.168.1.1"
                    or vm.guest.ipAddress == "192.168.1.2"
                ):
                    abort("cloud-init update did not complete!", 2)

        self.vm = vm
        with VMUpdater(self.ipaddr) as vmu:
            vmu.reconnect_if_needed()
            if self.config.get("ntp_servers"):
                # FIXME: until BAM learns to use cloud-init for this, let's just force the NTP config via PsmClient
                substage("Ensuring NTP sync on %s (%s)" % (self.name, self.ipaddr))
                # FIXME: we should also add the BAM as NTP server on BDDS here
                stdin, stdout, stderr = vmu.ssh.exec_command(  # nosec: B601
                    "ntpdate -u -b %s;PsmClient ntp set servers='%s,127.127.1.0';PsmClient ntp set 'server=127.127.1.0 stratum=12'"
                    % (
                        self.config["ntp_servers"][0],
                        ",".join(self.config["ntp_servers"]),
                    )
                )
                if stdout:
                    # just make sure to complete the command
                    stdout.readlines()
                greenprint("NTP updated!")
            self.version = vmu.get_version()
            greenprint(self.version, prefix="Current version: ")
            if updates:
                substage("Uploading updates to %s (%s)" % (self.name, self.ipaddr))
                vmu.upload_files(updates)
                while True:
                    vmu.retries = 10
                    vmu.reconnect_delay = 15
                    vmu.reconnect_if_needed(900)
                    stdin, stdout, stderr = vmu.ssh.exec_command(  # nosec: B601
                        "ls -1 /var/lib/bcn_updates/"
                    )
                    if not stdin:
                        greenprint("No more updates left to install")
                        self.version = vmu.get_version()
                        break
                    else:
                        pending = []
                        for line in stdout.readlines():
                            _l = line.strip()
                            if _l:
                                pending += [_l]
                        if not pending:
                            greenprint("No more updates left to install")
                            break
                        print("Will update using:")
                        print("\n".join(pending))
                    running = threading.Event()
                    running.set()
                    logthread = threading.Thread(target=self.tailf, args=(vmu, running))
                    logthread.start()
                    substage(
                        "%d updates pending - installing on %s"
                        % (len(pending), self.name)
                    )
                    try:
                        stdin, stdout, stderr = vmu.ssh.exec_command(  # nosec: B601
                            # XXX: we want to control the run of the update installer from here
                            # "systemctl start update_installer.service"
                            "/root/bin/update_installer.sh"
                        )
                        stdin.close()
                        for line in iter(stdout.readline, ""):
                            blueprint(line, end="")
                        greenprint("Finished update run")
                    except KeyboardInterrupt:
                        print("")
                        abort("Execution aborted")
                    except ChannelException:
                        yellowprint("Connection lost.")
                    # signal tailf thread to terminate
                    running.clear()
                    # waiting for tailf thread to terminate
                    logthread.join()
                    self.version = vmu.get_version()
                    blueprint(self.version, prefix="Current version: ")

            if self.config.get("backup"):
                substage("Enabling backup cronjob on %s" % self.name)
                try:
                    stdin, stdout, stderr = vmu.ssh.exec_command(  # nosec: B601
                        "/usr/local/bcn/backup.pl -c"
                    )
                    stdin.close()
                    for line in iter(stdout.readline, ""):
                        blueprint(line, end="")
                    greenprint("Cronjob added")
                except KeyboardInterrupt:
                    print("")
                    abort("Execution aborted")
        substage(
            "Done preparing VM '%s' (version: %s)" % (self.name, self.version),
            update=False,
        )
        greenprint("Done preparing VM '%s' (version: %s)" % (self.name, self.version))
        res = timeout_input("Snapshot VM before proceeding?", hint="(Y/n)")
        if res != "n":
            snapshot_vm(
                self.si,
                self.vm,
                self.version,
                "OVA: %s\n+ updates:\n%s\n deployed by %s at %s"
                % (
                    ova,
                    "\n".join(map((lambda x: os.path.basename(x)), updates)),
                    os.path.basename(sys.argv[0]),
                    datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                ),
            )

    def snapshot(
        self, name=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), description=""
    ):
        snapshot_vm(self.si, self.vm, name, description)

    def cleanup_snapshots(self, vm=None):
        if not vm:
            vm = self.vm
        snapshots = get_all_vm_snapshots(vm)
        if snapshots:
            if len(snapshots) == 1:
                blueprint("Found snapshot on %s" % vm.name)
            else:
                blueprint("Found %d snapshots on %s" % (len(snapshots), vm.name))
                res = timeout_input(
                    "Remove ALL snapshots from %s?" % vm.name, hint="(y/N)"
                )
                if res == "y":
                    wait_for_tasks(self.si, [vm.RemoveAllSnapshots()])
                    greenprint("Done removing ALL snapshots from %s" % self.name)
                    return
            for snapshot in snapshots:
                res = timeout_input(
                    "Remove snapshot %s from %s?" % (snapshot, vm.name), hint="(y/N)"
                )
                if res == "y":
                    blueprint("Removing VM snapshot %s on %s" % (snapshot, vm.name))
                    snap_obj = get_snapshots_by_name_recursively(
                        self.vm.snapshot.rootSnapshotList, snapshot
                    )
                    if len(snap_obj) != 1:
                        abort("Failed to access snapshot")
                    snap_obj = snap_obj[0].snapshot
                    wait_for_tasks(self.si, [snap_obj.RemoveSnapshot_Task(True)])
                    greenprint(
                        "Done removing snapshot %s on %s" % (snapshot, self.name)
                    )

    def upload_file_to_datastore(self, filename):
        dspath = self.vm.summary.config.vmPathName
        _vmx = os.path.basename(dspath)
        # let's just unconditionally believe that the VM definition always lives on the first datatore
        _ds_name = self.vm.datastore[0].info.name
        _ds_offset = "[%s] " % _ds_name
        if not dspath.startswith(_ds_offset):
            abort("Unknown datastore path: %s" % dspath)
        _vmpath = dspath[len(_ds_offset) : -(len(_vmx) + 1)]  # noqa: E203

        upload_file(
            self.si,
            self.dc,
            self.ds,
            self.config["server"],
            filename,
            "/" + _vmpath + "/" + os.path.basename(filename),
        )
        greenprint("Uploaded %s to [%s] %s" % (filename, _ds_name, _vmpath))

    def restore_backup(self, backup=None):
        if not backup:
            abort("No backup given!")
        _backup = os.path.basename(backup)
        if self.snapshot_restored:
            if self.snapshot_restored == _backup:
                blueprint("Backup %s already restored via snapshot" % _backup)
                return
        snapshots = get_all_vm_snapshots(self.vm)
        for _s in snapshots:
            if _backup in _s:
                res = timeout_input(
                    "Restore backup '%s' from snapshot?" % _backup, hint="(Y/n)"
                )
                if res != "n":
                    revert_to_snapshot(self.si, self.vm, _backup)
                    self.snapshot_restored = _backup
                    return
        if not os.path.exists(backup):
            abort("No such file '%s'" % backup)
        substage("Restoring backup %s to %s" % (backup, self.name), update=False)
        with VMUpdater(self.ipaddr) as vmu:
            vmu.reconnect_if_needed()
            vmu.upload_files(backup, target_dir="/data/backup/")
            stdin, stdout, stderr = vmu.ssh.exec_command(  # nosec: B601
                # XXX: redirecting stderr here to catch all output in stdout
                "/usr/local/bluecat/restoreDB.sh /data/backup/%s 2>&1"
                % _backup
            )
            stdin.close()
            for line in iter(stdout.readline, ""):
                print(line, end="")
            greenprint("Finished restoring backup")
        print("Waiting for jetty to restart...", end="")
        retries = 10
        delay = 15
        for retry in range(1, retries):
            try:
                ssl.get_server_certificate((self.name, 443))
                print(
                    clear_line()
                    + "\rhttps connection available on %s aain." % self.name
                )
                break
            except ConnectionRefusedError:
                for _d in range(delay, 0, -1):
                    print(
                        clear_line()
                        + "\rConnection refused while connecting to https://%s/. Waiting %ds. [attempt %d/%d]"
                        % (self.name, _d, retry, retries),
                        end="",
                    )
                    time.sleep(1)
        res = timeout_input("Snapshot VM before proceeding?", hint="(Y/n)")
        if res != "n":
            snapshot_vm(
                self.si,
                self.vm,
                _backup,
            )

    def deploy_x509(self, config):
        upload = None
        with X509Updater(config) as x:
            if not x.needs_update():
                greenprint(
                    "Cert for %s already matches. Don't need update." % self.name
                )
                return
            p12 = "certs/%s.p12" % self.name
            with open(p12, "wb") as _p12:
                _p12.write(x.gen_pkcs12())
            upload = [p12]
        print("Deploying X.509 config for: ", end="")
        greenprint(self.name)
        with VMUpdater(self.ipaddr) as vmu:
            vmu.upload_files(upload)
            vmu.upload_files(["lib/x509_update.sh"], "/root/bin/")
            stdin, stdout, stderr = vmu.ssh.exec_command(  # nosec: B601
                # XXX: redirecting stderr here to catch all output in stdout
                "/root/bin/x509_update.sh /var/lib/bcn_updates/%s.p12 2>&1"
                % self.name,
            )
            stdin.close()
            for line in iter(stdout.readline, ""):
                print(line, end="")
        with X509Updater(config) as x:
            if x.needs_update():
                abort("Cert for %s still mismatching. WTF?!")
            greenprint("Finished updating X.509 cert")

    def ensure_connection(self, retries=10):
        if self.connection:
            # greenprint("Connection to %s established" % self.name)
            return
        if not self.ipam_config:
            self.update_ipam_config()
        print("Ensuring connection to https://%s/" % self.name, end="")
        _try = 1
        while _try < retries:
            print(
                clear_line()
                + "\rEstablishing connection to https://%s/ ..." % self.name,
                end="",
            )
            try:
                self.connection = IpamUS(IpamConnection(self.ipam_config))
                greenprint(
                    clear_line() + "\rConnection to https://%s/ established" % self.name
                )
                return
            except ConnectionError:
                print(clear_line() + "\r", end="")
                timeout_input(
                    "Connection to https://%s/ failed. Waiting until retrying (%d/%d)"
                    % (self.name, _try, retries)
                )
            _try += 1

    def bootstrap_ipam_config(self):
        self.ensure_connection()
        if not self.connection:
            abort("No connection to https://%s/ could be established" % self.name)
        if not self.connection._configuration_id:
            print("Bootstrapping Configuration")
            self.connection.bootstrap()
        else:
            print("Using Configuration ID: %s" % self.connection._configuration_id)

    def migrate_xml(self, migration_dir):
        if not os.path.exists(migration_dir):
            return
        mxml = os.listdir(migration_dir)
        if not mxml:
            return
        migrate = []
        for _m in mxml:
            if _m.endswith(".xml"):
                res = timeout_input("Restore migration XML '%s'?" % _m, hint="(Y/n)")
                if res == "n":
                    return
                migrate.append(migration_dir + "/" + _m)
        if not migrate:
            return
        print("Will migrate %d XML files into BAM %s" % (len(migrate), self.name))
        self.ensure_connection()
        with VMUpdater(self.ipaddr) as vmu:
            vmu.upload_files(migrate, "/data/migration/incoming")
            for _m in migrate:
                __m = os.path.basename(_m)
                print("Migrating %s: " % __m, end="")
                self.connection.migrate_xml(__m)
                greenprint("OK")
        greenprint("All migration XML uploaded and imported")

    def reset_bam_account(self, password=None):
        # Resetting passwords for other users than 'admin' do not seem to work
        username = "admin"
        # only ensure API-bit is "enabled" (bit 0 in long1)
        with VMUpdater(self.ipaddr) as vmu:
            cmd = [
                "select nextval('history_id_seq')",
                "update entity_trunk set long1 = 17 where discriminator = 'NUSR' and name = '%s' and long1 = 16"
                % username,
            ]
            cmd = ";".join(cmd)
            stdin, stdout, stderr = vmu.ssh.exec_command(  # nosec: B601
                'psql -U postgres -d proteusdb -c "%s;"' % cmd,
            )
            stdin.close()
            res = stdout.read(2048).decode().strip()
            if res == "UPDATE 1":
                greenprint("Account '%s' is now API-enabled" % username)
            else:
                blueprint("Account '%s' already API-enabled" % username)
            if password:
                # https://care.bluecatnetworks.com/s/question/0D54000003xsus6CAA/how-do-i-change-the-admin-password-for-bam-web-interface
                password_hash = hashlib.sha512(password.encode()).hexdigest()
                cmd = [
                    "select nextval('history_id_seq')",
                    "update metadata_value set text = UPPER('"
                    + password_hash
                    + "') where owner_id = (select id from entity_trunk where discriminator = 'NUSR' and name = '"
                    + username
                    + "') and field_id = (select id from metadata_field where name='password' and entity_info_id = (select id from entity_info where entity_discriminator = 'NUSR'))",
                ]
                cmd = ";".join(cmd)
                stdin, stdout, stderr = vmu.ssh.exec_command(  # nosec: B601
                    'psql -U postgres -d proteusdb -c "%s;"' % cmd,
                )
                stdin.close()
                res = stdout.read(2048).decode().strip()
                if res == "UPDATE 1":
                    greenprint("Password reset for account '%s'" % username)
                else:
                    print(res)
                    redprint("Password reset for account '%s' FAILED!" % username)

    def get_all_servers(self):
        self.ensure_connection()
        _servers = {}
        print("Refreshing servers list...", end="")
        try:
            res = self.connection._conn.get_entities(
                self.connection._configuration_id, "Server"
            )
        except IpamAPIError as e:
            redprint("No servers present.")
            print(e)
            return
        if not res:
            return
        for _s in res:
            _servers[_s["name"]] = {
                "id": _s["id"],
                "profile": _s["properties"]["profile"],
                "ipv4": _s["properties"]["defaultInterfaceAddress"],
                "entity": _s,
            }
            if "servicesIPv6Address" in _s["properties"]:
                _servers[_s["name"]]["ipv6"] = _s["properties"][
                    "servicesIPv6Address"
                ].lower()
        greenprint(clear_line() + "\r", end="")
        return _servers

    def suspend_servers(self, servers):
        self.ensure_connection()
        # print("Suspending %d server(s) in %s" % (len(servers), self.name))
        _servers = self.get_all_servers()
        for _s in servers:
            print("Checking for %s..." % _s, end="")
            if _s in _servers:
                if _servers[_s]["profile"] == "OTHER_DNS_SERVER":
                    continue
                yellowprint(
                    clear_line() + "\rDisabling server %s: " % _s,
                    end="",
                )
                if self.connection.disable_server(_servers[_s]["id"]):
                    greenprint("OK")
                else:
                    redprint("FAILED")
            else:
                redprint(
                    clear_line() + "\rNo such server %s to disable! Skipping!" % _s
                )

    def enable_servers(self, servers):
        self.ensure_connection()
        # print("Enabling %d server(s) in %s" % (len(servers), self.name))
        _servers = self.get_all_servers()
        for _s in servers:
            print("Checking for %s..." % _s, end="")
            if _s in _servers:
                blueprint(
                    clear_line() + "\rEnabling server %s: " % _s,
                    end="",
                )
                if self.connection.enable_server(_servers[_s]["id"]):
                    greenprint("OK")
                else:
                    redprint("FAILED")
            else:
                redprint(clear_line() + "\rNo such server %s to enable! Skipping!" % _s)

    def replace_servers(self, rename_srv):
        self.ensure_connection()
        servers = self.get_all_servers()
        # print("Replacing %d servers in %s" % (len(rename_srv), self.name))
        for srv in rename_srv:
            v = rename_srv[srv]
            print("Checking for %s..." % srv, end="")
            if srv not in servers:
                abort("Server %s not found in servers" % srv)
            if (
                srv == v["name"]
                and servers[srv]["ipv4"] == v["ipv4"]
                and servers[srv]["ipv6"] == v["ipv6"].lower()
            ):
                blueprint("Skipping correct existing %s" % srv)
                continue
            print(clear_line() + "\rServer %s needs update..." % srv, end="")
            _entity = servers[srv]["entity"]
            if _entity["properties"]["profile"] == "OTHER_DNS_SERVER":
                print("Updating server %s" % srv, end="")
                # print(_entity)
                _entity["name"] = v["name"]
                _entity["properties"]["fullHostName"] = v["name"]
                _entity["properties"]["defaultInterfaceAddress"] = v["ipv4"]
                self.connection.update_entity(_entity)
                print(
                    clear_line()
                    + "\rFetching interface for %s to update" % servers[srv]["id"],
                    end="",
                )
                for _i in self.connection._conn.get_entities(
                    servers[srv]["id"], "NetworkServerInterface"
                ):
                    _entity = _i
                    # print('Got NetworkServerInterface of new server as %s' % _i['id'])
                    break
                # print(_entity)
                if "properties" not in _entity:
                    _entity["properties"] = {}
                _entity["properties"]["servicesIPv6Address"] = v["ipv6"].lower()
                _entity["properties"]["servicesIPv4Address"] = v["ipv4"]
                # FIXME: work around stupid warning
                _entity["properties"].pop("defaultInterfaceAddress", None)
                self.connection.update_entity(_entity)
            else:
                greenprint(
                    v["name"],
                    prefix=(
                        clear_line() + "\rReplacing BDDS %s with new reference " % srv
                    ),
                    end="",
                )
                try:
                    self.connection.replace_server(
                        srv, servers[srv]["id"], v["name"], v["ipv4"]
                    )
                except Exception as e:
                    print(e)
            greenprint(clear_line() + "\rUpdated server %s to %s" % (srv, v["name"]))

    def add_servers(self, add_srv):
        self.ensure_connection()
        servers = self.get_all_servers()
        for srv in add_srv:
            if srv in servers:
                abort("Server %s is already defined - cannot add!" % srv)
            v = add_srv[srv]
            print("Adding server %s ..." % srv, end="")
            _v4 = None
            _v6 = None
            _profile = "OTHER_DNS_SERVER"
            servers[srv] = {}
            if "ipv4" in v:
                _v4 = v["ipv4"]
                servers[srv]["ipv4"] = _v4
            if "ipv6" in v:
                _v6 = v["ipv6"].lower()
                servers[srv]["ipv6"] = _v6
            if "profile" in v:
                _profile = v["profile"]
            _newsrv = self.connection.add_server(srv, _v4, _v6, _profile)
            if not _newsrv:
                abort("Failed to create server %s" % srv)
            greenprint("Done. New server ID is %d." % _newsrv)
            if _v6:
                print("Fetching interfaces...", end="")
                _iface = None
                _iface_entity = None
                for _i in self.connection._conn.get_entities(
                    _newsrv, "NetworkServerInterface"
                ):
                    # print(_i)
                    _iface = _i["id"]
                    _iface_entity = _i
                    break
                print(
                    clear_line()
                    + "\rGot NetworkServerInterface of new server as %s" % _iface,
                    end="",
                )
                _iface_entity["properties"]["servicesIPv6Address"] = v["ipv6"].lower()
                if _v4:
                    _iface_entity["properties"]["servicesIPv4Address"] = _v4
                # FIXME: work around stupid bug
                _iface_entity["properties"].pop("defaultInterfaceAddress", None)
                # print(_iface_entity)
                self.connection.update_entity(_iface_entity)
                greenprint(clear_line() + "\rIPv6 added.")
            if "copy" in v:
                if v["copy"] not in servers:
                    yellowprint(
                        "No such server to copy DeploymentRoles from: %s. Skipping."
                        % v["copy"]
                    )
                    continue
                print("Fetching server roles from %s" % v["copy"], end="")
                _roles = self.connection.get_server_roles(servers[v["copy"]]["id"])
                # filter to only DNS roles
                _roles = list(
                    filter(
                        lambda x: (x["service"] == "DNS"),
                        _roles,
                    )
                )
                _len = len(_roles)
                for _ctr, r in enumerate(_roles):
                    if r["service"] != "DNS":
                        blueprint("Ignoring role type %s" % r["type"])
                        continue
                    print(
                        clear_line()
                        + "\r[%03d/%03d] Adding DNS role to %s"  # noqa: F507
                        % (_ctr, _len, srv),
                        end="",
                    )
                    _properties = {}
                    if "view" in r["properties"]:
                        _properties["view"] = r["properties"]["view"]
                    self.connection.add_dns_deployment_role(
                        r["entityId"], _properties, _iface, r["type"]
                    )
                greenprint(
                    clear_line()
                    + "\rServer roles successfully copied from %s to %s"
                    % (v["copy"], srv)
                )

    def deploy_servers(self, servers, wait=False):
        self.ensure_connection()
        _all_servers = self.get_all_servers()
        for srv in servers:
            if srv not in _all_servers:
                abort("Server %s is NOT defined - cannot deploy!" % srv)
                continue
            print("Deploying server %s " % srv, end="")
            self.connection.deploy_server(_all_servers[srv]["id"])
            if not wait:
                status = None
            else:
                status = "QUEUED"
                while status not in [
                    "CANCELLED",
                    "FAILED",
                    "NOT_DEPLOYED",
                    "WARNING",
                    "INVALID",
                    "DONE",
                ]:
                    status = self.connection.get_server_deployment_status(
                        _all_servers[srv]["id"]
                    )
                    spinner(
                        clear_line()
                        + "\rDeploying server %s: %s"
                        % (srv, Fore.YELLOW + Style.BRIGHT + status + Style.RESET_ALL)
                    )
                    time.sleep(1)
                print(clear_line() + "\rDeployed server %s " % srv, end="")
            greenprint("OK")
            return status


def deploy_vm(
    si,
    dc,
    ds,
    name,
    ova,
    server,
    folder,
    network,
    dvs_network,
    ipaddr,
    netmask,
    gateway,
    root_pw,
    admin_pw,
    ip6addr=None,
    gateway6=None,
    sshpubkey=[],
    ova_net="NAT",
    rp=None,
    clientid=None,
    activationid=None,
    ntp_servers=["0.pool.ntp.uni-stuttgart.de"],
    dns_resolvers=["129.69.252.252", "129.69.252.202"],
    mailrelay="smtp.example.com",
    hostmaster="admin",
    backup=None,
):
    vm = None
    vms = list_vms(si, dc)
    if name in vms:
        yellowprint("Found existing VM!")
        # print(self.vms[name].summary)
        _ans = timeout_input("Delete and redeploy?", hint="(Y/n)")
        if not _ans or _ans.lower() != "n":
            yellowprint("Shutting down and removing to restart deployment")
            vms[name].PowerOff()
            vms[name].Destroy()
            timeout_input("Cleanup pending - waiting 10s for storage to sync", 10)
        else:
            vm = vms[name]

    if not vm:
        upload_ova(
            si=si,
            name=name,
            ova_path=ova,
            host=server,
            dc=dc,
            rp=rp,
            ds=ds,
            folder=folder,
            ova_net=ova_net,
            network=network,
            dvs_network=dvs_network,
        )
        vm = get_vm(si, dc, name)
        # print(vm.summary)
    _metadata = {"dsmode": "local"}
    _domain = name.split(".", 1)[1]
    _resolv_conf = "domain " + _domain
    for _n in dns_resolvers:
        _resolv_conf += "\nnameserver " + _n
    _resolv_conf += "\n"
    _ntp_servers = []
    for _n in ntp_servers:
        _ntp_servers += ({"address": _n, "stratum": "default"},)
    if "@" not in hostmaster:
        hostmaster += "@" + _domain
    _mail_service_conf = (
        "\n".join(
            [
                "export PROTEUS_MAIL_SMTP_HOST=" + mailrelay,
                "export PROTEUS_MAIL_FROM=" + hostmaster,
            ]
        )
        + "\n"
    )
    _userdata = {
        # FIXME: no IPv6 config here
        "bluecat_netconf": {
            "ipaddr": str(ipaddr),
            "cidr": str(netmask),
            "gateway": str(gateway),
            "hostname": name.split(".")[0],
        },
        "timezone": "Europe/Berlin",
        "users": [
            {
                "name": "root",
                "passwd": root_pw,
                "lock_passwd": False,
                "ssh_authorized_keys": list(sshpubkey),
            },
            {
                "name": "admin",
                "passwd": admin_pw,
                "lock_passwd": False,
                "ssh_authorized_keys": list(sshpubkey),
            },
        ],
        "bluecat_service_config": {
            "payload": "@@@@_BLUECAT__@@@@__SERVICE__@@@@__CONFIG_@@@@"
        },
        "runcmd": [
            "mkdir -p /var/lib/bcn_updates",
            # XXX: we will run the update_installer.sh ourselves
            # "systemctl daemon-reload",
            # "systemctl enable update_installer.service",
            # "systemctl start --no-block update_installer.service",
        ],
        "write_files": [
            {
                "path": "/root/bin/update_installer.sh",
                "content": open("lib/update_installer.sh", "r").read(),
                "permissions": "0500",
            },
            {
                "path": "/root/bin/x509_update.sh",
                "content": open("lib/x509_update.sh", "r").read(),
                "permissions": "0500",
            },
            {
                "path": "/etc/resolv.conf",
                "content": _resolv_conf,
                "permissions": "0644",
            },
            {
                "path": "/opt/server/proteus/etc/mail-service.cfg",
                "content": _mail_service_conf,
                "permissions": "0644",
            },
            # {
            #    "path": "/etc/systemd/system/update_installer.service",
            #    "content": open("lib/update_installer.service","r").read(),
            #    "permissions": "0444",
            # },
        ],
    }
    if backup:
        backuptime = backup.get("time", "0300")
        backupretain = backup.get("retain", 15)
        backupprefix = backup.get("prefix", "bcn")
        backupsavelocal = str(backup.get("savelocal", "true")).lower()
        backupdir = backup.get("dir", ".")
        backuphost = backup["host"]
        backupuser = backup["user"]
        backuppassword = backup["password"]
        backupproto = backup["proto"]
        _backup_conf = (open("lib/backup.conf", "r").read(),)
        _userdata["write_files"] += [
            {
                "path": "/etc/bcn/backup.conf",
                "content": _backup_conf.format(
                    backuptime=backuptime,
                    backupretain=backupretain,
                    backupprefix=backupprefix,
                    backupsavelocal=backupsavelocal,
                    backuphost=backuphost,
                    backupdir=backupdir,
                    backupuser=backupuser,
                    backuppassword=backuppassword,
                    backupproto=backupproto,
                ),
                "permissions": "0644",
            },
        ]

    bcn_payload = {
        "version": "1.0.0",
        "services": {
            "firewall": {
                "configurations": [
                    {
                        "firewallConfiguration": {
                            "enable": True,
                            "allowPing": True,
                        }
                    }
                ]
            },
            "ssh": {
                "configurations": [
                    {"sshConfiguration": {"enable": True, "tacacs": {"enable": False}}}
                ]
            },
            "ntp": {
                "configurations": [
                    {
                        "ntpConfiguration": {
                            "enable": True,
                            "servers": _ntp_servers
                            + [
                                {"address": "127.127.0.10", "stratum": "1"},
                            ],
                        }
                    }
                ]
            },
            "dnsResolver": {
                "configurations": [
                    {
                        "dnsResolverConfiguration": {
                            "servers": dns_resolvers,
                        }
                    }
                ]
            },
            "snmp": {
                "configurations": [
                    {
                        "snmpConfiguration": {
                            "enable": True,
                            "agentService": {
                                "loglevel": "info",
                                "pollingPeriod": 156,
                                "system": {
                                    "contact": "test@bluecatnetworks.com",
                                    "description": "Lab Deployment",
                                    "location": "BCN Lab",
                                    "name": "Lab server",
                                },
                                "v2c": {"enable": True, "community": "public"},
                            },
                        }
                    }
                ]
            },
            "interfaces": {
                "configurations": [
                    {
                        "interfacesConfiguration": {
                            "dedicatedManagement": False,
                            "networkInterfaces": [
                                {
                                    "eth0": {
                                        "physical": {
                                            "active": True,
                                            "description": "eth0",
                                            "v4addresses": [
                                                {"ip4": ipaddr, "cidr": netmask}
                                            ],
                                            "v6addresses": [
                                                {"ip6": ip6addr, "cidr": 64}
                                            ],
                                        },
                                    },
                                },
                            ],
                            "routes": [
                                {"network": "default", "gateway": gateway, "cidr": 0},
                                {"network": "default", "gateway": gateway6, "cidr": 0},
                            ],
                        },
                    },
                ],
            },
        },
    }
    if clientid and activationid:
        # also support 9.3.0 style
        _userdata["bluecat_license"] = {}
        _userdata["bluecat_license"]["id"] = clientid
        _userdata["bluecat_license"]["key"] = activationid

        bcn_payload["services"]["license"] = {
            "configurations": [
                {
                    "licenseConfiguration": {
                        "clientID": clientid,
                        "key": activationid,
                    }
                }
            ]
        }

    _userdata = yaml.dump(_userdata)
    _userdata = _userdata.replace(
        "'@@@@_BLUECAT__@@@@__SERVICE__@@@@__CONFIG_@@@@'",
        "|\n    "
        + json.dumps(bcn_payload, sort_keys=True, indent=2).replace("\n", "\n    "),
    )

    if update_cloudinit(
        si, vm, json.dumps(_metadata, separators=(",", ":")), _userdata
    ):
        if vm.runtime.powerState == vim.VirtualMachinePowerState.poweredOn:
            yellowprint(
                "VM is already running - initiating reboot to re-activate cloud-init"
            )
            # FIXME: the BDDS might even be able to consume this using POST configureServerServices
            wait_reboot(vm)
        else:
            boot_vm(vm)
        print("Sleeping up to 2min ...", end="")
        timeout = 120
        _t = 0
        try:
            while True:
                if _t > timeout:
                    break
                if vm.guest.toolsRunningStatus == "guestToolsRunning":
                    if vm.guest.ipAddress is not None:
                        if ipaddr == "192.168.1.1" or ipaddr == "192.168.1.2":
                            # no change of default IP desired - just counting down
                            pass
                        else:
                            if (
                                vm.guest.ipAddress == "192.168.1.1"
                                or vm.guest.ipAddress == "192.168.1.2"
                            ):
                                spinner(
                                    Fore.CYAN
                                    + "Initrd update complete - waiting for cloud-init"
                                    + Style.RESET_ALL
                                )
                            else:
                                # FIXME: we might even want to check GET getServerServicesConfigurationStatus here to ensure that cloud-init completed OK
                                greenprint(
                                    "\rcloud-init config target reached. VM now online as:"
                                )
                                greenprint(vm.guest.ipAddress, prefix="IP: ")
                                greenprint(
                                    vm.guest.toolsRunningStatus, prefix="Tools Status: "
                                )
                                break
                time.sleep(2)
                _t = _t + 2
        except KeyboardInterrupt:
            sys.exit(0)
    return vm


def wait_reboot(vm, perform_reboot=True, timeout=180):
    if perform_reboot:
        reboot_vm(vm)
        blueprint("Waiting for VMware Tools to stop running")
    timeout = 180
    _t = 0
    boot_time = vm.runtime.bootTime
    while True:
        if _t == timeout:
            abort("Timeout!", 2)
        _t += 1
        if vm.guest.toolsRunningStatus == "guestToolsRunning":
            time.sleep(1)
        elif boot_time == vm.runtime.bootTime:
            time.sleep(1)
        else:
            break
    timeout_input("tools stopped. waiting some more...")
    # tools are stopped, now waiting until they come back online
    while True:
        if _t == timeout:
            abort("Timeout!", 2)
        _t += 1
        if vm.guest.toolsRunningStatus == "guestToolsRunning":
            break
        else:
            time.sleep(1)
    timeout_input("Waiting 10s for reboot to actually complete", 10)


# Define progress callback that prints the current percentage completed for the file
def ssh_progress(filename, size, sent):
    sys.stdout.write(
        "%s's progress: %.2f%%   \r"
        % (filename.decode("utf-8"), float(sent) / float(size) * 100)
    )


class VMUpdater:
    def __init__(self, target):
        self.target = target
        self.ssh = None
        self.agent = None
        self.agent_keys = None
        self.retries = 3
        self.reconnect_delay = 2
        self.ssh_connect_timeout = 10
        self.ssh_auth_timeout = 3
        self.private = None
        self.password = None
        self.transport = None
        self.username = "root"

    def __enter__(self):
        self.agent = Agent()
        self.agent_keys = self.agent.get_keys()
        if len(self.agent_keys) == 0:
            yellowprint("No SSH keys loaded in SSH agent")
        # else:
        #    print("Will attempt upload using %d keys" % len(self.agent_keys))

        self.init_ssh()
        self.connect()
        if not self.transport:
            for _t in range(self.retries):
                self.reconnect_if_needed()
                if self.transport:
                    break
        if not self.transport:
            abort("SSH into %s failed!" % self.target)
        elif not self.transport.is_active():
            abort("SSH session to %s closed already?!" % self.target)
        return self

    def init_ssh(self):
        self.ssh = SSHClient()
        self.transport = None
        self.ssh.load_system_host_keys()
        self.ssh._host_keys_filename = None
        self.ssh.set_missing_host_key_policy(AutoAddPolicy)  # nosec: B507

    def connect(self):
        try:
            if self.agent_keys:
                for key in self.agent_keys:
                    print("Trying ssh-agent login with %s" % key.name, end="")
                    if self.ssh._transport is None:
                        _try = 1
                        while _try < self.retries:
                            print(
                                clear_line()
                                + "\rTrying ssh-agent login with %s (%d/%d) "
                                % (key.name, _try, self.retries),
                                end="",
                            )
                            try:
                                self.ssh.connect(
                                    self.target,
                                    username=self.username,
                                    pkey=key,
                                    timeout=self.ssh_connect_timeout,
                                    auth_timeout=self.ssh_auth_timeout,
                                )
                                greenprint("... success!")
                                break
                            except NoValidConnectionsError:
                                yellowprint("... connection lost.")
                                time.sleep(self.reconnect_delay)
                                self.init_ssh()
                                continue
                            except SSHException as e:
                                yellowprint("... nope.")
                                print(e)
                                time.sleep(self.reconnect_delay)
                            _try += 1
                    self.transport = self.ssh.get_transport()
                    if self.transport:
                        if self.transport.is_active():
                            break  # no need to try other private keys
            else:
                if not self.private:
                    _ed25519key = os.environ["HOME"] + "/.ssh/id_ed25519"
                    _rsakey = os.environ["HOME"] + "/.ssh/id_rsa"
                    _ed25519key = "/tmp/x"
                    _rsakey = "/tmp/x"
                    if os.path.isfile(_ed25519key):
                        try:
                            self.private = Ed25519Key.from_private_key_file(_ed25519key)
                        except PasswordRequiredException:
                            from getpass import getpass

                            passphrase = getpass(
                                "Private key passphrase for %s: "
                                % os.path.basename(_ed25519key)
                            )
                            try:
                                self.private = Ed25519Key.from_private_key_file(
                                    _ed25519key, password=passphrase
                                )
                            except PasswordRequiredException:
                                raise SystemExit("Wrong passphrase")
                    elif os.path.isfile(_rsakey):
                        try:
                            self.private = RSAKey.from_private_key_file(_rsakey)
                        except PasswordRequiredException:
                            from getpass import getpass

                            passphrase = getpass(
                                "Private key passphrase for %s: "
                                % os.path.basename(_rsakey)
                            )
                            try:
                                self.private = RSAKey.from_private_key_file(
                                    _rsakey, password=passphrase
                                )
                            except PasswordRequiredException:
                                raise SystemExit("Wrong passphrase")

                    if not self.private:
                        yellowprint("No pubkey found")
                        from getpass import getpass

                        self.password = getpass(
                            "Login password for %s@%s: " % (self.username, self.target)
                        )
                self.ssh.connect(
                    self.target,
                    username=self.username,
                    password=self.password,
                    pkey=self.private,
                )
                self.transport = self.ssh.get_transport()
        except socket.timeout:
            timeout_input("Timeout. Server is not yet online", 10, end="")
            print(clear_line() + "\r", end="")

    def reconnect_if_needed(self, timeout=300):
        _timeout = time.time() + timeout
        _conn_status = "active"
        while True:
            if time.time() > _timeout:
                abort(
                    "No connection could be reestablished with server within %d seconds!"
                    % timeout
                )
            if self.transport:
                if self.transport.is_active():
                    greenprint("SSH connection to %s %s" % (self.target, _conn_status))
                    break
            print("Closing SSH session and opening anew", end="")
            self.ssh.close()
            self.init_ssh()
            timeout_input(
                "No active transport - server either rebooting or still initializing",
                60,
                end="",
            )
            print(clear_line() + "\r", end="")
            self.connect()
            _conn_status = "reestablished"

    def __exit__(self, exc_type, exc_value, traceback):
        if self.ssh:
            self.ssh.close()

    def upload_files(self, files, target_dir="/var/lib/bcn_updates/"):
        # SCPCLient takes a paramiko transport and progress callback as its arguments.
        scp = SCPClient(self.ssh.get_transport(), progress=ssh_progress)

        if isinstance(files, str):
            files = [files]
        if not target_dir.endswith("/"):
            target_dir += "/"
        for f in files:
            print(
                "Uploading '%s' to %s"
                % (
                    Fore.GREEN + f + Style.RESET_ALL,
                    Fore.GREEN + self.target + Style.RESET_ALL,
                )
            )
            scp.put(f, target_dir + os.path.basename(f))
            print("")  # ensure clean newline after output

    def run_ssh_command(self, cmd):
        reboot = False
        stdin, stdout, stderr = self.ssh.exec_command(cmd, get_pty=True)  # nosec: B601
        for line in iter(stdout.readline, ""):
            if "reboot the system" in line:
                reboot = True
            print(line, end="")
        print("")  # ensure clean newline after output
        greenprint("Execution of '%s' finished" % cmd)
        if stdout.channel.recv_exit_status() > 0:
            redprint(
                "Command failed - exit status: %d" % stdout.channel.recv_exit_status()
            )
            return False
        print(reboot)
        return reboot

    def get_version(self):
        self.reconnect_if_needed()
        cmd = """
        if [ -f /usr/local/bluecat/Build.properties ];then
            cat /usr/local/bluecat/Build.properties | grep "version.published" | cut -d= -f2;
        else
            cat /etc/bcn/product.version;
        fi
        """
        stdin, stdout, stderr = self.ssh.exec_command(cmd, get_pty=True)  # nosec: B601
        ver = stdout.read(2048).decode().strip()
        if ver:
            return ver
        else:
            return "0.0.0"
