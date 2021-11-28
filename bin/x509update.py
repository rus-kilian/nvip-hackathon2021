"""
Deploy X.509 cert/key as update to Bluecat VM
"""
import sys

from tools.toolbox.x509 import X509Updater
from tools.toolbox import VMUpdater
from tools.toolbox.internals import greenprint, abort

if len(sys.argv) < 2:
    raise SystemExit("Usage: %s <fqdn>" % sys.argv[0])

config = {}
config["name"] = sys.argv[1]
print("Updating %s X.509 cert" % config["name"])

try:
    with X509Updater(config) as x:
        if not x.needs_update():
            greenprint(
                "Cert for %s already matches. Don't need update." % config["name"]
            )
            sys.exit(0)
        p12 = "certs/%s.p12" % config["name"]
        with open(p12, "wb") as _p12:
            _p12.write(x.gen_pkcs12())
        upload = [p12]
    print("Deploying X.509 config for: ", end="")
    greenprint(config["name"])
    with VMUpdater(config["name"]) as vmu:
        vmu.upload_files(["lib/x509_update.sh"], "/root/bin/")
        vmu.upload_files(upload)
        stdin, stdout, stderr = vmu.ssh.exec_command(  # nosec: B601
            # XXX: redirecting stderr here to catch all output in stdout
            "/root/bin/x509_update.sh /var/lib/bcn_updates/%s.p12 2>&1"
            % config["name"],
        )
        stdin.close()
        for line in iter(stdout.readline, ""):
            print(line, end="")
    with X509Updater(config) as x:
        if x.needs_update():
            abort("Cert for %s still mismatching. WTF?!")
        greenprint("Finished updating X.509 cert")
except KeyboardInterrupt:
    print("")
    abort("Deployment aborted!")
