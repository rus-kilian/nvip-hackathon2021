import os
import base64
import datetime
from time import sleep
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509
from tools.toolbox import greenprint, abort
from dns.resolver import Resolver, NXDOMAIN
from colorama.ansi import clear_line
from ssl import get_server_certificate

TEMPLATE = """-----BEGIN RSA PRIVATE KEY-----
%s
-----END RSA PRIVATE KEY-----
"""


def der_to_pem(keybytes):
    if isinstance(keybytes, str):
        keybytes = keybytes.encode()
    data = TEMPLATE % base64.b64encode(keybytes).decode("ascii")
    return data.encode("ascii")


class X509Updater:
    def __init__(self, config):
        self.resolver = Resolver()
        self.config = config
        self.name = None
        self.rootca = None
        self.rootca_file = None
        self.intermediate = []
        self.keyfile = None
        self.key = None
        self.certfile = None
        self.cert = None
        self.encrypt_passphrase = "bluecat"

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def __enter__(self):
        if not isinstance(self.config, dict):
            abort("config is not a dict!")

        if "name" not in self.config:
            abort("name is not defined in config dict!")

        self.name = self.config["name"]
        # FIXME: this will also need to learn IPv6 once cloud-init also has learned IPv6
        try:
            targets = self.resolver.query(self.name, "A")
        except NXDOMAIN:
            abort("NXDOMAIN - Not a valid FQDN: `%s`" % self.name)
        if not targets:
            abort("Not a valid FQDN: `%s`" % self.name)
        v4addrs = [v4.address for v4 in targets]
        if self.config["ipaddr"] not in v4addrs:
            abort(
                "Valid FQDN `%s` pointing to different IP than configured: %s (vs. %s)"
                % (self.name, ", ".join(v4addrs), self.config["ipaddr"])
            )

        self.rootca_file = "certs/rootca.crt"
        if not os.path.exists(self.rootca_file):
            abort("No root CA found at '%s'" % self.rootca_file)
        self.rootca = self.load_cert(self.rootca_file)
        if not self.rootca.issuer == self.rootca.subject:
            abort(
                "Invalid Root CA! Issuer '%s' != Subject '%s'"
                % (self.rootca.issuer, self.rootca.subject)
            )

        intermediates = "certs/intermediate"
        if not os.path.exists(intermediates):
            abort("No intermediate CA dir found at '%s'" % intermediates)

        _ica_avail = {}
        for i in os.listdir(intermediates):
            # FIXME: need to iterate through intermediates
            _ica = self.load_cert("%s/%s" % (intermediates, i))
            if _ica.subject in _ica_avail:
                abort("Duplicate intermediate CA found: %s (%s)" % (_ica.subject, i))
            if _ica.subject == _ica.issuer:
                abort("CA '%s' is not an intermediate CA" % i)
            _ica_avail[_ica.subject] = {}
            _ica_avail[_ica.subject]["issuer"] = _ica.issuer
            _ica_avail[_ica.subject]["ca"] = _ica

        for ext in ["crt", "pem", "der"]:
            _filename = "certs/%s.%s" % (self.name, ext)
            if os.path.exists(_filename):
                self.certfile = _filename
                break
        if not self.certfile:
            abort("No cert file found!")
        self.cert = self.load_cert(self.certfile)
        if not self.check_cert_fqdn(self.cert, self.name):
            abort("Cert %s does not match FQDN %s" % (self.certfile, self.name))

        greenprint("Cert %s matches FQDN %s!" % (self.certfile, self.name))

        for ext in ["key", "pem"]:
            _filename = "certs/%s.%s" % (self.name, ext)
            if os.path.exists(_filename):
                self.keyfile = _filename
                break
        if not self.keyfile:
            abort("No key file found!")
        self.load_key()

        self.verify_key_and_cert()

        _parent_issuer = self.cert.issuer
        while True:
            if _parent_issuer == self.rootca.subject:
                greenprint("CA chain validated")
                break
            if _parent_issuer not in _ica_avail:
                abort("No such (intermediate) CA found: '%s'" % _parent_issuer)
            self.intermediate += [_ica_avail[_parent_issuer]["ca"]]
            _parent_issuer = _ica_avail[_parent_issuer]["issuer"]

        return self

    def needs_update(self, retries=10, delay=15):
        print("Checking https cert on %s against configured one..." % self.name, end="")
        for retry in range(1, retries):
            try:
                _cert = x509.load_pem_x509_certificate(
                    get_server_certificate((self.name, 443)).encode()
                )
                if _cert != self.cert:
                    print(
                        clear_line()
                        + "\rhttps cert on %s mismatches cert to load" % self.name
                    )
                    return True
                print(clear_line() + "\r", end="")
                return False
            except ConnectionRefusedError:
                for _d in range(delay, 0, -1):
                    print(
                        clear_line()
                        + "\rConnection refused while connecting to https://%s/. Waiting %ds. [attempt %d/%d]"
                        % (self.name, _d, retry, retries),
                        end="",
                    )
                    sleep(1)
        print(
            clear_line()
            + "\rTimeout while connecting to https://%s/. Forcing update." % self.name
        )
        return True

    def check_validity(self, cert, min_val=30):
        _now = datetime.datetime.now()
        _min_val = _now + datetime.timedelta(days=min_val)

        if cert.not_valid_before > _now:
            abort("Cert '%s' is not yet valid!" % cert.subject)
        if cert.not_valid_after < _min_val:
            abort(
                "Cert '%s' is not valid any more! Only until: %s"
                % (cert.subject, cert.not_valid_after)
            )

    def passphrase_callback(self, void_bool, void1=None, void2=None):
        if "key_passphrase" in self.config:
            return self.config["key_passphrase"].encode()

    def verify_key_and_cert(self):
        # FIXME: still verify cert+key are matching
        # https://github.com/pyca/cryptography/pull/5093
        # self.cert.verify(
        #    intermediates=[self.intermediate],
        #    trusted_roots=[self.rootca],
        #    cert_verif_cb=lambda c, i: True,
        # )
        # FIXME: actually check whether rootca, intermediate and cert do align

        # FIXME: let's just do it the cheap way for now

        if self.key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.PKCS1
        ) != self.cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.PKCS1
        ):
            print(
                self.cert.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.PKCS1,
                )
            )
            print(
                self.key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.PKCS1,
                )
            )
            abort("Mismatching private key and cert")

    def load_cert(self, certfile):
        cert = None
        if not os.path.exists(certfile):
            abort("No such cert: %s" % certfile)
        with open(certfile, "rb") as _certfile:
            _c = _certfile.read().strip()
        try:
            cert = x509.load_pem_x509_certificate(_c)
        except ValueError:
            cert = x509.load_der_x509_certificate(_c)
        if not cert:
            abort("Invalid certificate data!")
        self.check_validity(cert)
        return cert

    def check_cert_fqdn(self, cert, name):
        match = False
        if "CN=%s" % name in str(cert.subject):
            match = True
        for ext in cert.extensions:
            if ext.oid._name == "subjectAltName":
                for _n in ext.value:
                    if isinstance(_n, x509.DNSName):
                        if _n.value == name:
                            match = True
        return match

    def load_key(self):
        if not self.keyfile:
            abort("No key file found!")

        if not os.path.exists(self.keyfile):
            abort("No such key: %s" % self.keyfile)
        with open(self.keyfile, "rb") as _key:
            raw = _key.read()
        try:
            # just ensure we do have a plain text PEM format
            pem = raw.decode("ascii").encode("ascii")
        except UnicodeDecodeError:
            pem = der_to_pem(raw)
        if not pem:
            abort("No valid PEM file")

        # try unencrypted load first
        password = None
        try:
            private_key = serialization.load_pem_private_key(
                pem,
                password=password,
            )
        except TypeError:
            password = self.passphrase_callback(False)
            private_key = serialization.load_pem_private_key(
                pem,
                password=password,
            )
        if not private_key:
            abort("FAILED to load key!")

        # reformat to PKCS8 for importing it into BAM
        pkcs8key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                self.encrypt_passphrase.encode()
            ),
        )
        if not pkcs8key:
            abort("FAILED to load key!")
        private_key = serialization.load_pem_private_key(
            pkcs8key,
            password=self.encrypt_passphrase.encode(),
        )
        greenprint("Loaded key successfully")
        self.key = private_key
        if self.cert:
            self.verify_key_and_cert()

    def gen_pkcs12(self):
        return pkcs12.serialize_key_and_certificates(
            self.name.encode("ascii"),
            self.key,
            self.cert,
            self.intermediate,
            serialization.BestAvailableEncryption(self.encrypt_passphrase.encode()),
        )
