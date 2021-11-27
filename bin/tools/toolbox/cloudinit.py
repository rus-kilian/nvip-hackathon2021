import json
import yaml

try:
    from cStringIO import StringIO as BytesIO
except ImportError:
    from io import BytesIO

import pycdlib


def gen_cloudinit_iso(path, metadata, userdata):
    iso = pycdlib.PyCdlib()
    iso.new(rock_ridge="1.09", joliet=3, vol_ident="cidata")
    _md = json.dumps(metadata, separators=(",", ":")).encode("utf-8")
    iso.add_fp(
        BytesIO(_md),
        len(_md),
        "/METADATA.;1",
        joliet_path="/meta-data",
        rr_name="meta-data",
    )
    _ud_cloud = "#cloud-config\n" + yaml.dump(userdata)
    _ud = _ud_cloud.encode("utf-8")
    iso.add_fp(
        BytesIO(_ud),
        len(_ud),
        "/USERDATA.;1",
        joliet_path="/user-data",
        rr_name="user-data",
    )
    iso.write(path)
    iso.close()
