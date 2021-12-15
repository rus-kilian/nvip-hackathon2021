# pylint: disable=C0103,C0111,R0912
from configparser import ConfigParser
from os.path import expanduser, exists
import abc
import json
import re
import sys

import dateutil.parser
import netaddr
import ipaddress
import requests


__all__ = [
    "Ipam",
    "IpamConnection",
    "network_zone_name",
    "enumDeploymentStatus",
]

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


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


class IpamAPIError(Exception):
    pass


def network_zone_name(net):
    # drop trailing dot and leading octets/nibbles depending no prefixlen
    if isinstance(net, str):
        net = netaddr.IPNetwork(net)
    if net.version == 4:
        rdns = net.network.reverse_dns.split(".")[
            4 - net.prefixlen // 8 : -1  # noqa: E203
        ]
        if not net.prefixlen % 8 == 0:
            if net.prefixlen < 25:
                raise SystemExit("Only aligned subnets allowed")
            else:
                rdns[0] = "%s-%d" % (rdns[0], net.prefixlen)
        return ".".join(rdns)
    if not net.version == 6:
        raise SystemExit("Unsupported net.version: %d" % net.version)
    if not net.prefixlen % 4 == 0:
        raise SystemExit("Only aligned subnets allowed")
    return ".".join(
        net.network.reverse_dns.split(".")[32 - net.prefixlen // 4 : -1]  # noqa: E203
    )


def wanted_ksk(ksks):
    return sorted(ksks, key=lambda ksk: ksk["expire"])[-1]


def enumDeploymentStatus(inputvalue):
    """Provides deployment processing status based on input.  Enumeration-like functionality.
        Note that while python has an enumeration class, it does not support negative integer values.  This function is designed to provide the functionality.
    Args:
        inputvalue (int) or (str): Accepts either an integer or string representing the status of deployment.  See ipmvars.BAM_DEPLOYMENTSTATUS_? for values.
    Returns:
        When input is integer, returns string of status.
        When input is string, returns integer of status.
    """
    if type(inputvalue) is int:
        if int(inputvalue) == -100:
            return "VARIABLEINIT"
        elif int(inputvalue) == -1:
            return "EXECUTING"
        elif int(inputvalue) == 0:
            return "INITIALIZING"
        elif int(inputvalue) == 1:
            return "QUEUED"
        elif int(inputvalue) == 2:
            return "CANCELLED"
        elif int(inputvalue) == 3:
            return "FAILED"
        elif int(inputvalue) == 4:
            return "NOT_DEPLOYED"
        elif int(inputvalue) == 5:
            return "WARNING"
        elif int(inputvalue) == 6:
            return "INVALID"
        elif int(inputvalue) == 7:
            return "DONE"
        elif int(inputvalue) == 8:
            return "NO_RECENT_DEPLOYMENT"
        elif int(inputvalue) == 9:
            return "CANCELLING"
        else:
            return "UNKNOWN"
    else:
        if inputvalue == "VARIABLEINIT":
            return -100
        elif inputvalue == "EXECUTING":
            return -1
        elif inputvalue == "INITIALIZING":
            return 0
        elif inputvalue == "QUEUED":
            return 1
        elif inputvalue == "CANCELLED":
            return 2
        elif inputvalue == "FAILED":
            return 3
        elif inputvalue == "NOT_DEPLOYED":
            return 4
        elif inputvalue == "WARNING":
            return 5
        elif inputvalue == "INVALID":
            return 6
        elif inputvalue == "DONE":
            return 7
        elif inputvalue == "NO_RECENT_DEPLOYMENT":
            return 8
        elif inputvalue == "CANCELLING":
            return 9
        else:
            return -101


def decode_properties(entity):
    props = entity.get("properties", None)
    if props is not None:
        entity["properties"] = dict([e.split("=", 1) for e in props.split("|") if e])
    return entity


def encode_properties(props):
    if props is None:
        return None
    elif isinstance(props, str):
        return props
    else:
        return "|".join(["%s=%s" % (str(k), str(v)) for k, v in props.items()]) + "|"


def split_properties(props):
    if props is None:
        return None
    # print('props: ' + repr(props))
    return dict([e.split("=", 1) for e in props.split("|") if e])


def json_to_entity(entity):
    entity["properties"] = encode_properties(entity.get("properties", None))
    return entity


def parse_ipam_date(d):
    # the parser fails to find the year after "," it there is no space between...
    d = d.replace(",", ", ")
    try:
        return dateutil.parser.parse(d)
    except ValueError:
        # try removing " PM" suffix - it still used the 24h format, which the parse doesn't like
        if d.endswith(" PM"):
            d = d[:-3]
        try:
            return dateutil.parser.parse(d)
        except ValueError:
            eprint("Couldn't parse date string {!r}".format(d))
            raise


class Ipam:
    def __init__(self, config=None, configfile="~/.proteus.conf"):
        if config is None:
            _location = expanduser(configfile)
            if not exists(_location):
                eprint('No such config file "%s"' % configfile)
                raise
            config = ConfigParser()
            with open(expanduser(_location)) as f:
                config.read_string("[root]\n" + f.read())
            config = {
                k: config["root"][k].replace('"', "")
                for k in ["endpoint", "username", "password"]
            }

        self._config = config
        self._connection = None

    def __enter__(self):
        if self._connection is not None:
            raise SystemExit("can't enter twice")
        self._connection = IpamConnection(self._config)
        return self._connection

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._connection is not None:
            c = self._connection
            self._connection = None
            c._logout()


class IpamAPI:
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def raw_get_json(self, path, *args, **kwargs):
        pass

    def raw_post_json(self, path, *args, **kwargs):
        pass

    def raw_put_json(self, path, *args, **kwargs):
        pass

    def add_server(
        self, configurationId, name, ipv4, ipv6, profile="OTHER_DNS_SERVER", **kwargs
    ):  # pylint: disable=W0622
        payload = {
            "configurationId": configurationId,
            "name": name,
            "fullHostName": name,
            "defaultInterfaceAddress": ipv4,
            "profile": profile,
        }
        # if ipv6:
        #    payload["properties"]["servicesIPv6Address"] = ipv6
        # if ipv4:
        #    payload["properties"]["servicesIPv4Address"] = ipv4
        if profile != "OTHER_DNS_SERVER":
            payload["properties"] = {}
            payload["properties"]["password"] = "bluecat"
            payload["properties"]["connected"] = "true"
            payload["properties"]["upgrade"] = "true"
        return self.raw_post_json(
            "addServer", data={}, params=json_to_entity(payload), **kwargs
        )

    def add_entity(self, name, t, parent, properties="", **kwargs):
        payload = {
            "parentId": parent,
        }
        entity = {
            "id": 0,
            "name": name,
            "type": t,
            "properties": properties,
        }
        return self.raw_post_json(
            "addEntity",
            data=json.dumps(entity),
            params=json_to_entity(payload),
            **kwargs
        )

    def add_zone(self, absoluteName, parentId, deployable=True, **kwargs):
        payload = {
            "absoluteName": absoluteName,
            "parentId": parentId,
            "properties": {"deployable": str(deployable).lower()},
        }
        return self.raw_post_json("addZone", params=json_to_entity(payload), **kwargs)

    def add_ip4_block(self, parentId, prefix, name=None, properties=None, **kwargs):
        if not properties:
            properties = {}
        if name:
            if not properties.get("name"):
                properties["name"] = name
        payload = {"CIDR": prefix, "parentId": parentId, "properties": properties}
        return self.raw_post_json(
            "addIP4BlockByCIDR", params=json_to_entity(payload), **kwargs
        )

    def add_ip6_block(self, parentId, prefix, name=None, properties=None, **kwargs):
        payload = {
            "prefix": prefix,
            "parentId": parentId,
            "properties": properties,
        }
        if name:
            payload["name"] = name
        return self.raw_post_json(
            "addIP6BlockByPrefix", params=json_to_entity(payload), **kwargs
        )

    def add_ip4_network(self, parentId, prefix, name=None, properties={}, **kwargs):
        if not properties:
            properties = {}
        if name:
            if not properties.get("name"):
                properties["name"] = name
        payload = {"CIDR": prefix, "blockId": parentId, "properties": properties}
        return self.raw_post_json(
            "addIP4Network", params=json_to_entity(payload), **kwargs
        )

    def add_ip6_network(self, parentId, prefix, name=None, properties={}, **kwargs):
        payload = {
            "prefix": prefix,
            "parentId": parentId,
            "properties": properties,
        }
        if name:
            payload["name"] = name
        return self.raw_post_json(
            "addIP6NetworkByPrefix", params=json_to_entity(payload), **kwargs
        )

    def replace_server(self, oldname, srvid, name, ipv4, **kwargs):
        payload = {
            "name": name,
            "hostName": name,
            "password": "bluecat",
            "defaultInterface": ipv4,
            "serverId": srvid,
            "upgrade": "true",
            "properties": {
                "resetServices": "true",
            },
        }
        return self.raw_put_json(
            "replaceServer", data={}, params=json_to_entity(payload), **kwargs
        )

    def add_dns_deployment_role(
        self, entityId, serverInterfaceId, roletype, properties={}, **kwargs
    ):
        payload = json_to_entity(
            {
                "entityId": entityId,
                "serverInterfaceId": serverInterfaceId,
                "type": roletype,
                "properties": properties,
            }
        )
        if debug:
            print(payload)
        return self.raw_post_json(
            "addDNSDeploymentRole", data={}, params=payload, **kwargs
        )

    def delete_dns_deployment_role(self, entityId, serverInterfaceId, **kwargs):
        payload = json_to_entity(
            {
                "entityId": entityId,
                "serverInterfaceId": serverInterfaceId,
            }
        )
        if debug:
            print(payload)
        return self.raw_delete_json(
            "deleteDNSDeploymentRole", data={}, params=payload, **kwargs
        )

    def add_dns_deployment_option(self, entityId, name, properties, value, **kwargs):
        if debug:
            print("+++ Adding DNS deployment option to entity:")
            print(self.get_entity_by_id(entityId))
        payload = json_to_entity(
            {
                "entityId": entityId,
                "name": name,
                "properties": properties,
                "value": value,
            }
        )
        if debug:
            print(payload)
        return self.raw_post_json(
            "addDNSDeploymentOption", data={}, params=payload, **kwargs
        )

    def disable_server(self, id, **kwargs):  # pylint: disable=W0622
        entity = self.get_entity_by_id(id)
        if entity["properties"]["profile"] == "OTHER_DNS_SERVER":
            return
        return self._put_rest(
            "updateWithOptions",
            params="options=disable=true",
            json=json_to_entity(entity),
            **kwargs
        )

    def enable_server(self, id, **kwargs):  # pylint: disable=W0622
        entity = self.get_entity_by_id(id)
        return self._put_rest(
            "updateWithOptions",
            params="options=disable=false",
            json=json_to_entity(entity),
            **kwargs
        )

    def delete_entity(self, id, **kwargs):  # pylint: disable=W0622
        return self._put_rest(
            "delete", params=json_to_entity({"objectId": id}), **kwargs
        )

    def deploy_server(self, id, **kwargs):  # pylint: disable=W0622
        return self._post_rest(
            "deployServer", params=json_to_entity({"serverId": id}), **kwargs
        )

    def get_server_deployment_status(self, id, **kwargs):  # pylint: disable=W0622
        res = self._get_rest(
            "getServerDeploymentStatus",
            params=json_to_entity({"serverId": id}),
            **kwargs
        )
        if res.status_code != 200:
            return "UNKNOWN"
        else:
            return enumDeploymentStatus(int(res.text))

    def update_entity(self, entity, **kwargs):  # pylint: disable=W0622
        if debug:
            print(entity)
        return self._put_rest("update", json=json_to_entity(entity), **kwargs)

    def migrate_xml(self, xmlfile, **kwargs):
        return self.raw_post_json(
            "migrateFile",
            data={},
            params=json_to_entity({"filename": xmlfile}),
            **kwargs
        )

    def get_entity_by_name(
        self, parentId, name, type, **kwargs
    ):  # pylint: disable=W0622
        return decode_properties(
            self.raw_get_json(
                "getEntityByName",
                params={
                    "parentId": parentId,
                    "name": name,
                    "type": type,
                },
                **kwargs
            )
        )

    def get_entity_by_id(self, id, **kwargs):  # pylint: disable=W0622
        return decode_properties(
            self.raw_get_json(
                "getEntityById",
                params={
                    "id": id,
                },
                **kwargs
            )
        )

    def get_entities(self, parentId, type, **kwargs):  # pylint: disable=W0622
        if isinstance(type, list):
            for t in type:
                for e in self.get_entities(parentId, t, **kwargs):
                    yield e
            return
        params = {
            "parentId": parentId,
            "type": type,
            "start": 0,
            "count": 500,
        }
        while True:
            try:
                block = self.raw_get_json("getEntities", params=params, **kwargs)
            except IpamAPIError:
                # no entities found
                return
            if not block:
                return
            for elem in block:
                yield decode_properties(elem)
            if len(block) != params["count"]:
                break

    def get_linked_entities(self, entityId, type, **kwargs):  # pylint: disable=W0622
        params = {
            "entityId": entityId,
            "type": type,
            "start": 0,
            "count": 500,
        }
        while True:
            block = self.raw_get_json("getLinkedEntities", params=params, **kwargs)
            if not block:
                return
            for elem in block:
                yield decode_properties(elem)
            if len(block) != params["count"]:
                break

    def get_dns_option(self, entityId, name, serverId=0, **kwargs):
        if debug:
            print(
                "Fetching DNS Option %s at %d for server %d"
                % (name, int(entityId), int(serverId))
            )
        _res = self.raw_get_json(
            "getDNSDeploymentOption",
            params={"entityId": entityId, "name": name, "serverId": serverId},
            **kwargs
        )
        if _res:
            return _res.get("value", None)

    def get_server_roles(self, serverId, **kwargs):
        return [
            decode_properties(r)
            for r in (
                self.raw_get_json(
                    "getServerDeploymentRoles", params={"serverId": serverId}, **kwargs
                )
            )
        ]

    def get_deployment_role(self, entityId, **kwargs):
        return [
            decode_properties(r)
            for r in (
                self.raw_get_json(
                    "getDeploymentRoles", params={"entityId": entityId}, **kwargs
                )
            )
        ]

    # format: 'TRUST_ANCHOR', 'DNS_KEY', 'DS_RECORD'
    def get_ksks(self, entityId, format="TRUST_ANCHOR"):  # pylint: disable=W0622
        result = []
        if entityId == 0:
            print("Zone entityId 0 is not valid!")
            return result
        try:
            ksks = self.raw_get_json(
                "getKSK",
                params={
                    "entityId": entityId,
                    "format": format,
                },
            )
            for k in ksks:
                (data, create, expire) = k.split("|", 2)
                result.append(
                    {
                        "data": data,
                        "create": parse_ipam_date(create),
                        "expire": parse_ipam_date(expire),
                    }
                )
        except Exception as e:
            print("Error fetching KSK for %d - %s" % (entityId, e))
        return result


class IpamConnection(IpamAPI):
    def __init__(self, config):
        self._config = config
        self._token = None
        self._login()

    def _get(self, path, *args, **kwargs):
        debug = kwargs.get("debug", False)
        uri = "{}/{}".format(self._config["endpoint"], path)
        response = requests.get(uri, *args, **kwargs)
        if debug:
            print("Response for {} with {!r}".format(path, kwargs.get("params", {})))
            print("Req-Headers: {!r}".format(kwargs.get("headers")))
            print("Response-Headers: {!r}".format(response.headers))
            print(repr(response))
            print(repr(response.text))
        return response

    def _post(self, path, *args, **kwargs):
        debug = kwargs.get("debug", False)
        uri = "{}/{}".format(self._config["endpoint"], path)
        response = requests.post(uri, *args, **kwargs)
        if debug:
            print("Response for {} with {!r}".format(path, kwargs.get("params", {})))
            print("POST Body: {!r}".format(kwargs.get("data", {})))
            print("Req-Headers: {!r}".format(kwargs.get("headers")))
            print("Response-Headers: {!r}".format(response.headers))
            print(repr(response))
            print(repr(response.text))
        return response

    def _put(self, path, *args, **kwargs):
        debug = kwargs.get("debug", False)
        uri = "{}/{}".format(self._config["endpoint"], path)
        response = requests.put(uri, *args, **kwargs)
        if debug:
            print("Response for {} with {!r}".format(path, kwargs.get("params", {})))
            print("POST Body: {!r}".format(kwargs.get("data", {})))
            print("Req-Headers: {!r}".format(kwargs.get("headers")))
            print("Response-Headers: {!r}".format(response.headers))
            print(repr(response))
            print(repr(response.text))
        return response

    def _delete(self, path, *args, **kwargs):
        debug = kwargs.get("debug", False)
        uri = "{}/{}".format(self._config["endpoint"], path)
        response = requests.delete(uri, *args, **kwargs)
        if debug:
            print("Response for {} with {!r}".format(path, kwargs.get("params", {})))
            print("POST Body: {!r}".format(kwargs.get("data", {})))
            print("Req-Headers: {!r}".format(kwargs.get("headers")))
            print("Response-Headers: {!r}".format(response.headers))
            print(repr(response))
            print(repr(response.text))
        return response

    def _get_rest(self, path, *args, **kwargs):
        headers = kwargs.get("headers", {})
        if self._token:
            new_headers = {
                "Authorization": self._token,
            }
            new_headers.update(headers)
            headers = new_headers
        return self._get("Services/REST/v1/" + path, *args, headers=headers, **kwargs)

    def _post_rest(self, path, *args, **kwargs):
        headers = kwargs.get("headers", {})
        if self._token:
            new_headers = {
                "Authorization": self._token,
                "Content-Type": "application/json",
                "cache-control": "no-cache",
            }
            new_headers.update(headers)
            headers = new_headers
        return self._post("Services/REST/v1/" + path, *args, headers=headers, **kwargs)

    def _put_rest(self, path, *args, **kwargs):
        headers = kwargs.get("headers", {})
        if self._token:
            new_headers = {
                "Authorization": self._token,
                "Content-Type": "application/json",
                "cache-control": "no-cache",
            }
            new_headers.update(headers)
            headers = new_headers
        return self._put("Services/REST/v1/" + path, *args, headers=headers, **kwargs)

    def _delete_rest(self, path, *args, **kwargs):
        headers = kwargs.get("headers", {})
        if self._token:
            new_headers = {
                "Authorization": self._token,
                "Content-Type": "application/json",
                "cache-control": "no-cache",
            }
            new_headers.update(headers)
            headers = new_headers
        return self._delete(
            "Services/REST/v1/" + path, *args, headers=headers, **kwargs
        )

    def _logout(self):
        try:
            self._get_rest("logout")
        finally:
            self._token = None

    def _login(self):
        if self._token:
            self._get_rest("logout")
        self._token = None
        login_response = self._get_rest(
            "login",
            params={
                "username": self._config["username"],
                "password": self._config["password"],
            },
        )
        if login_response.status_code == 200:
            m = re.compile(r"\s(BAMAuthToken:\s*\S+)\s").search(login_response.text)
            if not m:
                raise SystemExit(
                    "Couldn't find auth token in {}".format(login_response.text)
                )
            self._token = m.group(1)
            # print("Login got token: {!r}".format(self._token))
        else:
            raise SystemExit("Login failed")

    def raw_get_json(self, path, *args, **kwargs):
        response = self._get_rest(path, *args, **kwargs)
        if response.status_code == 401:
            # try again with new login
            self._login()
            response = self._get_rest(path, *args, **kwargs)
        if response.status_code == 200:
            if response.text:
                return json.loads(response.text)
            return
        raise IpamAPIError(
            "Request to {!r} failed: {!r}\n{!r}".format(path, response, response.text)
        )

    def raw_post_json(self, path, *args, **kwargs):
        response = self._post_rest(path, *args, **kwargs)
        if response.status_code == 401:
            # try again with new login
            self._login()
            response = self._post_rest(path, *args, **kwargs)
        if response.status_code == 200:
            try:
                if response.text:
                    return json.loads(response.text)
                return
            except json.decoder.JSONDecodeError:
                return
        raise IpamAPIError(
            "Request to {!r} failed: {!r}\n{!r}".format(path, response, response.text)
        )

    def raw_put_json(self, path, *args, **kwargs):
        response = self._put_rest(path, *args, **kwargs)
        if response.status_code == 401:
            # try again with new login
            self._login()
            response = self._put_rest(path, *args, **kwargs)
        if response.status_code == 200:
            if response.text:
                return json.loads(response.text)
            return
        raise IpamAPIError(
            "Request to {!r} failed: {!r}\n{!r}".format(path, response, response.text)
        )

    def raw_delete_json(self, path, *args, **kwargs):
        response = self._delete_rest(path, *args, **kwargs)
        if response.status_code == 401:
            # try again with new login
            self._login()
            response = self._delete_rest(path, *args, **kwargs)
        if response.status_code == 200:
            if response.text:
                return json.loads(response.text)
            return
        raise IpamAPIError(
            "Request to {!r} failed: {!r}\n{!r}".format(path, response, response.text)
        )


class IpamGenericCache:
    def __init__(self, connection):
        self._conn = connection
        self.clear_cache()

    def clear_cache(self):
        self._generic_cache_configurations = {}
        self._generic_cache_views = {}
        self._generic_cache_zones = {}
        self._generic_cache_networks = {}
        self._generic_cache_dns_options = {}
        self._generic_cache_server_interface = {}

    def generic_get_configuration(self, config_name):
        if not self._generic_cache_configurations.get(config_name):
            c = self._conn.get_entity_by_name(0, config_name, "Configuration")
            self._generic_cache_configurations[config_name] = c
        return self._generic_cache_configurations[config_name]

    def generic_get_view(self, config_name, view_name):
        if config_name not in self._generic_cache_views:
            self._generic_cache_views[config_name] = {}
        views = self._generic_cache_views[config_name]

        if not views.get(view_name):
            c = self.generic_get_configuration(config_name)

            views[view_name] = self._conn.get_entity_by_name(c["id"], view_name, "View")
        return views[view_name]

    def generic_get_dns_option(self, entityId, name, serverId):
        if name not in self._generic_cache_dns_options:
            self._generic_cache_dns_options[name] = {}
        servers = [0]
        if int(serverId) > 0:
            servers = [serverId, 0]
        for s in servers:
            if s not in self._generic_cache_dns_options[name]:
                self._generic_cache_dns_options[name][s] = {}
            if entityId in self._generic_cache_dns_options[name][s]:
                if debug:
                    print(
                        "Cache hit for DNS option %s on %d for srv %d"
                        % (name, int(entityId), int(s))
                    )
                return self._generic_cache_dns_options[name][s][entityId]
        if "default" in self._generic_cache_dns_options[name][serverId]:
            if debug:
                print(
                    "Default server option Cache hit for DNS option %s on %d for srv %d"
                    % (name, int(entityId), int(serverId))
                )
            return self._generic_cache_dns_options[name][serverId]["default"]
        # no cache hit - actually fetch DNS options
        for s in servers:
            _res = self._conn.get_dns_option(entityId, name, s)
            if _res is not None:
                if debug:
                    print(
                        "Lookup complete for DNS option %s on %d for %d"
                        % (name, int(entityId), int(serverId)),
                        _res,
                    )
                self._generic_cache_dns_options[name][serverId][entityId] = _res
                return _res
        # default to server options or None
        if debug:
            print(
                "Lookup complete for server default DNS option %s on %d"
                % (name, int(serverId)),
                _res,
            )
        _res = self._conn.get_dns_option(serverId, name, serverId)
        self._generic_cache_dns_options[name][serverId]["default"] = _res
        return _res

    def generic_find_zone(self, config_name, view_name, zone):
        # cut off trailing dot
        if zone.endswith("."):
            zone = zone[:-1]

        if config_name not in self._generic_cache_zones:
            self._generic_cache_zones[config_name] = {}
        views_zones = self._generic_cache_zones[config_name]

        if view_name not in views_zones:
            views_zones[view_name] = {}
        zones = views_zones[view_name]

        if zone not in zones:
            view = self.generic_get_view(config_name, view_name)

            def walk(name):
                if name not in zones:
                    if name == "":
                        zones[name] = view
                    elif "." not in name:
                        zones[name] = self._conn.get_entity_by_name(
                            view["id"], name, "Zone"
                        )
                    else:
                        (localname, parent) = name.split(".", 1)
                        zones[name] = self._conn.get_entity_by_name(
                            walk(parent)["id"],
                            localname,
                            "Zone",
                        )
                return zones[name]

            walk(zone)

        return zones[zone]

    def generic_find_network_parent(self, config_name, network):
        if config_name not in self._generic_cache_networks:
            self._generic_cache_networks[config_name] = {}
        networks = self._generic_cache_networks[config_name]

        def scan_v4_children(parentId):
            children = []
            for e in self._conn.get_entities(parentId, ["IP4Block", "IP4Network"]):
                try:
                    cidr = str(ipaddress.ip_network(e["properties"]["CIDR"]))
                except Exception as e:
                    eprint("Invalid IPv4 object (no CIDR): " + repr(e))
                    raise
                else:
                    children.append(cidr)
                    networks[cidr] = [e, None]
            return children

        def scan_v6_children(parentId):
            children = []
            for e in self._conn.get_entities(parentId, ["IP6Block", "IP6Network"]):
                try:
                    cidr = str(ipaddress.ip_network(e["properties"]["prefix"]))
                except Exception as e:
                    eprint("Invalid IPv6 object (no prefix): " + repr(e))
                    raise
                else:
                    children.append(cidr)
                    networks[cidr] = [e, None]
            return children

        if network not in networks:
            if None not in networks:
                networks[None] = [self.generic_get_configuration(config_name), None]
            current = None
            while True:
                obj = networks[current]
                if obj[1] is None:
                    if current is None:
                        obj[1] = scan_v4_children(obj[0]["id"]) + scan_v6_children(
                            obj[0]["id"]
                        )
                    elif current.version == 4:
                        obj[1] = scan_v4_children(obj[0]["id"])
                    elif current.version == 6:
                        obj[1] = scan_v6_children(obj[0]["id"])
                    else:
                        raise Exception("invalid netaddr object: " + repr(current))

                for c in obj[1]:
                    if network == c:
                        return (network, networks[network][0])
                    if network in c:
                        current = c
                        break
                else:
                    return (current, obj[0])

        return (network, networks[network][0])

    def generic_find_network(self, config_name, network):
        (found, obj) = self.generic_find_network_parent(config_name, network)
        if found == network:
            return obj

        raise Exception("network {} not found".format(network))

    def generic_get_server_interface(self, serverid):
        if serverid in self._generic_cache_server_interface:
            return self._generic_cache_server_interface[serverid]

        for _i in self._conn.get_entities(serverid, "NetworkServerInterface"):
            self._generic_cache_server_interface[serverid] = _i["id"]
            return _i["id"]


class IpamUS(IpamGenericCache, IpamAPI):
    CONFIGURATION = "Uni-Stuttgart"
    EXTERN_VIEW = "extern"

    def __init__(self, connection):
        super().__init__(connection)
        self._conn = connection
        self._configuration_id = self.get_configuration_id()

    def raw_get_json(self, path, *args, **kwargs):
        return self._conn.raw_get_json(path, *args, **kwargs)

    def raw_post_json(self, path, *args, **kwargs):
        return self._conn.raw_post_json(path, *args, **kwargs)

    def raw_put_json(self, path, *args, **kwargs):
        return self._conn.raw_put_json(path, *args, **kwargs)

    def get_configuration_id(self):
        _id = self.generic_get_configuration(IpamUS.CONFIGURATION)["id"]
        if _id:
            return _id

    def get_extern_view_id(self):
        _id = self.generic_get_view(IpamUS.CONFIGURATION, IpamUS.EXTERN_VIEW)["id"]
        if _id:
            return _id

    def get_dns_option(self, entityid, name, serverid):
        return self.generic_get_dns_option(entityid, name, serverid)

    def get_server_roles(self, id):
        return self._conn.get_server_roles(id)

    def get_entities(
        self,
        entityid,
        enttype=["IP4Block", "IP4Network", "IP6Block", "IP6Network", "View", "Zone"],
    ):
        return self._conn.get_entities(entityid, enttype)

    def find_network_parent(self, network):
        return self.generic_find_network_parent(IpamUS.CONFIGURATION, network)

    def find_network(self, network):
        return self.generic_find_network(IpamUS.CONFIGURATION, network)

    def find_zone(self, name):
        return self.generic_find_zone(IpamUS.CONFIGURATION, IpamUS.EXTERN_VIEW, name)

    def add_server(self, name, ipv4, ipv6, profile="OTHER_DNS_SERVER"):
        return self._conn.add_server(self._configuration_id, name, ipv4, ipv6, profile)

    def get_server_interface(self, serverid):
        return self.generic_get_server_interface(serverid)

    def add_entity(self, name, t, parent, properties=""):
        return self._conn.add_entity(name, t, parent, properties)

    def add_zone(self, absoluteName, parentId, deployable=True):
        return self._conn.add_zone(absoluteName, parentId, deployable)

    def add_block(self, parentId, prefix, name=None, properties=None):
        try:
            cidr = ipaddress.ip_network(prefix)
        except Exception as e:
            eprint("Invalid IP prefix (no CIDR): " + repr(e))
            raise
        if cidr.version == 4:
            if not properties:
                properties = {}
            if not properties.get("defaultView"):
                properties["defaultView"] = self.get_extern_view_id()
            return self._conn.add_ip4_block(parentId, prefix, name, properties)
        else:
            return self._conn.add_ip6_block(parentId, prefix, name, properties)

    def add_network(self, parentId, prefix, name=None, properties=None):
        try:
            cidr = ipaddress.ip_network(prefix)
        except Exception as e:
            eprint("Invalid IP prefix (no CIDR): " + repr(e))
            raise
        if cidr.version == 4:
            if not properties:
                properties = {}
            if not properties.get("defaultView"):
                properties["defaultView"] = self.get_extern_view_id()
            return self._conn.add_ip4_network(parentId, prefix, name, properties)
        else:
            return self._conn.add_ip6_network(parentId, prefix, name, properties)

    def replace_server(self, oldname, srvid, name, ipv4):
        return self._conn.replace_server(oldname, srvid, name, ipv4)

    def add_dns_deployment_role(
        self,
        entityId,
        serverInterfaceId,
        roletype,
        properties={},
    ):
        return self._conn.add_dns_deployment_role(
            entityId,
            serverInterfaceId,
            roletype,
            properties,
        )

    def delete_dns_deployment_role(
        self,
        entityId,
        serverInterfaceId,
    ):
        return self._conn.delete_dns_deployment_role(
            entityId,
            serverInterfaceId,
        )

    def get_deployment_roles(
        self,
        entityId,
    ):
        return self._conn.get_deployment_role(
            entityId,
        )

    def add_dns_deployment_option(
        self, entityId, name, value, properties=None, server=None, serverGroup=None
    ):
        if server or serverGroup:
            if not properties:
                properties = {}
            if server:
                properties["server"] = server
            if serverGroup:
                properties["serverGroup"] = server
        return self._conn.add_dns_deployment_option(entityId, name, properties, value)

    def disable_server(self, id):
        return self._conn.disable_server(id)

    def enable_server(self, id):
        return self._conn.enable_server(id)

    def delete_entity(self, id):
        return self._conn.delete_entity(id)

    def deploy_server(self, id):
        return self._conn.deploy_server(id)

    def get_server_deployment_status(self, id):
        return self._conn.get_server_deployment_status(id)

    def update_entity(self, entity):
        return self._conn.update_entity(entity)

    def migrate_xml(self, xmlfile):
        return self._conn.migrate_xml(xmlfile)

    def bootstrap(self):
        if not self._configuration_id:
            print("No Configuration found. Bootstrapping one")
            self._configuration_id = self.add_entity(
                IpamUS.CONFIGURATION, "Configuration", 0
            )
            print("Configuration ID: %d" % int(self._configuration_id))
        if not self.get_extern_view_id():
            print("No default view found in Configuration. Bootstrapping one")
            self.add_entity(IpamUS.EXTERN_VIEW, "View", self._configuration_id)
            self.clear_cache()
            print(
                "View ID '%s': %d"
                % (IpamUS.EXTERN_VIEW, int(self.get_extern_view_id()))
            )
