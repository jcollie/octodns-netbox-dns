"""OctoDNS provider for NetboxDNS."""
import logging
from pprint import pprint

import dns.rdata
import octodns.provider.base
import octodns.provider.plan
import octodns.record
import octodns.zone
import pynetbox.core.api
import pynetbox.core.response


class NetBoxDNSSource(octodns.provider.base.BaseProvider):
    """NetBoxDNS source for OctoDNS."""

    SUPPORTS_GEO: bool = False
    SUPPORTS_DYNAMIC: bool = False
    SUPPORTS: set[str] = {
        "A",
        "AAAA",
        "AFSDB",
        "APL",
        "CAA",
        "CDNSKEY",
        "CERT",
        "CNAME",
        "DCHID",
        "DNAME",
        "DNSKEY",
        "DS",
        "HIP",
        "IPSECKEY",
        "LOC",
        "MX",
        "NAPTR",
        "NS",
        "NSEC",
        "PTR",
        "RP",
        "RRSIG",
        "SOA",
        "SPF",
        "SRV",
        "SSHFP",
        "TLSA",
        "TXT",
    }

    _api: pynetbox.core.api.Api
    # log: logging.Logger
    _nb_view: pynetbox.core.response.Record | None
    _ttl: int

    def __init__(self, id: int, url: str, token: str, view: str | None, ttl=3600):
        """Initialize the NetboxDNSSource."""
        self.log = logging.getLogger(f"NetboxDNSSource[{id}]")
        self.log.debug(f"__init__: id={id}, url={url}, view={view}")
        super(NetBoxDNSSource, self).__init__(id)
        self._api = pynetbox.core.api.Api(url, token)
        self._nb_view = None
        if view is not None:
            self._nb_view = self._api.plugins.netbox_dns.views.get(name=view)
            if self._nb_view is None:
                raise ValueError
            self.log.debug(f"found {self._nb_view.name} {self._nb_view.id}")
        self._ttl = ttl

    def _get_nb_zone(self, name: str) -> pynetbox.core.response.Record:
        """Given a zone name, look it up in NetBox."""
        if self._nb_view is None:
            nb_zones = self._api.plugins.netbox_dns.zones.filter(name=name[:-1])
            if len(nb_zones) > 1:
                raise ValueError
            if len(nb_zones) == 0:
                raise ValueError
            return next(nb_zones)

        nb_zones = self._api.plugins.netbox_dns.zones.filter(
            view_id=self._nb_view.id, name=name[:-1]
        )
        for nb_zone in nb_zones:
            self.log.debug(f"{nb_zone.name} {nb_zone.view.id}")
            if nb_zone.name == name[:-1] and nb_zone.view.id == self._nb_view.id:
                return nb_zone

        raise ValueError

    def populate(
        self, zone: octodns.zone.Zone, target: bool = False, lenient: bool = False
    ):
        """Get all of the records of a zone from NetBox and add them to the OctoDNS zone."""
        self.log.debug(
            f"populate: name={zone.name}, target={target}, lenient={lenient}"
        )

        records = {}

        nb_zone = self._get_nb_zone(zone.name)

        nb_records = self._api.plugins.netbox_dns.records.filter(zone_id=nb_zone.id)
        for nb_record in nb_records:
            self.log.debug(
                f"{nb_record.name!r} {nb_record.type!r} {nb_record.value!r}"
            )
            name = nb_record.name
            if name == "@":
                name = ""
            data = {
                "name": name,
                "type": nb_record.type,
                "ttl": nb_record.ttl,
                "values": [],
            }
            rdata = dns.rdata.from_text("IN", nb_record.type, nb_record.value)
            match rdata.rdtype.name:
                case "A" | "AAAA":
                    value = rdata.address

                case "CNAME" | "DNAME" | "NS" | "PTR":
                    value = rdata.target.to_text()

                case "CAA":
                    value = {
                        "flags": rdata.flags,
                        "tag": rdata.tag,
                        "value": rdata.value,
                    }

                case "LOC":
                    value = {
                        "lat_direction": "N" if rdata.latitude[4] >= 0 else "S",
                        "lat_degrees": rdata.latitude[0],
                        "lat_minutes": rdata.latitude[1],
                        "lat_seconds": rdata.latitude[2] + rdata.latitude[3] / 1000,
                        "long_direction": "W" if rdata.latitude[4] >= 0 else "E",
                        "long_degrees": rdata.longitude[0],
                        "long_minutes": rdata.longitude[1],
                        "long_seconds": rdata.longitude[2] + rdata.longitude[3] / 1000,
                        "altitude": rdata.altitude / 100,
                        "size": rdata.size / 100,
                        "precision_horz": rdata.horizontal_precision / 100,
                        "precision_vert": rdata.veritical_precision / 100,
                    }

                case "MX":
                    value = {
                        "preference": rdata.preference,
                        "exchange": rdata.exchange.to_text(),
                    }

                case "NAPTR":
                    value = {
                        "order": rdata.order,
                        "preference": rdata.preference,
                        "flags": rdata.flags,
                        "service": rdata.service,
                        "regexp": rdata.regexp,
                        "replacement": rdata.replacement.to_text(),
                    }

                case "SSHFP":
                    value = {
                        "algorithm": rdata.algorithm,
                        "fingerprint_type": rdata.fp_type,
                        "fingerprint": rdata.fingerprint,
                    }

                case "SOA":
                    self.log.debug("SOA")
                    continue

                case "SPF" | "TXT":
                    value = nb_record.value

                case "SRV":
                    value = {
                        "priority": rdata.priority,
                        "weight": rdata.weight,
                        "port": rdata.port,
                        "target": rdata.target.to_text(),
                    }

                case _:
                    raise ValueError

            if (name, nb_record.type) not in records:
                records[(name, nb_record.type)] = data
            records[(name, nb_record.type)]["values"].append(value)

        for data in records.values():
            if len(data["values"]) == 1:
                data["value"] = data.pop("values")[0]
            pprint(data)
            record = octodns.record.Record.new(
                zone=zone,
                name=data["name"],
                data=data,
                source=self,
                lenient=lenient,
            )
            zone.add_record(record, lenient=lenient)

    def _apply(self, plan: octodns.provider.plan.Plan):
        """Apply the changes to the NetBox DNS zone."""
        self.log.debug(
            f"_apply: zone={plan.desired.name}, len(changes)={len(plan.changes)}"
        )

        nb_zone = self._get_nb_zone(plan.desired.name)

        for change in plan.changes:
            match change:

                case octodns.record.Create():
                    name = change.new.name
                    if name == "":
                        name = "@"

                    match change.new:
                        case octodns.record.ValueMixin():
                            new = {repr(change.new.value)[1:-1]}
                        case octodns.record.ValuesMixin():
                            new = set(map(lambda v: repr(v)[1:-1], change.new.values))
                        case _:
                            raise ValueError

                    for value in new:
                        nb_record = self._api.plugins.netbox_dns.records.create(
                            zone=nb_zone.id,
                            name=name,
                            type=change.new._type,
                            ttl=change.new.ttl,
                            value=value,
                            disable_ptr=True,
                        )
                        self.log.debug(f"{nb_record!r}")

                case octodns.record.Delete():
                    name = change.existing.name
                    if name == "":
                        name = "@"

                    nb_records = self._api.plugins.netbox_dns.records.filter(
                        zone_id=nb_zone.id,
                        name=change.existing.name,
                        type=change.existing._type,
                    )

                    match change.existing:
                        case octodns.record.ValueMixin():
                            existing = {repr(change.existing.value)[1:-1]}
                        case octodns.record.ValuesMixin():
                            existing = set(
                                map(lambda v: repr(v)[1:-1], change.existing.values)
                            )
                        case _:
                            raise ValueError

                    for nb_record in nb_records:
                        for value in existing:
                            if nb_record.value == value:
                                self.log.debug(
                                    f"{nb_record.id} {nb_record.name} {nb_record.type} {nb_record.value} {value}"
                                )
                                self.log.debug(
                                    f"{nb_record.url} {nb_record.endpoint.url}"
                                )
                                nb_record.delete()

                case octodns.record.Update():

                    name = change.existing.name
                    if name == "":
                        name = "@"

                    nb_records = self._api.plugins.netbox_dns.records.filter(
                        zone_id=nb_zone.id,
                        name=name,
                        type=change.existing._type,
                    )

                    match change.existing:
                        case octodns.record.ValueMixin():
                            existing = {repr(change.existing.value)[1:-1]}
                        case octodns.record.ValuesMixin():
                            existing = set(
                                map(lambda v: repr(v)[1:-1], change.existing.values)
                            )
                        case _:
                            raise ValueError

                    match change.new:
                        case octodns.record.ValueMixin():
                            new = {repr(change.new.value)[1:-1]}
                        case octodns.record.ValuesMixin():
                            new = set(map(lambda v: repr(v)[1:-1], change.new.values))
                        case _:
                            raise ValueError

                    delete = existing.difference(new)
                    update = existing.intersection(new)
                    create = new.difference(existing)

                    for nb_record in nb_records:
                        if nb_record.value in delete:
                            nb_record.delete()
                        if nb_record.value in update:
                            nb_record.ttl = change.new.ttl
                            nb_record.save()

                    for value in create:
                        nb_record = self._api.plugins.netbox_dns.records.create(
                            zone=nb_zone.id,
                            name=name,
                            type=change.new._type,
                            ttl=change.new.ttl,
                            value=value,
                            disable_ptr=True,
                        )
