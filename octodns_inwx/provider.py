import logging
import re
from collections import defaultdict

from octodns.provider import ProviderException
from octodns.provider.base import BaseProvider
from octodns.record import Record
from octodns.record.change import Create, Delete, Update

try:
    from INWX.Domrobot import ApiClient
except ImportError:  # pragma: no cover - exercised when dependency is missing at runtime
    ApiClient = None


API_LIVE_URL = "https://api.domrobot.com"
DEFAULT_ENDPOINT = getattr(ApiClient, "API_LIVE_URL", API_LIVE_URL)


class INWXClient:
    SUCCESS_CODE = 1000
    LOGOUT_SUCCESS_CODES = {SUCCESS_CODE, 1500}

    def __init__(
        self,
        username,
        api_password,
        endpoint=DEFAULT_ENDPOINT,
    ):
        if ApiClient is None:
            raise ProviderException("inwx-domrobot dependency is required")

        self._username = username
        self._api_password = api_password
        self._client = ApiClient(api_url=endpoint, debug_mode=False)
        self._logged_in = False
        self._login()

    def _login(self):
        response = self._client.login(self._username, self._api_password)
        self._ensure_success(response, "account.login")
        self._logged_in = True
        return response

    def _ensure_logged_in(self):
        if not self._logged_in:
            self._login()

    def _ensure_success(self, response, method):
        code = int(response.get("code", 0))
        if code != self.SUCCESS_CODE:
            message = response.get("msg", "unknown INWX API error")
            raise ProviderException(f"{method} failed: {code} {message}")

    def list_records(self, domain):
        self._ensure_logged_in()
        response = self._client.call_api(
            api_method="nameserver.info", method_params={"domain": domain}
        )
        self._ensure_success(response, "nameserver.info")
        return response.get("resData", {}).get("record", []) or []

    def create_record(self, domain, payload):
        self._ensure_logged_in()
        data = {"domain": domain, **payload}
        response = self._client.call_api(
            api_method="nameserver.createRecord", method_params=data
        )
        self._ensure_success(response, "nameserver.createRecord")
        return response

    def delete_record(self, record_id):
        self._ensure_logged_in()
        response = self._client.call_api(
            api_method="nameserver.deleteRecord", method_params={"id": record_id}
        )
        self._ensure_success(response, "nameserver.deleteRecord")
        return response

    def logout(self):
        if not self._logged_in:
            return None
        response = self._client.logout()
        code = int(response.get("code", 0))
        if code not in self.LOGOUT_SUCCESS_CODES:
            self._ensure_success(response, "account.logout")
        self._logged_in = False
        return response


class INWXProvider(BaseProvider):
    SUPPORTS = {"A", "AAAA", "CAA", "CNAME", "MX", "NS", "SRV", "TLSA", "TXT"}
    SUPPORTS_GEO = False
    SUPPORTS_ROOT_NS = True
    DEFAULT_TTL = 3600

    def __init__(
        self,
        id,
        username=None,
        api_password=None,
        endpoint=DEFAULT_ENDPOINT,
        client=None,
        *args,
        **kwargs,
    ):
        self.log = logging.getLogger(f"INWXProvider[{id}]")
        super().__init__(id, *args, **kwargs)
        self._owns_client = client is None
        if client is not None:
            self._client = client
        else:
            if not username or not api_password:
                raise ProviderException(
                    "username and api_password are required when no client is provided"
                )
            self._client = INWXClient(
                username=username, api_password=api_password, endpoint=endpoint
            )

    def _cleanup_client(self):
        if not self._owns_client:
            return
        logout = getattr(self._client, "logout", None)
        if callable(logout):
            logout()

    @staticmethod
    def _domain_for_zone(zone):
        return zone.name[:-1]

    @staticmethod
    def _to_octodns_name(name, domain):
        name = (name or "").rstrip(".")
        if name in ("", "@", domain):
            return ""
        if name.endswith(f".{domain}"):
            return name[: -(len(domain) + 1)]
        return name

    @staticmethod
    def _to_inwx_name(name):
        return "@" if name == "" else name

    @staticmethod
    def _normalize_content(value):
        value = str(value)
        if len(value) > 1 and value[0] == value[-1] == '"':
            return value[1:-1]
        return value

    @staticmethod
    def _ensure_fqdn(value):
        # INWX strips the trailing dot from FQDN-valued fields (CNAME target,
        # MX exchange, SRV target, NS host) on storage. octoDNS requires the
        # canonical form with a trailing dot, so add it back when reading.
        value = str(value)
        if not value:
            return value
        if value.endswith("."):
            return value
        return f"{value}."

    @staticmethod
    def _normalize_tlsa_data(value):
        # INWX (and some zone exports) may wrap the certificate association
        # hex blob across whitespace; octoDNS expects a single contiguous
        # string. Comparisons are case-insensitive so lower-case here for a
        # stable canonical form.
        return "".join(str(value).split()).lower()

    @classmethod
    def _normalize_txt_content(cls, value):
        value = cls._normalize_content(value)
        return re.sub(r"(?<!\\);", r"\\;", value)

    @classmethod
    def _serialize_txt_content(cls, value):
        value = cls._normalize_content(value)
        return value.replace(r"\;", ";")

    def _record_data_from_group(self, record_type, ttl, rows):
        if record_type in {"A", "AAAA"}:
            return {
                "ttl": ttl,
                "type": record_type,
                "values": [str(row["content"]) for row in rows],
            }

        if record_type == "NS":
            return {
                "ttl": ttl,
                "type": "NS",
                "values": [self._ensure_fqdn(row["content"]) for row in rows],
            }

        if record_type == "TXT":
            return {
                "ttl": ttl,
                "type": "TXT",
                "values": [self._normalize_txt_content(row["content"]) for row in rows],
            }

        if record_type == "CNAME":
            return {
                "ttl": ttl,
                "type": "CNAME",
                "value": self._ensure_fqdn(rows[0]["content"]),
            }

        if record_type == "MX":
            values = []
            for row in rows:
                values.append(
                    {
                        "preference": int(row.get("prio", 0)),
                        "exchange": self._ensure_fqdn(row["content"]),
                    }
                )
            values = sorted(values, key=lambda v: (v["preference"], v["exchange"]))
            return {"ttl": ttl, "type": "MX", "values": values}

        if record_type == "SRV":
            values = []
            for row in rows:
                parts = str(row["content"]).split(maxsplit=2)
                if len(parts) != 3:
                    raise ProviderException(
                        f"Invalid SRV content from INWX for {row.get('name', '@')}: {row.get('content')}"
                    )
                weight, port, target = parts
                values.append(
                    {
                        "priority": int(row.get("prio", 0)),
                        "weight": int(weight),
                        "port": int(port),
                        "target": self._ensure_fqdn(target),
                    }
                )
            values = sorted(
                values, key=lambda v: (v["priority"], v["weight"], v["port"], v["target"])
            )
            return {"ttl": ttl, "type": "SRV", "values": values}

        if record_type == "CAA":
            values = []
            for row in rows:
                parts = str(row["content"]).split(maxsplit=2)
                if len(parts) != 3:
                    raise ProviderException(
                        f"Invalid CAA content from INWX for {row.get('name', '@')}: {row.get('content')}"
                    )
                flags, tag, value = parts
                values.append(
                    {
                        "flags": int(flags),
                        "tag": tag,
                        "value": self._normalize_content(value),
                    }
                )
            values = sorted(values, key=lambda v: (v["flags"], v["tag"], v["value"]))
            return {"ttl": ttl, "type": "CAA", "values": values}

        if record_type == "TLSA":
            values = []
            for row in rows:
                parts = str(row["content"]).split(maxsplit=3)
                if len(parts) != 4:
                    raise ProviderException(
                        f"Invalid TLSA content from INWX for {row.get('name', '@')}: {row.get('content')}"
                    )
                usage, selector, matching_type, cert_data = parts
                values.append(
                    {
                        "certificate_usage": int(usage),
                        "selector": int(selector),
                        "matching_type": int(matching_type),
                        "certificate_association_data": self._normalize_tlsa_data(
                            cert_data
                        ),
                    }
                )
            values = sorted(
                values,
                key=lambda v: (
                    v["certificate_usage"],
                    v["selector"],
                    v["matching_type"],
                    v["certificate_association_data"],
                ),
            )
            return {"ttl": ttl, "type": "TLSA", "values": values}

        return None

    def populate(self, zone, target=False, lenient=False):
        domain = self._domain_for_zone(zone)
        try:
            rows = self._client.list_records(domain)
            groups = defaultdict(list)
            for row in rows:
                record_type = str(row.get("type", "")).upper()
                if record_type not in self.SUPPORTS:
                    continue
                name = self._to_octodns_name(row.get("name"), domain)
                ttl = int(row.get("ttl") or self.DEFAULT_TTL)
                groups[(name, record_type, ttl)].append(row)

            for (name, record_type, ttl), grouped_rows in sorted(groups.items()):
                data = self._record_data_from_group(record_type, ttl, grouped_rows)
                if not data:
                    continue
                record = Record.new(zone, name, data, source=self, lenient=lenient)
                zone.add_record(record, lenient=lenient)

            return True
        finally:
            self._cleanup_client()

    def _record_to_api_payloads(self, record):
        name = self._to_inwx_name(record.name)
        record_type = record._type
        ttl = int(record.ttl)

        if record_type in {"A", "AAAA", "NS"}:
            return [
                {"name": name, "type": record_type, "content": str(value), "ttl": ttl}
                for value in record.values
            ]

        if record_type == "TXT":
            return [
                {
                    "name": name,
                    "type": "TXT",
                    "content": self._serialize_txt_content(value),
                    "ttl": ttl,
                }
                for value in record.values
            ]

        if record_type == "CNAME":
            return [
                {
                    "name": name,
                    "type": "CNAME",
                    "content": str(record.value),
                    "ttl": ttl,
                }
            ]

        if record_type == "MX":
            payloads = []
            for value in record.values:
                payloads.append(
                    {
                        "name": name,
                        "type": "MX",
                        "content": str(value.exchange),
                        "ttl": ttl,
                        "prio": int(value.preference),
                    }
                )
            return payloads

        if record_type == "SRV":
            payloads = []
            for value in record.values:
                payloads.append(
                    {
                        "name": name,
                        "type": "SRV",
                        "content": f"{value.weight} {value.port} {value.target}",
                        "ttl": ttl,
                        "prio": int(value.priority),
                    }
                )
            return payloads

        if record_type == "CAA":
            payloads = []
            for value in record.values:
                payloads.append(
                    {
                        "name": name,
                        "type": "CAA",
                        "content": f'{value.flags} {value.tag} "{value.value}"',
                        "ttl": ttl,
                    }
                )
            return payloads

        if record_type == "TLSA":
            payloads = []
            for value in record.values:
                cert_data = self._normalize_tlsa_data(
                    value.certificate_association_data
                )
                payloads.append(
                    {
                        "name": name,
                        "type": "TLSA",
                        "content": (
                            f"{value.certificate_usage} {value.selector} "
                            f"{value.matching_type} {cert_data}"
                        ),
                        "ttl": ttl,
                    }
                )
            return payloads

        raise ProviderException(f"Unsupported record type {record_type}")

    def _matches_payload(self, row, payload):
        if str(row.get("name") or "") != str(payload.get("name") or ""):
            return False
        record_type = str(payload.get("type") or "").upper()
        if str(row.get("type") or "").upper() != record_type:
            return False
        if int(row.get("ttl") or 0) != int(payload.get("ttl") or 0):
            return False

        row_prio = row.get("prio")
        payload_prio = payload.get("prio")
        if payload_prio is not None and int(row_prio or 0) != int(payload_prio):
            return False

        row_content = self._normalize_content(row.get("content"))
        payload_content = self._normalize_content(payload.get("content"))
        # INWX returns FQDN-valued fields without the trailing dot it stripped on
        # write — compare in a dot-insensitive way for those types.
        if record_type in {"CNAME", "MX", "NS"}:
            row_content = row_content.rstrip(".")
            payload_content = payload_content.rstrip(".")
        elif record_type == "SRV":
            # SRV content is "<weight> <port> <target>"; only the target may
            # differ by trailing dot.
            row_content = row_content.rstrip(".")
            payload_content = payload_content.rstrip(".")
        elif record_type == "TLSA":
            row_content = self._canonicalize_tlsa_content(row_content)
            payload_content = self._canonicalize_tlsa_content(payload_content)
        return row_content == payload_content

    @classmethod
    def _canonicalize_tlsa_content(cls, content):
        parts = str(content).split(maxsplit=3)
        if len(parts) != 4:
            return content
        usage, selector, matching_type, cert_data = parts
        return (
            f"{int(usage)} {int(selector)} {int(matching_type)} "
            f"{cls._normalize_tlsa_data(cert_data)}"
        )

    def _delete_record_payloads(self, current_rows, payloads):
        for payload in payloads:
            fallback_row = None
            match_index = None
            for index, row in enumerate(current_rows):
                if (
                    str(row.get("name") or "") == str(payload.get("name") or "")
                    and str(row.get("type") or "").upper()
                    == str(payload.get("type") or "").upper()
                ):
                    fallback_row = row
                    if self._matches_payload(row, payload):
                        match_index = index
                        break
            if match_index is not None:
                row = current_rows.pop(match_index)
            elif fallback_row is not None:
                current_rows.remove(fallback_row)
                row = fallback_row
            else:
                continue
            self._client.delete_record(int(row["id"]))

    def _apply(self, plan):
        domain = self._domain_for_zone(plan.desired)
        try:
            current_rows = self._client.list_records(domain)

            for change in plan.changes:
                if isinstance(change, Delete):
                    payloads = self._record_to_api_payloads(change.existing)
                    self._delete_record_payloads(current_rows, payloads)
                elif isinstance(change, Create):
                    for payload in self._record_to_api_payloads(change.new):
                        self._client.create_record(domain, payload)
                elif isinstance(change, Update):
                    existing_payloads = self._record_to_api_payloads(change.existing)
                    self._delete_record_payloads(current_rows, existing_payloads)
                    for payload in self._record_to_api_payloads(change.new):
                        self._client.create_record(domain, payload)
                else:
                    raise ProviderException(
                        f"Unsupported change type {change.__class__.__name__}"
                    )
        finally:
            self._cleanup_client()
