import logging
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
        self._ensure_success(response, "account.logout")
        self._logged_in = False
        return response


class INWXProvider(BaseProvider):
    SUPPORTS = {"A", "AAAA", "CAA", "CNAME", "MX", "NS", "SRV", "TXT"}
    SUPPORTS_GEO = False
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
        if name in ("", "@"):
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

    def _record_data_from_group(self, record_type, ttl, rows):
        if record_type in {"A", "AAAA", "NS"}:
            return {
                "ttl": ttl,
                "type": record_type,
                "values": [str(row["content"]) for row in rows],
            }

        if record_type == "TXT":
            return {
                "ttl": ttl,
                "type": "TXT",
                "values": [self._normalize_content(row["content"]) for row in rows],
            }

        if record_type == "CNAME":
            return {"ttl": ttl, "type": "CNAME", "value": str(rows[0]["content"])}

        if record_type == "MX":
            values = []
            for row in rows:
                values.append(
                    {
                        "preference": int(row.get("prio", 0)),
                        "exchange": str(row["content"]),
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
                        "target": target,
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

        if record_type in {"A", "AAAA", "NS", "TXT"}:
            return [
                {"name": name, "type": record_type, "content": value, "ttl": ttl}
                for value in record.values
            ]

        if record_type == "CNAME":
            return [{"name": name, "type": "CNAME", "content": record.value, "ttl": ttl}]

        if record_type == "MX":
            payloads = []
            for value in record.values:
                payloads.append(
                    {
                        "name": name,
                        "type": "MX",
                        "content": value.exchange,
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

        raise ProviderException(f"Unsupported record type {record_type}")

    def _matches_payload(self, row, payload):
        if str(row.get("name") or "") != str(payload.get("name") or ""):
            return False
        if str(row.get("type") or "").upper() != str(payload.get("type") or "").upper():
            return False
        if int(row.get("ttl") or 0) != int(payload.get("ttl") or 0):
            return False

        row_prio = row.get("prio")
        payload_prio = payload.get("prio")
        if payload_prio is not None and int(row_prio or 0) != int(payload_prio):
            return False

        return self._normalize_content(row.get("content")) == self._normalize_content(
            payload.get("content")
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
