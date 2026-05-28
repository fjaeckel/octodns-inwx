import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, call

from octodns.provider import ProviderException
from octodns.record import Record
from octodns.record.change import Create, Delete, Update
from octodns.zone import Zone

from octodns_inwx import INWXProvider
from octodns_inwx import provider as provider_module
from octodns_inwx.provider import INWXClient


class FakeClient:
    def __init__(self, records=None):
        self.records = records or []
        self.created = []
        self.deleted = []
        self.logout_calls = 0

    def list_records(self, domain):
        return list(self.records)

    def create_record(self, domain, payload):
        self.created.append((domain, payload))

    def delete_record(self, record_id):
        self.deleted.append(record_id)

    def logout(self):
        self.logout_calls += 1


class INWXProviderTest(unittest.TestCase):
    def test_constructor_requires_credentials_without_client(self):
        with self.assertRaises(ProviderException):
            INWXProvider("inwx")
        with self.assertRaises(ProviderException):
            INWXProvider("inwx", username="u")
        with self.assertRaises(ProviderException):
            INWXProvider("inwx", api_password="p")

    def test_populate_loads_supported_records(self):
        client = FakeClient(
            records=[
                {
                    "id": 1,
                    "name": "www",
                    "type": "A",
                    "content": "192.0.2.10",
                    "ttl": 300,
                },
                {
                    "id": 2,
                    "name": "@",
                    "type": "MX",
                    "content": "mx1.example.com",
                    "ttl": 300,
                    "prio": 10,
                },
                {
                    "id": 3,
                    "name": "www",
                    "type": "TXT",
                    "content": '"v=spf1 -all"',
                    "ttl": 300,
                },
                {
                    "id": 4,
                    "name": "_sip._tcp",
                    "type": "SRV",
                    "content": "10 443 sip.example.com.",
                    "ttl": 300,
                    "prio": 5,
                },
                {
                    "id": 5,
                    "name": "@",
                    "type": "CAA",
                    "content": '0 issue "letsencrypt.org"',
                    "ttl": 300,
                },
                {
                    "id": 6,
                    "name": "www",
                    "type": "UNKNOWN",
                    "content": "ignored",
                    "ttl": 300,
                },
            ]
        )
        provider = INWXProvider("inwx", client=client)
        zone = Zone("example.com.", [])

        exists = provider.populate(zone)

        self.assertTrue(exists)
        records = {(r.name, r._type): r for r in zone.records}
        self.assertEqual("192.0.2.10", records[("www", "A")].values[0])
        self.assertEqual("v=spf1 -all", records[("www", "TXT")].values[0])
        self.assertEqual(10, records[("", "MX")].values[0].preference)
        self.assertEqual("mx1.example.com.", records[("", "MX")].values[0].exchange)
        self.assertEqual(5, records[("_sip._tcp", "SRV")].values[0].priority)
        self.assertEqual(443, records[("_sip._tcp", "SRV")].values[0].port)
        self.assertEqual("sip.example.com.", records[("_sip._tcp", "SRV")].values[0].target)
        self.assertEqual("issue", records[("", "CAA")].values[0].tag)
        self.assertEqual("letsencrypt.org", records[("", "CAA")].values[0].value)
        self.assertNotIn(("www", "UNKNOWN"), records)

    def test_populate_handles_cname_ns_and_aaaa(self):
        client = FakeClient(
            records=[
                {"id": 1, "name": "alias", "type": "CNAME", "content": "target.example.com.", "ttl": 600},
                {"id": 2, "name": "sub", "type": "NS", "content": "ns1.example.com.", "ttl": 600},
                {"id": 3, "name": "sub", "type": "NS", "content": "ns2.example.com.", "ttl": 600},
                {"id": 4, "name": "ipv6", "type": "AAAA", "content": "2001:db8::1", "ttl": 600},
            ]
        )
        provider = INWXProvider("inwx", client=client)
        zone = Zone("example.com.", [])
        provider.populate(zone)
        records = {(r.name, r._type): r for r in zone.records}
        self.assertEqual("target.example.com.", records[("alias", "CNAME")].value)
        self.assertEqual(
            sorted(["ns1.example.com.", "ns2.example.com."]),
            sorted(records[("sub", "NS")].values),
        )
        self.assertEqual("2001:db8::1", records[("ipv6", "AAAA")].values[0])

    def test_populate_uses_default_ttl_when_missing(self):
        client = FakeClient(
            records=[{"id": 1, "name": "www", "type": "A", "content": "192.0.2.10"}]
        )
        provider = INWXProvider("inwx", client=client)
        zone = Zone("example.com.", [])
        provider.populate(zone)
        records = {(r.name, r._type): r for r in zone.records}
        self.assertEqual(INWXProvider.DEFAULT_TTL, records[("www", "A")].ttl)

    def test_populate_escapes_txt_semicolons(self):
        client = FakeClient(
            records=[
                {
                    "id": 1,
                    "name": "_dmarc",
                    "type": "TXT",
                    "content": "v=DMARC1; p=quarantine; adkim=r; aspf=r; sp=quarantine",
                    "ttl": 300,
                }
            ]
        )
        provider = INWXProvider("inwx", client=client)
        zone = Zone("example.com.", [])

        provider.populate(zone)

        records = {(r.name, r._type): r for r in zone.records}
        self.assertEqual(
            [r"v=DMARC1\; p=quarantine\; adkim=r\; aspf=r\; sp=quarantine"],
            records[("_dmarc", "TXT")].values,
        )

    def test_populate_full_qualified_names_are_stripped(self):
        client = FakeClient(
            records=[
                {"id": 1, "name": "www.example.com", "type": "A", "content": "192.0.2.10", "ttl": 300},
                {"id": 2, "name": "@", "type": "A", "content": "192.0.2.20", "ttl": 300},
            ]
        )
        provider = INWXProvider("inwx", client=client)
        zone = Zone("example.com.", [])
        provider.populate(zone)
        records = {(r.name, r._type): r for r in zone.records}
        self.assertIn(("www", "A"), records)
        self.assertIn(("", "A"), records)

    def test_populate_bare_domain_name_treated_as_apex(self):
        client = FakeClient(
            records=[
                {"id": 1, "name": "example.com", "type": "MX", "content": "mail.example.com.", "ttl": 3600, "prio": 10},
                {"id": 2, "name": "example.com", "type": "NS", "content": "ns1.example.com.", "ttl": 86400},
                {"id": 3, "name": "example.com", "type": "TXT", "content": "v=spf1 mx ~all", "ttl": 3600},
            ]
        )
        provider = INWXProvider("inwx", client=client)
        zone = Zone("example.com.", [])
        provider.populate(zone)
        records = {(r.name, r._type): r for r in zone.records}
        self.assertIn(("", "MX"), records)
        self.assertIn(("", "NS"), records)
        self.assertIn(("", "TXT"), records)
        self.assertNotIn(("example.com", "MX"), records)
        self.assertNotIn(("example.com", "NS"), records)
        self.assertNotIn(("example.com", "TXT"), records)

    def test_populate_adds_trailing_dot_to_fqdn_targets(self):
        # INWX strips trailing dots from FQDN-valued fields on storage; the
        # provider must add them back so octoDNS sees canonical FQDNs.
        client = FakeClient(
            records=[
                {"id": 1, "name": "alias", "type": "CNAME", "content": "target.example.com", "ttl": 600},
                {"id": 2, "name": "@", "type": "MX", "content": "mx.example.com", "ttl": 3600, "prio": 10},
                {"id": 3, "name": "sub", "type": "NS", "content": "ns1.example.com", "ttl": 86400},
                {"id": 4, "name": "_sip._tcp", "type": "SRV", "content": "10 443 sip.example.com", "ttl": 300, "prio": 5},
            ]
        )
        provider = INWXProvider("inwx", client=client)
        zone = Zone("example.com.", [])
        provider.populate(zone)
        records = {(r.name, r._type): r for r in zone.records}
        self.assertEqual("target.example.com.", records[("alias", "CNAME")].value)
        self.assertEqual("mx.example.com.", records[("", "MX")].values[0].exchange)
        self.assertEqual(["ns1.example.com."], records[("sub", "NS")].values)
        self.assertEqual("sip.example.com.", records[("_sip._tcp", "SRV")].values[0].target)

    def test_populate_raises_on_invalid_srv(self):
        client = FakeClient(
            records=[{"id": 1, "name": "_x._tcp", "type": "SRV", "content": "bogus", "ttl": 300}]
        )
        provider = INWXProvider("inwx", client=client)
        zone = Zone("example.com.", [])
        with self.assertRaises(ProviderException):
            provider.populate(zone)

    def test_populate_raises_on_invalid_caa(self):
        client = FakeClient(
            records=[{"id": 1, "name": "@", "type": "CAA", "content": "bogus", "ttl": 300}]
        )
        provider = INWXProvider("inwx", client=client)
        zone = Zone("example.com.", [])
        with self.assertRaises(ProviderException):
            provider.populate(zone)

    def test_apply_update_recreates_records(self):
        client = FakeClient(
            records=[
                {
                    "id": 10,
                    "name": "www",
                    "type": "A",
                    "content": "192.0.2.10",
                    "ttl": 300,
                }
            ]
        )
        provider = INWXProvider("inwx", client=client)
        zone = Zone("example.com.", [])
        existing = Record.new(
            zone, "www", {"ttl": 300, "type": "A", "value": "192.0.2.10"}
        )
        new = Record.new(
            zone, "www", {"ttl": 300, "type": "A", "value": "192.0.2.11"}
        )
        plan = SimpleNamespace(desired=zone, changes=[Update(existing, new)])

        provider._apply(plan)

        self.assertEqual([10], client.deleted)
        self.assertEqual(
            [("example.com", {"name": "www", "type": "A", "content": "192.0.2.11", "ttl": 300})],
            client.created,
        )

    def test_apply_create_root_record_uses_at_name(self):
        client = FakeClient()
        provider = INWXProvider("inwx", client=client)
        zone = Zone("example.com.", [])
        record = Record.new(
            zone, "", {"ttl": 300, "type": "TXT", "value": "hello world"}
        )
        plan = SimpleNamespace(desired=zone, changes=[Create(record)])

        provider._apply(plan)

        self.assertEqual(
            [("example.com", {"name": "@", "type": "TXT", "content": "hello world", "ttl": 300})],
            client.created,
        )

    def test_apply_create_txt_unescapes_semicolons(self):
        client = FakeClient()
        provider = INWXProvider("inwx", client=client)
        zone = Zone("example.com.", [])
        record = Record.new(
            zone,
            "_dmarc",
            {
                "ttl": 300,
                "type": "TXT",
                "value": r"v=DMARC1\; p=quarantine\; adkim=r\; aspf=r\; sp=quarantine",
            },
        )
        plan = SimpleNamespace(desired=zone, changes=[Create(record)])

        provider._apply(plan)

        self.assertEqual(
            [
                (
                    "example.com",
                    {
                        "name": "_dmarc",
                        "type": "TXT",
                        "content": "v=DMARC1; p=quarantine; adkim=r; aspf=r; sp=quarantine",
                        "ttl": 300,
                    },
                )
            ],
            client.created,
        )

    def test_apply_delete_removes_all_matching_rows(self):
        client = FakeClient(
            records=[
                {"id": 1, "name": "www", "type": "A", "content": "192.0.2.10", "ttl": 300},
                {"id": 2, "name": "www", "type": "A", "content": "192.0.2.11", "ttl": 300},
            ]
        )
        provider = INWXProvider("inwx", client=client)
        zone = Zone("example.com.", [])
        existing = Record.new(
            zone, "www", {"ttl": 300, "type": "A", "values": ["192.0.2.10", "192.0.2.11"]}
        )
        plan = SimpleNamespace(desired=zone, changes=[Delete(existing)])

        provider._apply(plan)

        self.assertEqual(sorted([1, 2]), sorted(client.deleted))
        self.assertEqual([], client.created)

    def test_apply_create_mx_includes_priority(self):
        client = FakeClient()
        provider = INWXProvider("inwx", client=client)
        zone = Zone("example.com.", [])
        record = Record.new(
            zone,
            "",
            {
                "ttl": 300,
                "type": "MX",
                "values": [
                    {"preference": 10, "exchange": "mx1.example.com."},
                    {"preference": 20, "exchange": "mx2.example.com."},
                ],
            },
        )
        plan = SimpleNamespace(desired=zone, changes=[Create(record)])
        provider._apply(plan)
        payloads = [c[1] for c in client.created]
        self.assertEqual(2, len(payloads))
        self.assertEqual(
            {("mx1.example.com.", 10), ("mx2.example.com.", 20)},
            {(p["content"], p["prio"]) for p in payloads},
        )

    def test_apply_create_srv_serializes_content(self):
        client = FakeClient()
        provider = INWXProvider("inwx", client=client)
        zone = Zone("example.com.", [])
        record = Record.new(
            zone,
            "_sip._tcp",
            {
                "ttl": 300,
                "type": "SRV",
                "values": [
                    {"priority": 5, "weight": 10, "port": 443, "target": "sip.example.com."}
                ],
            },
        )
        plan = SimpleNamespace(desired=zone, changes=[Create(record)])
        provider._apply(plan)
        self.assertEqual(1, len(client.created))
        payload = client.created[0][1]
        self.assertEqual("10 443 sip.example.com.", payload["content"])
        self.assertEqual(5, payload["prio"])

    def test_apply_create_caa_quotes_value(self):
        client = FakeClient()
        provider = INWXProvider("inwx", client=client)
        zone = Zone("example.com.", [])
        record = Record.new(
            zone,
            "",
            {
                "ttl": 300,
                "type": "CAA",
                "value": {"flags": 0, "tag": "issue", "value": "letsencrypt.org"},
            },
        )
        plan = SimpleNamespace(desired=zone, changes=[Create(record)])
        provider._apply(plan)
        payload = client.created[0][1]
        self.assertEqual('0 issue "letsencrypt.org"', payload["content"])

    def test_apply_update_txt_matches_quoted_current_content(self):
        client = FakeClient(
            records=[
                {
                    "id": 42,
                    "name": "@",
                    "type": "TXT",
                    "content": '"old value"',
                    "ttl": 300,
                }
            ]
        )
        provider = INWXProvider("inwx", client=client)
        zone = Zone("example.com.", [])
        existing = Record.new(zone, "", {"ttl": 300, "type": "TXT", "value": "old value"})
        new = Record.new(zone, "", {"ttl": 300, "type": "TXT", "value": "new value"})
        plan = SimpleNamespace(desired=zone, changes=[Update(existing, new)])

        provider._apply(plan)

        self.assertEqual([42], client.deleted)
        self.assertEqual(
            [("example.com", {"name": "@", "type": "TXT", "content": "new value", "ttl": 300})],
            client.created,
        )

    def test_apply_unsupported_change_raises(self):
        provider = INWXProvider("inwx", client=FakeClient())
        zone = Zone("example.com.", [])
        plan = SimpleNamespace(desired=zone, changes=[object()])
        with self.assertRaises(ProviderException):
            provider._apply(plan)

    def test_apply_update_cname_matches_dotless_current_target(self):
        # The existing INWX row stores the target without trailing dot; the
        # update should still locate and delete the correct row by id.
        client = FakeClient(
            records=[
                {
                    "id": 77,
                    "name": "alias",
                    "type": "CNAME",
                    "content": "old.example.com",
                    "ttl": 600,
                }
            ]
        )
        provider = INWXProvider("inwx", client=client)
        zone = Zone("example.com.", [])
        existing = Record.new(
            zone, "alias", {"ttl": 600, "type": "CNAME", "value": "old.example.com."}
        )
        new = Record.new(
            zone, "alias", {"ttl": 600, "type": "CNAME", "value": "new.example.com."}
        )
        plan = SimpleNamespace(desired=zone, changes=[Update(existing, new)])

        provider._apply(plan)

        self.assertEqual([77], client.deleted)
        self.assertEqual(
            [
                (
                    "example.com",
                    {
                        "name": "alias",
                        "type": "CNAME",
                        "content": "new.example.com.",
                        "ttl": 600,
                    },
                )
            ],
            client.created,
        )


class INWXClientTest(unittest.TestCase):
    def _patched_client(self, login_response):
        api_client_mock = MagicMock()
        inner = MagicMock()
        inner.login.return_value = login_response
        api_client_mock.return_value = inner
        original = provider_module.ApiClient
        provider_module.ApiClient = api_client_mock
        self.addCleanup(setattr, provider_module, "ApiClient", original)
        return api_client_mock, inner

    def test_login_failure_raises(self):
        self._patched_client({"code": 2000, "msg": "bad credentials"})
        with self.assertRaises(ProviderException):
            INWXClient("user", "pass")

    def test_list_create_delete_success(self):
        api_client_mock, inner = self._patched_client({"code": 1000})
        inner.call_api.side_effect = [
            {
                "code": 1000,
                "resData": {"record": [{"id": 1, "name": "@", "type": "A", "content": "1.2.3.4"}]},
            },
            {"code": 1000},
            {"code": 1000},
        ]

        client = INWXClient("user", "pass")
        rows = client.list_records("example.com")
        self.assertEqual(1, len(rows))
        client.create_record(
            "example.com", {"name": "@", "type": "A", "content": "1.2.3.4", "ttl": 300}
        )
        client.delete_record(1)
        api_client_mock.assert_called_once_with(
            api_url=provider_module.DEFAULT_ENDPOINT, debug_mode=False
        )
        inner.login.assert_called_once_with("user", "pass")
        self.assertEqual(
            [
                call(api_method="nameserver.info", method_params={"domain": "example.com"}),
                call(
                    api_method="nameserver.createRecord",
                    method_params={
                        "domain": "example.com",
                        "name": "@",
                        "type": "A",
                        "content": "1.2.3.4",
                        "ttl": 300,
                    },
                ),
                call(api_method="nameserver.deleteRecord", method_params={"id": "1"}),
            ],
            inner.call_api.call_args_list,
        )

    def test_api_failure_in_list_raises(self):
        _, inner = self._patched_client({"code": 1000})
        inner.call_api.return_value = {"code": 2400, "msg": "boom"}
        client = INWXClient("user", "pass")
        with self.assertRaises(ProviderException):
            client.list_records("example.com")

    def test_logout_allows_future_relogin(self):
        _, inner = self._patched_client({"code": 1000})
        inner.call_api.return_value = {"code": 1000, "resData": {"record": []}}
        inner.logout.return_value = {
            "code": 1500,
            "msg": "Command completed successfully; ending session",
        }

        client = INWXClient("user", "pass")
        client.logout()
        self.assertFalse(client._logged_in)
        client.list_records("example.com")

        inner.logout.assert_called_once_with()
        self.assertEqual(2, inner.login.call_count)

    def test_logout_failure_raises(self):
        _, inner = self._patched_client({"code": 1000})
        inner.logout.return_value = {"code": 2000, "msg": "logout failed"}

        client = INWXClient("user", "pass")

        with self.assertRaises(ProviderException):
            client.logout()


class INWXProviderTlsaTest(unittest.TestCase):
    _HEX = "3605d0184c472ef86272aaa17a31f3f5c57c43552ff2f79540dd4ba03a578772"

    def test_populate_loads_tlsa_record(self):
        # INWX may return the cert association hex with whitespace and/or in
        # upper case; both should normalize to the canonical lower-case form.
        client = FakeClient(
            records=[
                {
                    "id": 1,
                    "name": "_25._tcp.mail",
                    "type": "TLSA",
                    "content": (
                        "3 1 1 "
                        "3605D0184C472EF86272AAA17A31F3F5C57C43552FF2F79540DD4BA0"
                        " 3A578772"
                    ),
                    "ttl": 3600,
                }
            ]
        )
        provider = INWXProvider("inwx", client=client)
        zone = Zone("example.com.", [])

        provider.populate(zone)

        record = next(iter(zone.records))
        self.assertEqual("TLSA", record._type)
        self.assertEqual("_25._tcp.mail", record.name)
        value = record.values[0]
        self.assertEqual(3, value.certificate_usage)
        self.assertEqual(1, value.selector)
        self.assertEqual(1, value.matching_type)
        self.assertEqual(self._HEX, value.certificate_association_data)

    def test_invalid_tlsa_content_raises(self):
        client = FakeClient(
            records=[
                {
                    "id": 1,
                    "name": "_25._tcp.mail",
                    "type": "TLSA",
                    "content": "3 1 1",  # missing cert data
                    "ttl": 3600,
                }
            ]
        )
        provider = INWXProvider("inwx", client=client)
        zone = Zone("example.com.", [])

        with self.assertRaises(ProviderException):
            provider.populate(zone)

    def test_apply_create_tlsa(self):
        client = FakeClient()
        provider = INWXProvider("inwx", client=client)
        zone = Zone("example.com.", [])
        record = Record.new(
            zone,
            "_25._tcp.mail",
            {
                "ttl": 3600,
                "type": "TLSA",
                "value": {
                    "certificate_usage": 3,
                    "selector": 1,
                    "matching_type": 1,
                    "certificate_association_data": self._HEX,
                },
            },
        )
        plan = SimpleNamespace(desired=zone, changes=[Create(record)])

        provider._apply(plan)

        self.assertEqual(1, len(client.created))
        domain, payload = client.created[0]
        self.assertEqual("example.com", domain)
        self.assertEqual("_25._tcp.mail", payload["name"])
        self.assertEqual("TLSA", payload["type"])
        self.assertEqual(f"3 1 1 {self._HEX}", payload["content"])
        self.assertEqual(3600, payload["ttl"])

    def test_apply_update_tlsa_matches_whitespace_and_case_variations(self):
        # Existing INWX row returns the cert blob with a wrap space and upper
        # case; the desired value uses the canonical lower-case form. They
        # represent the same record so an Update with identical values should
        # not produce any change (matches the existing row exactly and avoids
        # spurious deletes/creates).
        existing_row = {
            "id": 7,
            "name": "_25._tcp.mail",
            "type": "TLSA",
            "content": (
                "3 1 1 "
                "3605D0184C472EF86272AAA17A31F3F5C57C43552FF2F79540DD4BA0"
                " 3A578772"
            ),
            "ttl": 3600,
        }
        client = FakeClient(records=[existing_row])
        provider = INWXProvider("inwx", client=client)
        zone = Zone("example.com.", [])
        existing = Record.new(
            zone,
            "_25._tcp.mail",
            {
                "ttl": 3600,
                "type": "TLSA",
                "value": {
                    "certificate_usage": 3,
                    "selector": 1,
                    "matching_type": 1,
                    "certificate_association_data": self._HEX,
                },
            },
        )
        # _matches_payload should treat whitespace-wrapped/upper-case hex as
        # equivalent to the canonical form.
        payload = provider._record_to_api_payloads(existing)[0]
        self.assertTrue(provider._matches_payload(existing_row, payload))


class RecordToApiPayloadsMarshalTest(unittest.TestCase):
    """Ensure payload content is xmlrpc-marshalable (plain str, not typed values).

    Regression test for the case where newer octodns versions return typed
    value objects (e.g. ``CnameValue``) that ``xmlrpc.client`` cannot marshal.
    """

    def _assert_marshalable(self, payload):
        import xmlrpc.client

        xmlrpc.client.dumps((payload,))
        self.assertIs(type(payload["content"]), str)

    def test_cname_payload_content_is_plain_str(self):
        provider = INWXProvider("inwx", client=FakeClient())
        zone = Zone("example.com.", [])
        record = Record.new(
            zone,
            "alias",
            {"ttl": 600, "type": "CNAME", "value": "target.example.com."},
        )
        payload = provider._record_to_api_payloads(record)[0]
        self._assert_marshalable(payload)

    def test_a_aaaa_ns_payload_content_is_plain_str(self):
        provider = INWXProvider("inwx", client=FakeClient())
        zone = Zone("example.com.", [])
        for name, data in (
            ("a", {"ttl": 600, "type": "A", "value": "1.2.3.4"}),
            ("aaaa", {"ttl": 600, "type": "AAAA", "value": "::1"}),
            ("ns", {"ttl": 600, "type": "NS", "value": "ns1.example.com."}),
        ):
            record = Record.new(zone, name, data)
            for payload in provider._record_to_api_payloads(record):
                self._assert_marshalable(payload)

    def test_mx_payload_content_is_plain_str(self):
        provider = INWXProvider("inwx", client=FakeClient())
        zone = Zone("example.com.", [])
        record = Record.new(
            zone,
            "mx",
            {
                "ttl": 600,
                "type": "MX",
                "value": {"preference": 10, "exchange": "mail.example.com."},
            },
        )
        for payload in provider._record_to_api_payloads(record):
            self._assert_marshalable(payload)


class ApplyUpdateAgainstFqdnNamesTest(unittest.TestCase):
    """INWX's ``nameserver.info`` returns names as FQDNs while the create
    API takes short names. Make sure Update changes still match (and thus
    delete) the existing row.
    """

    def test_update_deletes_existing_fqdn_named_row(self):
        # Live state as INWX would return it: name is the FQDN, no trailing dot.
        existing_row = {
            "id": 42,
            "name": "host.example.com",
            "type": "A",
            "content": "192.0.2.1",
            "ttl": 3600,
            "prio": 0,
        }
        client = FakeClient(records=[existing_row])
        provider = INWXProvider("inwx", client=client)
        zone = Zone("example.com.", [])
        existing = Record.new(
            zone, "host", {"ttl": 3600, "type": "A", "value": "192.0.2.1"}
        )
        new = Record.new(
            zone, "host", {"ttl": 1800, "type": "A", "value": "192.0.2.2"}
        )
        plan = SimpleNamespace(
            desired=zone, changes=[Update(existing=existing, new=new)]
        )
        provider._apply(plan)
        self.assertEqual([42], client.deleted)
        self.assertEqual(1, len(client.created))
        _, payload = client.created[0]
        self.assertEqual("host", payload["name"])
        self.assertEqual(1800, payload["ttl"])
        self.assertEqual("192.0.2.2", payload["content"])


class DeleteRecordIdMarshalTest(unittest.TestCase):
    """Regression test: INWX record IDs can exceed XML-RPC's 32-bit <int>."""

    def test_delete_record_marshals_64bit_id(self):
        import xmlrpc.client

        big_id = 9876543210123
        _, inner = INWXClientTest()._patched_client({"code": 1000})
        inner.call_api.return_value = {"code": 1000}
        client = INWXClient("user", "pass")
        client.delete_record(big_id)
        params = inner.call_api.call_args.kwargs["method_params"]
        self.assertEqual({"id": str(big_id)}, params)
        # And the params dict must be marshalable end-to-end.
        xmlrpc.client.dumps((params,), "nameserver.deleteRecord")


if __name__ == "__main__":
    unittest.main()
