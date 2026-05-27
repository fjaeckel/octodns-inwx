import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

from octodns.provider import ProviderException
from octodns.record import Record
from octodns.record.change import Create, Delete, Update
from octodns.zone import Zone

from octodns_inwx import INWXProvider
from octodns_inwx.provider import INWXClient


class FakeClient:
    def __init__(self, records=None):
        self.records = records or []
        self.created = []
        self.deleted = []

    def list_records(self, domain):
        return list(self.records)

    def create_record(self, domain, payload):
        self.created.append((domain, payload))

    def delete_record(self, record_id):
        self.deleted.append(record_id)


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
        self.assertEqual("mx1.example.com", records[("", "MX")].values[0].exchange)
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


class INWXClientTest(unittest.TestCase):
    def _patched_client(self, login_response):
        domrobot_mock = MagicMock()
        inner = MagicMock()
        inner.account.login.return_value = login_response
        domrobot_mock.DOMRobot.return_value = inner
        import sys
        sys.modules["domrobot"] = domrobot_mock
        return inner

    def test_login_failure_raises(self):
        self._patched_client({"code": 2000, "msg": "bad credentials"})
        with self.assertRaises(ProviderException):
            INWXClient("user", "pass")

    def test_list_create_delete_success(self):
        inner = self._patched_client({"code": 1000})
        inner.nameserver.info.return_value = {
            "code": 1000,
            "resData": {"record": [{"id": 1, "name": "@", "type": "A", "content": "1.2.3.4"}]},
        }
        inner.nameserver.createrecord.return_value = {"code": 1000}
        inner.nameserver.deleterecord.return_value = {"code": 1000}

        client = INWXClient("user", "pass")
        rows = client.list_records("example.com")
        self.assertEqual(1, len(rows))
        client.create_record("example.com", {"name": "@", "type": "A", "content": "1.2.3.4", "ttl": 300})
        client.delete_record(1)
        inner.nameserver.createrecord.assert_called_once()
        inner.nameserver.deleterecord.assert_called_once_with({"id": 1})

    def test_api_failure_in_list_raises(self):
        inner = self._patched_client({"code": 1000})
        inner.nameserver.info.return_value = {"code": 2400, "msg": "boom"}
        client = INWXClient("user", "pass")
        with self.assertRaises(ProviderException):
            client.list_records("example.com")


if __name__ == "__main__":
    unittest.main()
