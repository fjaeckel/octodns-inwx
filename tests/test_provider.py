import unittest
from types import SimpleNamespace

from octodns.record import Record
from octodns.record.change import Create, Update
from octodns.zone import Zone

from octodns_inwx import INWXProvider


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
                    "content": "v=spf1 -all",
                    "ttl": 300,
                },
                {
                    "id": 4,
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
        self.assertNotIn(("www", "UNKNOWN"), records)

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


if __name__ == "__main__":
    unittest.main()
