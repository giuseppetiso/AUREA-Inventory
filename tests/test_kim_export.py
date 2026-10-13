import ast
import importlib.util
import ipaddress
import re
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
COMPONENT = ROOT / 'custom_components/aurea_inventory'
spec = importlib.util.spec_from_file_location('kim_report', COMPONENT / 'kim_report.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
NAMES = {'SAFE_ATTRS', 'BLOCKED', 'SENSITIVE_CONFIG_KEYS', 'SENSITIVE_TEXT_PATTERNS', 'IPV6_CANDIDATE_PATTERN',
         '_is_sensitive_key', '_sanitize_text', '_sanitize_config', '_safe_attrs'}
tree = ast.parse((COMPONENT / '__init__.py').read_text())
selected = [node for node in tree.body if getattr(node, 'name', None) in NAMES or
            isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in NAMES for t in node.targets)]
ns = {'re': re, 'ipaddress': ipaddress, 'Any': Any, 'select_kim_attributes': module.select_kim_attributes}
exec(compile(ast.Module(body=selected, type_ignores=[]), str(COMPONENT / '__init__.py'), 'exec'), ns)


class ExportTest(unittest.TestCase):
    def export(self, sensor, attrs):
        return ns['_safe_attrs'](attrs, sensor)

    def test_voice_metrics_and_provider_names_survive(self):
        data = {'timings_ms': {'listen_ms': 1800, 'total_ms': 4100}, 'providers': {'stt': 'stt.faster_whisper'},
                'turn_id': 'abc123', 'first_audio_or_failure': True}
        self.assertEqual(data, self.export('sensor.kim_voice', data))

    def test_all_records_preserve_identity_and_resolution(self):
        data = {'report_id': 'coherent-report', 'page': 0, 'records': [
            {'id': f'fault:{i}', 'severity': 2, 'evidence': 'Provider unavailable', 'first_seen': 100,
             'last_seen': 200, 'occurrences': 4, 'state': 'resolved', 'resolved_at': 300, 'resolution': 'ok'} for i in range(32)]}
        self.assertEqual(data, self.export('sensor.kim_incidents_00', data))

    def test_module_results_and_reset_metadata_survive(self):
        data = {'modules': [{'module': 'Autotest', 'state': 'ok', 'evidence': '8 tests', 'checked_at': 100}],
                'reset_count': 2, 'reset_at_ms': 100}
        self.assertEqual(data, self.export('sensor.kim_health', data))

    def test_non_kim_sensors_keep_original_allowlist(self):
        data = {'friendly_name': 'Other', 'timings_ms': {'total_ms': 500}, 'records': [{'evidence': 'private'}]}
        self.assertEqual({'friendly_name': 'Other'}, self.export('sensor.other', data))
        self.assertEqual({'friendly_name': 'Other'}, self.export('sensor.kim_incidents_16', data))

    def test_unexpected_nested_fields_cannot_escape(self):
        data = {'records': [{'id': 'a', 'password': 'FAKE_ONLY', 'audio': 'bytes', 'latitude': 40,
                            'evidence': 'known'}], 'unrecognized': 'private'}
        self.assertEqual({'records': [{'id': 'a', 'evidence': 'known'}]}, self.export('sensor.kim_incidents_01', data))

    def test_credentials_and_network_values_are_redacted_inside_evidence(self):
        raw = 'token = FAKE_ONLY_123 password=FAKE_ONLY_pwd ghp_FAKEONLY12345678 http://192.168.178.72:8123 192.168.178.72 2001:db8::1'
        out = self.export('sensor.kim_health', {'modules': [{'evidence': raw}]})['modules'][0]['evidence']
        for secret in ['FAKE_ONLY', 'ghp_FAKE', '192.168.178.72', '2001:db8::1']:
            self.assertNotIn(secret, out)

    def test_raw_audio_text_and_history_are_never_exported(self):
        self.assertEqual({}, self.export('sensor.kim_voice', {'audio': 'private', 'transcript': 'private', 'history': ['private']}))

    def test_oversized_list_is_explicitly_flagged(self):
        out = self.export('sensor.kim_incidents_00', {'records': [{'id': str(i)} for i in range(129)]})
        self.assertIn('export_error', out['records'])

    def test_nan_and_container_in_scalar_are_rejected(self):
        out = self.export('sensor.kim_voice', {'timings_ms': {'total_ms': float('nan'), 'listen_ms': {'password': 'private'}}})
        self.assertEqual({'total_ms': None, 'listen_ms': None}, out['timings_ms'])

    def test_entity_ids_and_versions_are_not_network_addresses(self):
        out = self.export('sensor.kim_status', {'app_version': '1.0.6', 'details': [{'entity_or_module': 'switch.luce_ingresso'}]})
        self.assertEqual('1.0.6', out['app_version'])
        self.assertEqual('switch.luce_ingresso', out['details'][0]['entity_or_module'])

    def test_inventory_builder_passes_entity_identity_to_selector(self):
        fn = next(node for node in tree.body if getattr(node, 'name', None) == '_build_inventory')
        calls = [node for node in ast.walk(fn) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == '_safe_attrs']
        self.assertEqual(1, len(calls))
        self.assertEqual('entity_id', calls[0].args[1].id)

if __name__ == '__main__':
    unittest.main()
