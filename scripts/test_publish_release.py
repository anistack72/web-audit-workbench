import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from publish_release import MATRIX, ReleaseError, publish

SHA = 'a' * 40
REPO = 'anistack72/ai-runtime-doctor'


class FakeGitHub:
    def __init__(self):
        self.sha = SHA
        self.release = None
        self.assets = {}
        self.calls = []
        self.failed_matrix = False
        self.corrupt = False
        self.tag = None
        self.full_release_pages = False
        self.hidden_draft_reads = 0

    def api(self, endpoint, optional=False):
        if endpoint.endswith('/commits/main'):
            return {'sha': self.sha}
        if endpoint.endswith('/actions/runs/123'):
            return {'name': 'Tests', 'event': 'push', 'head_branch': 'main', 'head_sha': SHA,
                    'status': 'completed', 'conclusion': 'success'}
        if '/jobs?' in endpoint:
            return {'total_count': 6, 'jobs': [{'name': name, 'status': 'completed',
                'conclusion': 'failure' if self.failed_matrix else 'success'} for name in MATRIX]}
        if '/git/ref/tags/' in endpoint:
            return self.tag
        if '/releases/tags/' in endpoint:
            return self.release if self.release and not self.release['draft'] else None
        if '/releases?' in endpoint:
            if self.full_release_pages:
                return [{'tag_name': f'v2.0.{n}'} for n in range(100)]
            if self.release and self.hidden_draft_reads:
                self.hidden_draft_reads -= 1
                return []
            if self.release:
                self.release['tag_name'] = 'v0.1.0'
                self.release['assets'] = [{'name': name} for name in self.assets]
                return [self.release]
            return []
        raise AssertionError(endpoint)

    def run(self, *args):
        self.calls.append(args)
        if args[:2] == ('release', 'create'):
            self.release = {'draft': True, 'target_commitish': SHA, 'assets': [],
                            'html_url': 'https://github.com/' + REPO + '/releases/tag/v0.1.0'}
        elif args[:2] == ('release', 'upload'):
            file = Path(args[3])
            self.assets[file.name] = file.read_bytes()
        elif args[:2] == ('release', 'download'):
            name = args[args.index('--pattern') + 1]
            directory = Path(args[args.index('--dir') + 1])
            (directory / name).write_bytes(b'corrupt' if self.corrupt else self.assets[name])
        elif args[:2] == ('release', 'edit'):
            self.release['draft'] = False
        else:
            raise AssertionError(args)
        return ''


class ReleaseIntegration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.output = self.root / 'release-output'
        self.output.mkdir()
        self.meta = {'name': '@anistack72/ai-runtime-doctor', 'version': '0.1.0', 'description': 'Fixture package'}
        (self.root / 'package.json').write_text(json.dumps(self.meta))
        self.archive = self.output / 'anistack72-ai-runtime-doctor-0.1.0.tgz'
        self.pack()
        (self.output / 'pack.json').write_text(json.dumps([{'filename': self.archive.name}]))
        self.gh = FakeGitHub()

    def tearDown(self):
        self.temp.cleanup()

    def pack(self, omit=None, unsafe=False):
        with tarfile.open(self.archive, 'w:gz') as package:
            for name in ['cli.mjs', 'index.mjs', 'support.mjs', 'package.json', 'LICENSE',
                         'README.md', 'demo.mjs', 'docs/try-it.md', 'CHANGELOG.md']:
                if name == omit:
                    continue
                data = json.dumps(self.meta).encode() if name == 'package.json' else b'fixture'
                info = tarfile.TarInfo('package/' + name)
                info.size = len(data)
                package.addfile(info, io.BytesIO(data))
            if unsafe:
                info = tarfile.TarInfo('../outside')
                package.addfile(info, io.BytesIO(b''))

    def publish(self, **kwargs):
        return publish(self.root, self.output, REPO, SHA, '123', self.gh, **kwargs)

    def test_full_verified_publish_and_idempotent_repeat(self):
        self.assertEqual(self.publish()['status'], 'published')
        self.assertFalse(self.gh.release['draft'])
        self.assertIn('SHA256SUMS.txt', self.gh.assets)
        calls = len(self.gh.calls)
        self.assertEqual(self.publish()['status'], 'skipped_version_already_published')
        self.assertEqual(len(self.gh.calls), calls)

    def test_lookup_bound_prevents_duplicate_release_creation(self):
        self.gh.full_release_pages = True
        with self.assertRaises(ReleaseError):
            self.publish()
        self.assertEqual(self.gh.calls, [])

    def test_new_draft_visibility_delay_retries_reads_only(self):
        self.gh.hidden_draft_reads = 2
        with patch('publish_release.time.sleep') as sleep:
            self.assertEqual(self.publish()['status'], 'published')
        self.assertEqual(sleep.call_count, 2)
        self.assertEqual(sum(c[:2] == ('release', 'create') for c in self.gh.calls), 1)

    def test_unconfirmed_draft_stops_after_bounded_reads(self):
        self.gh.hidden_draft_reads = 10
        with patch('publish_release.time.sleep') as sleep:
            with self.assertRaisesRegex(ReleaseError, 'Created draft could not be confirmed'):
                self.publish()
        self.assertEqual(sleep.call_count, 3)
        self.assertTrue(self.gh.release['draft'])
        self.assertEqual(sum(c[:2] == ('release', 'create') for c in self.gh.calls), 1)

    def test_mismatched_package_identity_is_rejected(self):
        self.meta['name'] = '@someone/else'
        (self.root / 'package.json').write_text(json.dumps(self.meta))
        self.pack()
        with self.assertRaisesRegex(ReleaseError, 'Package identity'):
            self.publish()
        self.assertEqual(self.gh.calls, [])

    def test_dry_run_has_no_network_or_mutations(self):
        self.assertEqual(self.publish(dry_run=True)['status'], 'validated_only')
        self.assertEqual(self.gh.calls, [])
        self.assertIsNone(self.gh.release)

    def test_failed_matrix_prevents_release(self):
        self.gh.failed_matrix = True
        with self.assertRaises(ReleaseError):
            self.publish()
        self.assertEqual(self.gh.calls, [])

    def test_changed_main_prevents_release(self):
        self.gh.sha = 'b' * 40
        self.assertEqual(self.publish()['status'], 'skipped_main_moved')
        self.assertEqual(self.gh.calls, [])

    def test_wrong_repository_is_rejected(self):
        with self.assertRaises(ReleaseError):
            publish(self.root, self.output, 'someone/else', SHA, '123', self.gh)
        self.assertEqual(self.gh.calls, [])

    def test_wrong_existing_tag_is_never_moved(self):
        self.gh.tag = {'object': {'type': 'commit', 'sha': 'b' * 40}}
        with self.assertRaises(ReleaseError):
            self.publish()
        self.assertEqual(self.gh.calls, [])

    def test_corrupt_upload_stays_draft(self):
        self.gh.corrupt = True
        with self.assertRaises(ReleaseError):
            self.publish()
        self.assertTrue(self.gh.release['draft'])
        self.assertFalse(any(call[:2] == ('release', 'edit') for call in self.gh.calls))

    def test_missing_onboarding_file_blocks_release(self):
        self.pack(omit='docs/try-it.md')
        with self.assertRaises(ReleaseError):
            self.publish()
        self.assertEqual(self.gh.calls, [])

    def test_unsafe_archive_is_rejected(self):
        self.pack(unsafe=True)
        with self.assertRaises(ReleaseError):
            self.publish()
        self.assertEqual(self.gh.calls, [])

    def test_partial_upload_resumes_without_clobber(self):
        self.gh.release = {'draft': True, 'target_commitish': SHA, 'assets': [], 'html_url': 'https://github.com/' + REPO}
        self.gh.assets[self.archive.name] = self.archive.read_bytes()
        self.assertEqual(self.publish()['status'], 'published')
        uploaded = [c[3] for c in self.gh.calls if c[:2] == ('release', 'upload')]
        self.assertEqual([Path(p).name for p in uploaded], ['SHA256SUMS.txt'])


if __name__ == '__main__':
    unittest.main()
