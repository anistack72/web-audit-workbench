"""Publish a tested package version, with immutable tags and verified downloads."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import time

ALLOWED = {'anistack72/ai-runtime-doctor', 'anistack72/asset-budget',
           'anistack72/web-audit-workbench', 'anistack72/mac-release-gate',
           'anistack72/security-report-kit'}
MATRIX = {f'test ({platform}, {node})' for platform in
          ('ubuntu-latest', 'macos-latest', 'windows-latest') for node in ('22', '24')}


class ReleaseError(RuntimeError):
    pass


class GitHub:
    def run(self, *args):
        result = subprocess.run(['gh', *args], text=True, capture_output=True, timeout=120)
        if result.returncode:
            raise ReleaseError('GitHub CLI operation failed; no credential or response body logged')
        return result.stdout

    def api(self, endpoint, optional=False):
        result = subprocess.run(['gh', 'api', endpoint], text=True, capture_output=True, timeout=45)
        if result.returncode:
            if optional and re.search(r'HTTP 404\b', result.stderr):
                return None
            raise ReleaseError('GitHub API permission or transport failure')
        return json.loads(result.stdout)


def validate_package(root, output):
    root, output = Path(root), Path(output)
    meta = json.loads((root / 'package.json').read_text())
    if not re.fullmatch(r'\d+\.\d+\.\d+', meta['version']):
        raise ReleaseError('Only explicit stable package versions may be published')
    rows = json.loads((output / 'pack.json').read_text())
    if not isinstance(rows, list) or len(rows) != 1:
        raise ReleaseError('Expected exactly one packed artifact')
    filename = rows[0]['filename']
    archive = (output / filename).resolve()
    if archive.parent != output.resolve() or not filename.endswith('.tgz') or not archive.is_file():
        raise ReleaseError('Invalid packed artifact path')
    if archive.stat().st_size > 50 * 1024 * 1024:
        raise ReleaseError('Artifact exceeds the release size bound')
    with tarfile.open(archive, 'r:gz') as package:
        members = package.getmembers()
        if any(Path(m.name).is_absolute() or '..' in Path(m.name).parts or m.issym() or m.islnk() for m in members):
            raise ReleaseError('Unsafe package archive member')
        required = {'package/cli.mjs', 'package/index.mjs', 'package/support.mjs',
                    'package/package.json', 'package/LICENSE', 'package/README.md',
                    'package/demo.mjs', 'package/docs/try-it.md', 'package/CHANGELOG.md'}
        if meta['name'] == '@anistack72/asset-budget':
            required.add('package/budget.example.json')
        if not required.issubset({m.name for m in members}):
            raise ReleaseError('The distributable is missing documented runtime or onboarding files')
        embedded = json.load(package.extractfile('package/package.json'))
        if (embedded['name'], embedded['version']) != (meta['name'], meta['version']):
            raise ReleaseError('Packed metadata differs from tested source')
    return meta, archive



def find_release(github, repo, tag):
    # The by-tag endpoint returns published releases only. Authenticated listings
    # also include drafts, which must be resumed rather than created twice.
    published = github.api(f'repos/{repo}/releases/tags/{tag}', optional=True)
    if published is not None:
        return published
    for page in range(1, 11):
        releases = github.api(f'repos/{repo}/releases?per_page=100&page={page}')
        matches = [release for release in releases if release['tag_name'] == tag]
        if len(matches) > 1:
            raise ReleaseError('Ambiguous release version; no mutation permitted')
        if matches:
            return matches[0]
        if len(releases) < 100:
            return None
    raise ReleaseError('Release lookup exceeded its bound; no duplicate creation permitted')


def publish(root, output, repo, sha, run_id, github, dry_run=False):
    if repo not in ALLOWED or not re.fullmatch(r'[a-f0-9]{40}', sha) or not str(run_id).isdigit():
        raise ReleaseError('Repository, commit or workflow run is not authorized')
    meta, archive = validate_package(root, output)
    if meta['name'] != '@' + repo:
        raise ReleaseError('Package identity differs from authorized repository')
    tag = 'v' + meta['version']
    if dry_run:
        return {'status': 'validated_only', 'tag': tag, 'artifact': archive.name}
    if github.api(f'repos/{repo}/commits/main')['sha'] != sha:
        return {'status': 'skipped_main_moved'}
    run = github.api(f'repos/{repo}/actions/runs/{run_id}')
    if not (run['name'] == 'Tests' and run['event'] == 'push' and run['head_branch'] == 'main'
            and run['head_sha'] == sha and run['status'] == 'completed' and run['conclusion'] == 'success'):
        raise ReleaseError('A successful main-branch test run for this exact SHA is required')
    jobs = github.api(f'repos/{repo}/actions/runs/{run_id}/jobs?per_page=100')
    if jobs['total_count'] > 100 or {j['name'] for j in jobs['jobs']} != MATRIX or any(
            j['status'] != 'completed' or j['conclusion'] != 'success' for j in jobs['jobs']):
        raise ReleaseError('The complete six-job platform/Node matrix must pass')
    release = find_release(github, repo, tag)
    if release and not release['draft']:
        return {'status': 'skipped_version_already_published', 'url': release['html_url']}
    if release and release['target_commitish'] != sha:
        raise ReleaseError('Existing draft targets different source; no overwrite permitted')
    ref = github.api(f'repos/{repo}/git/ref/tags/{tag}', optional=True)
    if ref:
        obj = ref['object']
        if obj['type'] == 'tag':
            obj = github.api(f'repos/{repo}/git/tags/' + obj['sha'])['object']
        if obj['type'] != 'commit' or obj['sha'] != sha:
            raise ReleaseError('Version tag points to a different commit; no force update permitted')
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    sums = archive.parent / 'SHA256SUMS.txt'
    sums.write_text(f'{digest}  {archive.name}\n')
    if release is None:
        notes = archive.parent / 'release-notes.txt'
        notes.write_text(f"{meta['description']}\n\n"
                         f"Source commit: {sha}\n\nRequires Node.js 22 or later. "
                         "Download the npm source package and verify it against SHA256SUMS.txt. "
                         "This GitHub release does not publish the package to npm.\n\n"
                         f"Validated Node 22/24 on Linux, macOS and Windows: https://github.com/{repo}/actions/runs/{run_id}\n\n"
                         "The packaged fixture demo is synthetic and is not a production benchmark. "
                         "Read the README and docs/try-it.md for supported behavior and limitations.\n")
        github.run('release', 'create', tag, '--repo', repo, '--target', sha, '--draft',
                   '--title', meta['name'] + ' ' + tag, '--notes-file', str(notes))
        # Only retry reads here. A newly created draft may not yet be visible
        # through the listing; never repeat the create operation implicitly.
        for delay in (0, 1, 2, 4):
            if delay:
                time.sleep(delay)
            release = find_release(github, repo, tag)
            if release is not None:
                break
        if release is None:
            raise ReleaseError('Created draft could not be confirmed; retry safely')
    existing = {a['name'] for a in release['assets']}
    for file in (archive, sums):
        if file.name not in existing:
            github.run('release', 'upload', tag, str(file), '--repo', repo)
    with tempfile.TemporaryDirectory() as directory:
        for file in (archive, sums):
            github.run('release', 'download', tag, '--repo', repo, '--pattern', file.name, '--dir', directory)
            if (Path(directory) / file.name).read_bytes() != file.read_bytes():
                raise ReleaseError('Uploaded asset verification failed; release remains a draft')
    if github.api(f'repos/{repo}/commits/main')['sha'] != sha:
        return {'status': 'draft_retained_main_moved'}
    github.run('release', 'edit', tag, '--repo', repo, '--draft=false')
    published = github.api(f'repos/{repo}/releases/tags/{tag}')
    if published['draft']:
        raise ReleaseError('Release publication was not confirmed')
    return {'status': 'published', 'url': published['html_url'], 'sha256': digest}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', default='release-output')
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    try:
        result = publish('.', args.output, os.environ['GITHUB_REPOSITORY'],
                         os.environ['TESTED_SHA'], os.environ['TEST_RUN_ID'], GitHub(), args.dry_run)
        print(json.dumps(result))
    except (ReleaseError, KeyError, ValueError, OSError, subprocess.SubprocessError, tarfile.TarError) as error:
        result = {'status': 'failed_closed', 'error_type': type(error).__name__}
        if isinstance(error, ReleaseError):
            result['reason'] = str(error)  # Authored static messages; never a response body.
        print(json.dumps(result))
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
