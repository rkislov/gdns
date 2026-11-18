#!/usr/bin/env python3
# Copyright 2026 Кислов Роман Сергеевич
# SPDX-License-Identifier: Apache-2.0
"""Cross-compile a self-contained bundle for the isolated Linux benchmark."""
import argparse
import ast
import json
import os
import pathlib
import shutil
import subprocess as sp
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument('--arch', choices=['amd64', 'arm64'], required=True)
parser.add_argument('--out', type=pathlib.Path, required=True)
parser.add_argument('--baseline-ref', default='cce7c27')
parser.add_argument('--baseline-tags', default='', help='Go build tags for baseline')
parser.add_argument('--candidate-tags', default='', help='Go build tags for candidate only')
args = parser.parse_args()
root = pathlib.Path(__file__).resolve().parents[1]
out = args.out.resolve()
out.mkdir(parents=True, exist_ok=False)
env = dict(os.environ, CGO_ENABLED='0', GOOS='linux', GOARCH=args.arch)
runner = root / 'scripts/bind9-performance.py'
tree = ast.parse(runner.read_text())
hook = next(ast.literal_eval(node.value) for node in ast.walk(tree)
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'hook' for t in node.targets))
with tempfile.TemporaryDirectory(prefix='gdns-performance-source-') as directory:
    base = pathlib.Path(directory).resolve()
    archive = sp.Popen(['git', 'archive', args.baseline_ref], cwd=root, stdout=sp.PIPE)
    sp.run(['tar', '-x', '-C', str(base)], stdin=archive.stdout, check=True)
    archive.stdout.close()
    if archive.wait():
        raise RuntimeError('git archive failed')
    for name, source, package in [('baseline-bin', base, './cmd/gdns'),
                                  ('candidate', root, './cmd/gdns'),
                                  ('load', root, './cmd/gdns-loadtest')]:
        sp.run(['go', 'build', *(['-tags', tags] if (tags := args.candidate_tags if name == 'candidate' else args.baseline_tags if name == 'baseline-bin' else '') else []), '-trimpath', '-o', str(out / name), package],
               cwd=source, env=env, check=True)
    for impl, source in [('baseline', base), ('candidate', root)]:
        original = source / 'cmd/gdns/main.go'
        patched = out / (impl + '-main.go')
        patched.write_text(original.read_text().replace('import (', 'import (\n"runtime"\n"runtime/pprof"', 1)
                           .replace('func main() {', hook, 1))
        overlay = out / (impl + '-overlay.json')
        overlay.write_text(json.dumps({'Replace': {str(original): str(patched)}}))
        sp.run(['go', 'build', *(['-tags', tags] if (tags := args.candidate_tags if impl == 'candidate' else args.baseline_tags) else []), '-overlay', str(overlay), '-trimpath', '-o',
                str(out / (impl + '-profile')), './cmd/gdns'], cwd=source, env=env, check=True)
        overlay.unlink()
        patched.unlink()
source = {
    'candidate_tags': args.candidate_tags,
    'baseline_tags': args.baseline_tags,
    'baseline_commit': sp.check_output(['git', 'rev-parse', args.baseline_ref], cwd=root, text=True).strip(),
    'candidate_commit': sp.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
    'candidate_diff': sp.check_output(['git', 'diff'], cwd=root, text=True),
    'go_version': sp.check_output(['go', 'version'], text=True).strip(),
}
source['candidate_untracked_sources'] = {name: (root / name).read_text() for name in sp.check_output(['git', 'ls-files', '--others', '--exclude-standard', 'cmd', 'internal'], cwd=root, text=True).splitlines() if name.endswith('.go')}
(out / 'source.json').write_text(json.dumps(source, indent=2) + '\n')
shutil.copy2(runner, out / runner.name)
print(out)
