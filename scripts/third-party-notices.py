#!/usr/bin/env python3
"""Collect upstream Go module and compiled UI license notices for distribution."""
import json
import subprocess
from pathlib import Path

data = subprocess.check_output(['go', 'list', '-m', '-json', 'all']).decode()
decoder = json.JSONDecoder()
modules = []
while data.strip():
    module, end = decoder.raw_decode(data.lstrip())
    modules.append(module)
    data = data.lstrip()[end:]
parts = ['gdns third-party notices\nGenerated from pinned go.mod modules and Tailwind CSS.\n']
gorooot=Path(subprocess.check_output(['go','env','GOROOT']).decode().strip())
parts.append('Go toolchain / standard library\n'+(gorooot/'LICENSE').read_text())
for module in modules:
    if module.get('Main'):
        continue
    directory = module.get('Dir')
    if not directory:
        downloaded = json.loads(subprocess.check_output(['go', 'mod', 'download', '-json', module['Path']+'@'+module['Version']]))
        directory = downloaded['Dir']
    root = Path(directory)
    candidates = sorted(p for p in root.iterdir() if p.is_file() and (p.name.upper().startswith(('LICENSE','COPYING','NOTICE'))))
    if not candidates:
        raise SystemExit('No license notice found for '+module['Path'])
    parts.append('\n'+'='*72+'\n'+module['Path']+' '+module['Version']+'\n')
    for p in candidates:
        parts.append('\n'+p.name+'\n'+p.read_text(errors='replace'))
p = Path('node_modules/tailwindcss/LICENSE')
if not p.exists():
    raise SystemExit('Run npm ci before generating Tailwind license notices')
parts.append('\n'+'='*72+'\nTailwind CSS '+json.loads(Path('node_modules/tailwindcss/package.json').read_text())['version']+'\n'+p.read_text())
Path('THIRD_PARTY_NOTICES.txt').write_text('\n'.join(line.rstrip() for line in '\n'.join(parts).splitlines())+'\n')
