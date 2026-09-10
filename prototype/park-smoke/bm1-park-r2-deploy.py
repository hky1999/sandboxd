#!/usr/bin/env python3
# r2: layer the checkpoint_dir fix onto the currently deployed candidate.
# merge-process deployments run runtime_manager inside function_proxy, so the
# flag must be forced (and the deploy.sh-supplied default filtered) in the
# function_proxy wrapper; runtime_manager wrapper gets the same for
# non-merged deployments. Binaries are unchanged from r1.
from pathlib import Path
import json, shutil, subprocess

R = Path('/root/akernel-bm1')
TAG = 'retire-e382dbe7-20260910-r2'
BASE = 'retire-e382dbe7-20260909-r1'

FIX_FLAG = b' --checkpoint_dir=/home/akernel/sandboxd/root/checkpoints'

BASH_FILTER = b"""
# r2: park-chain fix - sandboxd requires checkpoints below its own root; the
# deploy default (/home/yuanrong/checkpoints) is rejected and the flag parser
# refuses duplicates, so filter the incoming value and force ours.
args2=()
for arg in "${args[@]}"; do
 case "$arg" in --checkpoint_dir=*) ;; *) args2+=("$arg");; esac
done
"""

SH_FILTER = b"""
# r2: park-chain fix (see args2 variant above): POSIX-sh positional rebuild.
_first=1
for _a in "$@"; do
  case "$_a" in
    --checkpoint_dir=*) ;;
    *) if [ "$_first" = 1 ]; then set -- "$_a"; _first=0; else set -- "$@" "$_a"; fi ;;
  esac
done
"""

patch_core = (
    "from pathlib import Path\n"
    "p=Path('/home/yuanrong/functionsystem/bin/function_proxy')\n"
    "raw=p.read_bytes()\n"
    "anchor=b'exec /opt/akernel-scheduler/function-proxy/function_proxy '\n"
    "assert anchor in raw\n"
    + "bash_filter=" + repr(BASH_FILTER) + "\n"
    + "sh_filter=" + repr(SH_FILTER) + "\n"
    + "fix=" + repr(FIX_FLAG) + "\n"
    + "nl=" + repr(b"\n") + "\n"
    "if b'checkpoint_dir=/home/akernel/sandboxd/root/checkpoints' not in raw:\n"
    "    head,sep,rest=raw.partition(anchor)\n"
    "    if b'${args[@]}' in raw:\n"
    "        raw=head+bash_filter+nl+anchor+rest\n"
    "        raw=raw.replace(anchor+b'\"${args[@]}\"', anchor+b'\"${args2[@]}\"'+fix)\n"
    "    else:\n"
    "        raw=head+sh_filter+nl+anchor+rest\n"
    "        raw=raw.replace(anchor+b'\"$@\"', anchor+b'\"$@\"'+fix)\n"
    "    assert b'/home/akernel/sandboxd/root/checkpoints' in raw.split(anchor)[1]\n"
    "    p.write_bytes(raw)\n"
)

patch_rm = (
    "from pathlib import Path\n"
    "p=Path('/home/yuanrong/functionsystem/bin/runtime_manager')\n"
    "raw=p.read_bytes()\n"
    "anchor=b'exec /opt/akernel-scheduler/runtime-manager/runtime_manager '\n"
    "if b'checkpoint_dir=/home/akernel/sandboxd/root/checkpoints' not in raw:\n"
    "    raw=raw.replace(anchor, anchor+b'--checkpoint_dir=/home/akernel/sandboxd/root/checkpoints ')\n"
    "    p.write_bytes(raw)\n"
)

for role in ['core', 'node']:
    d = R / f'park-r2-{role}-image'
    if d.exists():
        shutil.rmtree(d)
    d.mkdir()
    lines = [f'FROM akerel-bm1/{role}:{BASE}' if False else f'FROM akernel-bm1/{role}:{BASE}']
    scripts = patch_core if role == 'core' else patch_core + "\n" + patch_rm
    (d / 'patch-checkpoint.py').write_text(scripts)
    lines += ['COPY patch-checkpoint.py /tmp/r2-patch.py',
              'RUN python3 /tmp/r2-patch.py && rm /tmp/r2-patch.py']
    (d / 'Dockerfile').write_text('\n'.join(lines) + '\n')
    log = R / 'logs' / f'park-r2-{role}-build.log'
    r = subprocess.run(['docker', 'build', '-t', f'akernel-bm1/{role}:{TAG}', str(d)],
                       stdout=open(log, 'w'), stderr=subprocess.STDOUT)
    print(role, 'build exit', r.returncode)
    assert r.returncode == 0
    image_id = subprocess.check_output(
        ['docker', 'inspect', '--format', '{{.Id}}', f'akernel-bm1/{role}:{TAG}'], text=True).strip()
    print(role, image_id)

values_path = R / 'secrets/values.json'
v = json.loads(values_path.read_text())
for r2 in ['master', 'frontend', 'node']:
    assert v['core'][r2]['image']['tag'] in (BASE, TAG), r2
    v['core'][r2]['image']['tag'] = BASE  # rebuild the candidate from the r1 baseline
for pod in json.loads(subprocess.check_output(
        ['kubectl', '-n', 'akernel', 'get', 'pods', '-o', 'json'], text=True))['items']:
    if pod['metadata']['name'].startswith('akernel-node-'):
        ids = subprocess.check_output(['kubectl', '-n', 'akernel', 'exec', pod['metadata']['name'],
                                       '--', 'sbox', 'list'], text=True)
        assert not any(l.split() and l.split()[0].startswith('sbox-') for l in ids.splitlines()), 'pre-existing instance'
for r2 in ['master', 'frontend', 'node']:
    v['core'][r2]['image']['tag'] = TAG
candidate = R / 'secrets/values-park-r2.json'
candidate.write_text(json.dumps(v, indent=2) + '\n')
candidate.chmod(0o600)
cmd = ['helm', 'upgrade', 'akernel', str(R / 'source/deploy/akernel'), '-n', 'akernel',
       '-f', str(candidate), '--atomic', '--wait', '--timeout', '8m']
with (R / 'logs/park-r2-deploy.log').open('w') as f:
    result = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT)
if result.returncode == 0:
    shutil.copy2(candidate, values_path)
    values_path.chmod(0o600)
(R / 'logs/park-r2-deploy-result.json').write_text(json.dumps(
    {'exit_code': result.returncode, 'values_promoted': result.returncode == 0, 'tag': TAG}))
print('helm upgrade exit', result.returncode)
raise SystemExit(result.returncode)
