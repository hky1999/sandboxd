#!/usr/bin/env python3
# Phase 0.2: BM1 park-chain health smoke on the rev16 stack (no LLM).
# Chain under test: create -> park(signal 18, leaveRunning=false) ->
# directed wake(signal 24, schema-1 identity) -> restore -> marker survives.
# Plus an ABA negative: a stale-generation wake must be rejected.
import json, os, subprocess, time, sys, traceback
from pathlib import Path

R = Path('/root/akernel-bm1')
OUT = R / 'logs/park-smoke'
OUT.mkdir(parents=True, exist_ok=True)
report = {}
def save():
    (OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')

def k(*args):
    return subprocess.check_output(['kubectl', '-n', 'akernel', *args], text=True)

def node_pod():
    # prefer a node hosting live sandboxes; fall back to any node pod so
    # pre-create probes (resolver token) still have a place to run
    fallback = None
    for p in json.loads(k('get', 'pods', '-o', 'json'))['items']:
        n = p['metadata']['name']
        if n.startswith('akernel-node-'):
            if fallback is None:
                fallback = n
            ids = k('exec', n, '--', 'sbox', 'list')
            if any(l.split() and l.split()[0].startswith('sbox-') for l in ids.splitlines()):
                return n
    return fallback

JWT = subprocess.check_output(
    ['bash', '-c', 'grep AKERNEL_TOKEN /root/akernel-bm1/secrets/akernel.env | cut -d= -f2'],
    text=True).strip()
RESOLVER_TOKEN = None

import base64 as _b64

def frontend_kill(instance_id, signal, payload=None):
    body = {"instanceID": instance_id, "signal": signal}
    if payload is not None:
        # protojson decodes the bytes payload field from base64
        body["payload"] = _b64.b64encode(payload.encode()).decode()
    pod = node_pod()
    cmd = ['kubectl', '-n', 'akernel', 'exec', pod, '--', 'curl', '-s', '-m', '170', '-k',
           '-X', 'POST', 'https://akernel-frontend:8888/frontend/v1/instance/kill',
           '-H', f'X-Auth: {JWT}', '-H', 'Content-Type: application/json',
           '-d', json.dumps(body)]
    out = subprocess.check_output(cmd, text=True)
    try:
        return json.loads(out)
    except Exception:
        return {"raw": out[:500]}

def resolve(instance_id):
    # Identity straight from sandbox labels (instance-id/runtime-id/
    # resource-generation all live there); scans every node pod.
    for p in json.loads(k('get', 'pods', '-o', 'json'))['items']:
        pod = p['metadata']['name']
        if not pod.startswith('akernel-node-'):
            continue
        out = k('exec', pod, '--', 'sbox', 'list')
        for line in out.splitlines():
            parts = line.split()
            if not parts or not parts[0].startswith('sbox-'):
                continue
            info = json.loads(k('exec', pod, '--', 'sbox', 'inspect', parts[0]))
            labels = info.get('labels', {})
            if labels.get('akernel.scheduler/instance-id') != instance_id:
                continue
            return {"sandbox_id": parts[0],
                    "runtime_id": labels.get('akernel.scheduler/runtime-id', ''),
                    "resource_generation": labels.get('akernel.scheduler/resource-generation', ''),
                    "ip": info.get('ip', '')}
    return {}

def sbox_ids():
    ids = []
    for p in json.loads(k('get', 'pods', '-o', 'json'))['items']:
        pod = p['metadata']['name']
        if not pod.startswith('akernel-node-'):
            continue
        out = k('exec', pod, '--', 'sbox', 'list')
        ids.extend(l.split()[0] for l in out.splitlines()
                   if l.split() and l.split()[0].startswith('sbox-'))
    return ids

def sbox_exec(sandbox_id, command):
    pod = pod_of(sandbox_id)
    return subprocess.run(
        ['kubectl', '-n', 'akernel', 'exec', pod, '--', 'sbox', 'exec', sandbox_id, '--', 'sh', '-c', command],
        capture_output=True, text=True, timeout=60)

def pod_of(sandbox_id):
    for p in json.loads(k('get', 'pods', '-o', 'json'))['items']:
        pod = p['metadata']['name']
        if not pod.startswith('akernel-node-'):
            continue
        out = k('exec', pod, '--', 'sbox', 'list')
        if any(l.split() and l.split()[0] == sandbox_id for l in out.splitlines()):
            return pod
    return node_pod()

def proxy_log_tail(grep, pod=None):
    pod = pod or node_pod()
    out = subprocess.run(
        ['kubectl', '-n', 'akernel', 'exec', pod, '--', 'sh', '-c',
         f"grep -a '{grep}' /home/yuanrong/logs/*function_proxy.log | tail -3"],
        capture_output=True, text=True).stdout
    return out.strip().splitlines()

os.environ.update(AKERNEL_BACKEND='openyuanrong-sdk',
                  AKERNEL_SERVER_ADDRESS='https://127.0.0.1:8443',
                  AKERNEL_GATEWAY_ADDRESS='http://127.0.0.1:8080',
                  AKERNEL_TOKEN=JWT)
from akernel_sdk import Sandbox

name = f'bm1-park-smoke-{int(time.time())}'
sb = None
try:
    RESOLVER_TOKEN = k('exec', node_pod(), '--', 'cat', '/home/akernel/scheduler/resolver.token').strip()

    # 1. create + marker
    sb = Sandbox(image='arcagi-acr-1-registry-vpc.ap-southeast-5.cr.aliyuncs.com/benchmark/image:deep-swe-happy-dom-abort-pending-body-reads-20260907',
                 cpu=500, memory=512, name=name, idle_timeout=600, schedule_timeout=120)
    report['instance'] = sb.id
    r = sb.commands.run('sh -c "date +%s%N > /tmp/park-marker && cat /tmp/park-marker"', timeout=60)
    marker = r.stdout.strip()
    report['marker_at_create'] = marker
    save()
    print('created', sb.id, 'marker', marker, flush=True)

    # 2. identity via resolver
    ident = resolve(sb.id)  # sb.id carries the akernel- prefix the labels use
    report['identity_v1'] = ident
    sandbox_id = ident.get('sandbox_id') or ident.get('sandbox', '')
    generation = ident.get('resource_generation') or ident.get('generation', '')
    runtime_id = ident.get('runtime_id') or ident.get('runtime', '')
    assert sandbox_id and generation and runtime_id, ident
    assert sandbox_id in sbox_ids(), 'sandbox not listed before park'
    save()
    print('identity', sandbox_id, runtime_id, generation, flush=True)

    # 3. park (signal 18, empty payload => leaveRunning=false).
    # The frontend's authorizeKillRequest consults its exec-endpoint cache,
    # which fills from instance events; poll until this instance appears.
    cache_wait = 0.0
    for _ in range(24):
        try:
            listing = subprocess.check_output(
                ['kubectl', '-n', 'akernel', 'exec', pod_of(sandbox_id), '--', 'curl', '-s', '-m', '10', '-k',
                 '-H', f'X-Auth: {JWT}', 'https://akernel-frontend:8888/api/agent'], text=True)
            if sb.id in listing:
                break
        except Exception:
            pass
        time.sleep(10)
        cache_wait += 10
    report['frontend_cache_wait_s'] = cache_wait
    save()
    t0 = time.time()
    rsp = frontend_kill(sb.id, 18)
    report['park_rsp'] = rsp
    report['park_s'] = round(time.time() - t0, 3)
    save()
    gone = sandbox_id not in sbox_ids()
    report['sandbox_gone_after_park'] = gone
    report['park_log'] = proxy_log_tail('marked parked')
    print('park rsp', rsp, 'gone', gone, flush=True)

    # 4. wake with the correct identity (schema 1)
    deadline = int(time.time() * 1000) + 30000
    payload = json.dumps({"schema": 1, "sandbox_id": sandbox_id, "runtime_id": runtime_id,
                          "resource_generation": generation, "deadline_unix_ms": deadline})
    t0 = time.time()
    rsp = frontend_kill(sb.id, 24, payload)
    report['wake_rsp'] = rsp
    report['wake_s'] = round(time.time() - t0, 3)
    back = sandbox_id in sbox_ids()
    report['sandbox_back_after_wake'] = back
    if back:
        ex = sbox_exec(sandbox_id, 'cat /tmp/park-marker')
        report['marker_after_restore'] = ex.stdout.strip()
        report['marker_survived'] = ex.stdout.strip() == marker
        ident2 = resolve(sb.id)
        report['identity_v2'] = ident2
        report['same_sandbox_id'] = ident2.get('sandbox_id') == sandbox_id
    report['wake_log'] = proxy_log_tail('wake parked instance')
    save()
    print('wake rsp', rsp, 'back', back, flush=True)

    # 5. ABA negative: park again, then wake with the STALE generation
    if back and report.get('marker_survived'):
        stale_generation = generation  # generation of incarnation #1
        rsp = frontend_kill(name, 18)
        report['park2_rsp'] = rsp
        report['sandbox_gone_after_park2'] = sandbox_id not in sbox_ids()
        deadline = int(time.time() * 1000) + 30000
        stale_payload = json.dumps({"schema": 1, "sandbox_id": sandbox_id, "runtime_id": runtime_id,
                                    "resource_generation": stale_generation,
                                    "deadline_unix_ms": deadline})
        rsp = frontend_kill(sb.id, 24, stale_payload)
        report['stale_wake_rsp'] = rsp
        report['stale_wake_rejected'] = rsp.get('code') not in (0, None, '0')
        # recover with the current (fresh) generation so cleanup can proceed
        ident3 = None
        # after park2 the resolver cannot see the instance (parked); use the
        # registration the park recorded: same sandbox/runtime, fresh generation
        # from the wake log line.
        # For the smoke we only need the stale rejection; leave it parked.
        save()
        print('stale wake rsp', rsp, flush=True)

    report['smoke_pass'] = (
        report.get('sandbox_gone_after_park')
        and report.get('sandbox_back_after_wake')
        and report.get('marker_survived')
        and report.get('same_sandbox_id'))
    save()
except Exception as e:
    report['error'] = f'{type(e).__name__}: {str(e)[:800]}'
    report['traceback'] = traceback.format_exc()[-2500:]
    save()
    print(report['error'], flush=True)
finally:
    if sb:
        try:
            sb.kill()
        except Exception:
            pass
    save()
    print(json.dumps({k2: report.get(k2) for k2 in
        ['instance', 'park_rsp', 'park_s', 'sandbox_gone_after_park',
         'wake_rsp', 'wake_s', 'sandbox_back_after_wake', 'marker_survived',
         'same_sandbox_id', 'stale_wake_rsp', 'stale_wake_rejected',
         'smoke_pass', 'error']}, indent=2), flush=True)
