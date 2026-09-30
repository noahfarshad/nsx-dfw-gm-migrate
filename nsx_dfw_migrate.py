#!/usr/bin/env python3
"""Conservative GM-to-GM DFW exporter and disabled-policy staging tool.
Python 3.9+, requests (pip install requests). Run --help and each command --help.
No encrypted UI export support. API acceptance is not realization proof.
"""
import argparse
import copy
import getpass
import json
import os
import re
import sys
from datetime import datetime, timezone
from urllib.parse import quote, urlparse
import requests

ROOT = '/global-infra'
API = '/global-manager/api/v1'
READONLY = {'path', 'relative_path', 'parent_path', 'unique_id', 'realization_id',
            'marked_for_delete', 'overridden', 'origin_site_id', 'owner_id',
            'remote_path', 'publish_status', 'status', 'rule_id'}

def clean(v):
    if isinstance(v, dict):
        return {k: clean(x) for k, x in v.items()
                if not k.startswith('_') and k not in READONLY}
    if isinstance(v, list):
        return [clean(x) for x in v]
    return v

def save(path, data):
    # Exclusive creation avoids silently replacing exports, plans or journals.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(data, f, indent=2)
        f.write('\n')

def read(path):
    with open(path) as f:
        return json.load(f)

def strings(v):
    if isinstance(v, str):
        yield v
    elif isinstance(v, dict):
        for x in v.values():
            yield from strings(x)
    elif isinstance(v, list):
        for x in v:
            yield from strings(x)

def refs(v):
    return set(s for s in strings(v) if s.startswith(('/global-infra/', '/infra/')))

def remap(v, mapping):
    if isinstance(v, str):
        return mapping.get(v, v)
    if isinstance(v, list):
        return [remap(x, mapping) for x in v]
    if isinstance(v, dict):
        return {k: remap(x, mapping) for k, x in v.items()}
    return v

class Client:
    def __init__(self, args):
        self.host = args.host.rstrip('/')
        u = urlparse(self.host)
        if u.scheme != 'https' or not u.netloc or u.path or u.username or u.query or u.fragment:
            raise ValueError('--host must be https://hostname without credentials or path')
        self.session = requests.Session()
        self.session.auth = (args.user, getpass.getpass('NSX password: '))
        self.session.verify = args.ca_bundle or True
    def request(self, method, path, body=None, params=None):
        if not path.startswith(ROOT + '/') or '..' in path or '?' in path or '#' in path:
            raise ValueError('Invalid global policy path: ' + path)
        r = self.session.request(method, self.host + API + quote(path, safe='/'),
                                 json=body, params=params, timeout=(10, 60), allow_redirects=False)
        if r.status_code == 404 and method == 'GET':
            return None
        if not 200 <= r.status_code < 300:
            raise RuntimeError(f'{method} {path}: HTTP {r.status_code}; {r.text[:500]}')
        return r.json() if r.content else {}
    def listing(self, path):
        result, seen, cursor = [], set(), None
        while True:
            d = self.request('GET', path, params={'cursor': cursor} if cursor else {})
            if d is None or not isinstance(d.get('results'), list):
                raise RuntimeError('Unavailable or malformed collection: ' + path)
            result.extend(d['results'])
            cursor = d.get('cursor')
            if not cursor:
                return result
            if cursor in seen:
                raise RuntimeError('Repeated pagination cursor: ' + path)
            seen.add(cursor)

def export(c, a):
    objects = {}
    for domain in c.listing(ROOT + '/domains'):
        base = ROOT + '/domains/' + domain['id']
        for p in c.listing(base + '/security-policies'):
            path = base + '/security-policies/' + p['id']
            p = c.request('GET', path)
            p['rules'] = c.listing(path + '/rules')
            objects[path] = p
    # Fetch the transitive dependency closure; arbitrary network objects are
    # recorded for explicit mapping, never recreated by this tool.
    pending = list(set().union(*(refs(clean(x)) for x in objects.values())))
    external = {}
    while pending:
        path = pending.pop()
        if path in objects or path in external:
            continue
        supported = re.fullmatch(r'/global-infra/(services/[^/]+|context-profiles/[^/]+|domains/[^/]+/groups/[^/]+)', path)
        if not supported:
            external[path] = 'Requires explicit target path mapping'
            continue
        obj = c.request('GET', path)
        if obj is None:
            raise RuntimeError('Source dependency missing: ' + path)
        objects[path] = obj
        pending.extend(refs(clean(obj)))
    save(a.out, {'format': 1, 'source': c.host, 'exported_at': datetime.now(timezone.utc).isoformat(),
                 'objects': objects, 'external': external})
    print(f'Exported {len(objects)} objects to {a.out}')

def make_plan(c, a):
    bundle = read(a.bundle)
    mapping = read(a.mapping) if a.mapping else {}
    if not isinstance(mapping, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k,v in mapping.items()):
        raise ValueError('Mapping must be a JSON object of exact source path: target path pairs')
    if bundle['source'].rstrip('/') == c.host:
        raise ValueError('Source and target must differ')
    objects, blockers, operations, reused = bundle['objects'], [], {}, []
    for path, raw in objects.items():
        if '/security-policies/' in path and (raw.get('_system_owned') or raw.get('id','').startswith('default')):
            blockers.append('System/default policy requires manual review: ' + path)
            continue
        if path in mapping:
            target = mapping[path]
            if c.request('GET', target) is None:
                blockers.append('Mapped target missing: ' + target)
            else:
                reused.append({'source': path, 'target': target, 'review': 'Confirm semantic equivalence and membership'})
            continue
        body = remap(clean(raw), mapping)
        if '/security-policies/' in path:
            body['stateful'] = raw.get('stateful', True)
            body['disabled'] = True
        existing = c.request('GET', path)
        if existing is not None:
            if clean(existing) == body and '/security-policies/' not in path:
                reused.append({'source': path, 'target': path, 'review': 'Matching definition; verify membership'})
            else:
                blockers.append('Existing target object: map explicitly or resolve manually: ' + path)
            continue
        if raw.get('_system_owned') or raw.get('_protection') not in (None, 'NOT_PROTECTED'):
            blockers.append('Protected object requires target mapping: ' + path)
            continue
        if any(s in ('ExternalIDExpression', 'IdentityGroupExpression') for s in strings(body)):
            blockers.append('Identity/static VM membership requires target-specific mapping: ' + path)
        operations[path] = body
    for source in bundle.get('external', {}):
        if source not in mapping:
            blockers.append('Unmapped external reference: ' + source)
    checked = set()
    for path, body in operations.items():
        domain = re.match(r'(/global-infra/domains/[^/]+)/', path)
        dependencies = refs(body) | ({domain.group(1)} if domain else set())
        for dep in dependencies:
            if dep in operations or dep in checked:
                continue
            checked.add(dep)
            if c.request('GET', dep) is None:
                blockers.append('Target dependency missing: ' + dep)
    # Topological ordering prevents nested group/service forward references.
    ordered, remaining = [], dict(operations)
    while remaining:
        ready = [p for p,b in remaining.items() if not (refs(b) & remaining.keys())]
        if not ready:
            blockers.append('Dependency cycle: ' + ', '.join(remaining))
            break
        ready.sort(key=lambda p: ('/security-policies/' in p, remaining[p].get('sequence_number',0), p))
        for p in ready:
            ordered.append({'path': p, 'body': remaining.pop(p)})
    plan = {'format': 1, 'target': c.host, 'source': bundle['source'],
            'blockers': sorted(set(blockers)), 'reused': reused, 'operations': ordered,
            'notes': ['Policies staged disabled. No automatic activation.',
                      'Review tags, membership, policy ordering, scope and version compatibility.',
                      'Apply is not atomic; journal records partial progress. No automatic deletion.']}
    save(a.out, plan)
    print(f'{len(ordered)} creates; {len(plan["blockers"])} blockers. Review {a.out}')

def apply(c, a):
    plan = read(a.plan)
    if c.host != plan['target'] or c.host == plan['source']:
        raise ValueError('Plan target mismatch or source equals target')
    if plan['blockers']:
        raise ValueError('Plan has blockers; resolve and regenerate it')
    if not a.commit:
        print(f'DRY RUN: {len(plan["operations"])} creates; no writes. Use --commit after review.')
        return
    if not a.journal:
        raise ValueError('--journal is required with --commit')
    # All checks happen before the first write. There is still no API-wide
    # transaction; do not run concurrent changes to these object IDs.
    for op in plan['operations']:
        if '/security-policies/' in op['path'] and op['body'].get('disabled') is not True:
            raise ValueError('Refusing enabled policy')
        if not re.fullmatch(r'/global-infra/(services/[^/]+|context-profiles/[^/]+|domains/[^/]+/(groups|security-policies)/[^/]+)', op['path']):
            raise ValueError('Unsupported write path')
        if c.request('GET', op['path']) is not None:
            raise ValueError('Target appeared since plan; regenerate: ' + op['path'])
    fd = os.open(a.journal, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as log:
        for op in plan['operations']:
            # Write intent before request so ambiguous timeout remains auditable.
            for state in ['attempt', 'accepted']:
                if state == 'accepted':
                    c.request('PATCH', op['path'], op['body'])
                log.write(json.dumps({'state': state, 'path': op['path']}) + '\n')
                log.flush()
                os.fsync(log.fileno())
    print('API writes accepted; policies remain disabled. Verify realization and membership in both sites.')

def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    for name in ['export', 'plan', 'apply']:
        s = sub.add_parser(name)
        s.add_argument('--host', required=True, help='https://GM-FQDN')
        s.add_argument('--user', default='admin')
        s.add_argument('--ca-bundle', help='PEM CA bundle; TLS verification always enabled')
        if name == 'export':
            s.add_argument('--out', required=True)
        elif name == 'plan':
            s.add_argument('--bundle', required=True)
            s.add_argument('--mapping', help='JSON exact path mapping; mapped objects reused, not changed')
            s.add_argument('--out', required=True)
        else:
            s.add_argument('--plan', required=True)
            s.add_argument('--commit', action='store_true')
            s.add_argument('--journal')
    a = p.parse_args()
    globals()[{'export':'export','plan':'make_plan','apply':'apply'}[a.command]](Client(a), a)

if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as e:
        print(f'STOPPED: {e}. If applying, inspect the journal and target before retrying.', file=sys.stderr)
        sys.exit(1)
