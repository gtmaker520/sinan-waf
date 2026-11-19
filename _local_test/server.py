#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
司南防火墙 —— 本地测试服务器（仅用于开发自测，切勿用于生产）

作用:
  1. 模拟宝塔面板 /plugin?action=a&name=sinanwaf&s=<方法> 调用路由
  2. 模拟 Nginx 全局配置、站点 vhost、访问日志、网站目录与木马样本
  3. 把插件运行数据重定向到 _local_test/data，绝不写入真实系统目录
  4. 提供一个轻量 jQuery 兼容层，让插件原生界面无需宝塔面板也能运行

用法: python _local_test/server.py            # 启动服务器并自动打开浏览器
      python _local_test/server.py --selftest # 只跑后端自检 + HTTP 冒烟测试
"""
import os, sys, json, time, shutil, threading, traceback, webbrowser

try:
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
except ImportError:
    try:
        # Python 3.6（如 CentOS 7 系统自带）: 标准库可拼出等价类
        from http.server import BaseHTTPRequestHandler, HTTPServer as _HS
        from socketserver import ThreadingMixIn as _Mix
        class ThreadingHTTPServer(_Mix, _HS):
            daemon_threads = True
    except ImportError:
        # Python 2.7
        from BaseHTTPServer import BaseHTTPRequestHandler
        from SocketServer import ThreadingMixIn as _Mix
        from BaseHTTPServer import HTTPServer as _HS
        class ThreadingHTTPServer(_Mix, _HS):
            daemon_threads = True
try:
    from urllib.parse import urlparse, parse_qs
except ImportError:
    from urlparse import urlparse, parse_qs
try:
    from urllib.request import urlopen, Request
except ImportError:
    from urllib2 import urlopen, Request

HERE = os.path.dirname(os.path.abspath(__file__))
# 本地测试环境放在项目根目录, 与插件目录同级: <project>/sinanwaf 与 <project>/_local_test
PLUGIN = os.path.join(os.path.dirname(HERE), 'sinanwaf')
if not os.path.isdir(PLUGIN):
    # 兼容旧布局(测试环境仍在插件目录内)
    PLUGIN = os.path.dirname(HERE)
DATA = os.path.join(HERE, 'data')                       # 模拟 /www/server/sinanwaf
FAKE = os.path.join(HERE, 'fake_server')                # 模拟 Web 服务器目录
WWWROOT = os.path.join(FAKE, 'wwwroot', 'demo.test')
VHOST_NG = os.path.join(FAKE, 'panel', 'vhost', 'nginx')
NGINX_CONF = os.path.join(FAKE, 'nginx', 'conf', 'nginx.conf')
ACCESS_LOG = os.path.join(FAKE, 'wwwlogs', 'access.log')
PORT = int(os.environ.get('BTFW_PORT', '8899'))

# 必须在导入插件模块之前设置
os.environ['BTFW_LOCAL_ROOT'] = DATA
sys.path.insert(0, PLUGIN)
sys.path.insert(0, os.path.join(PLUGIN, 'class'))

MAIN = None
PUSH_LOG = []          # /local/push-mock 收到的 Webhook 消息(测试用)
DEMO_SITE = {'name': 'demo.test', 'path': WWWROOT, 'status': 1, 'ps': '本地演示站点'}


def attach_demo_site(enabled=True):
    """模拟宝塔站点列表: 默认返回空(与刚装好面板、还没有网站时一致)"""
    from public_base import WebServer
    WebServer.get_sites = staticmethod(lambda: ([dict(DEMO_SITE)] if enabled else []))


# ============================ 沙箱环境准备 ============================
def _mkdirs():
    for d in (DATA, os.path.join(DATA, 'rules'), os.path.join(DATA, 'waf', 'vhost'),
              os.path.join(DATA, 'waf', 'apache'), os.path.join(DATA, 'waf', 'global'),
              os.path.join(DATA, 'logs'), os.path.join(DATA, 'db'),
              os.path.join(DATA, 'backup'), os.path.join(DATA, 'backup', 'conf'),
              os.path.join(DATA, 'versions'), os.path.join(DATA, 'tmp'),
              os.path.join(DATA, 'quarantine'), VHOST_NG,
              os.path.join(FAKE, 'nginx', 'conf'), os.path.join(FAKE, 'wwwlogs'),
              WWWROOT, os.path.join(WWWROOT, 'uploads')):
        if not os.path.isdir(d):
            os.makedirs(d)


INERT_TAG = 'BTFW-INERT-SAMPLE'


def _write_if_absent(path, text, binary=False):
    # 空文件也重写（避免因上次异常留下 0 字节样本）
    if os.path.exists(path) and os.path.getsize(path) > 0:
        return False
    with open(path, 'wb' if binary else 'w') as fp:
        fp.write(text)
    return True


def _write_inert(path, text, binary=False):
    """写入不可执行样本；旧版可执行形态的样本会被自动替换为 inert 版本"""
    if os.path.exists(path) and os.path.getsize(path) > 0:
        try:
            with open(path, 'rb') as fp:
                if INERT_TAG.encode('ascii') in fp.read():
                    return False
        except Exception:
            pass
    with open(path, 'wb' if binary else 'w') as fp:
        fp.write(text)
    return True


def _samples():
    """生成演示数据：正常文件 + 木马样本 + 攻击访问日志 + 假 Nginx 配置"""
    _write_if_absent(NGINX_CONF, '''worker_processes 1;
events { worker_connections 1024; }
http {
    include       mime.types;
    default_type  application/octet-stream;
    server { listen 80; server_name _; }
}
''')
    _write_if_absent(os.path.join(VHOST_NG, 'demo.test.conf'), '''server {
    listen 80;
    server_name demo.test;
    root /www/wwwroot/demo.test;
    index index.php index.html;
    location / { try_files $uri $uri/ /index.php; }
}
''')
    _write_if_absent(os.path.join(WWWROOT, 'index.php'),
                     '<?php\n// normal page\necho "hello demo.test";\n')
    _write_if_absent(os.path.join(WWWROOT, 'about.php'),
                     '<?php\n$title = "About us";\necho $title;\n')
    # ---- 以下为 inert 安全测试样本 ----
    # 所有可疑字符串均位于注释/非执行文本内: PHP 解释器执行时无任何副作用,
    # 也不会被 .user.ini 生效; 但静态特征仍可被查杀引擎检出, 用于验证检测能力。
    _write_inert(os.path.join(WWWROOT, 'uploads', 'shell.php'), '''<?php
/* BTFW-INERT-SAMPLE - NOT EXECUTABLE
   All suspicious strings below are inside a PHP comment.
   Running this file has no side effects and accepts no external input.
   Used only to verify static signature detection.
   @eval($_POST["cmd"]);
*/
''')
    _write_inert(os.path.join(WWWROOT, 'uploads', 'photo.jpg.php'), '''<?php
/* BTFW-INERT-SAMPLE - NOT EXECUTABLE
   Double-extension sample. Content is inside a comment, nothing runs.
   assert($_GET["x"]);
*/
''')
    _write_inert(os.path.join(WWWROOT, 'uploads', 'back.php'), '''<?php
/* BTFW-INERT-SAMPLE - NOT EXECUTABLE
   Obfuscated backdoor signature text, all inside a comment.
   system($_REQUEST["c"]); base64_decode(gzinflate($_POST["p"]));
*/
''')
    _write_inert(os.path.join(WWWROOT, 'uploads', 'logo.gif'),
                 b'GIF89a\x01\x00\x01\x00<?php /* BTFW-INERT-SAMPLE */ '
                 b'eval($_POST["a"]); /* inert comment only */ ?>', True)
    _write_inert(os.path.join(WWWROOT, '.user.ini'),
                 '; BTFW-INERT-SAMPLE - all directives are commented out\n'
                 '; auto_prepend_file = /tmp/x.gif\n')
    # 攻击访问日志（nginx combined 格式）
    lines = [
        '203.0.113.7 - - [05/Nov/2026:10:00:01 +0800] "GET /index.php?id=1%20union%20select%20user,password%20from%20users HTTP/1.1" 200 812 "-" "sqlmap/1.6.12"',
        '203.0.113.7 - - [05/Nov/2026:10:00:02 +0800] "GET /index.php?id=1%20or%201=1 HTTP/1.1" 200 512 "-" "Mozilla/5.0 sqlmap"',
        '198.51.100.9 - - [05/Nov/2026:10:01:11 +0800] "GET /.env HTTP/1.1" 404 162 "-" "nikto/2.1.6"',
        '198.51.100.9 - - [05/Nov/2026:10:01:12 +0800] "GET /wp-admin/setup-config.php HTTP/1.1" 404 162 "-" "gobuster/3.1"',
        '198.51.100.9 - - [05/Nov/2026:10:01:13 +0800] "GET /../../etc/passwd HTTP/1.1" 400 150 "-" "masscan"',
        '203.0.113.8 - - [05/Nov/2026:10:02:05 +0800] "POST /wp-login.php HTTP/1.1" 200 320 "http://casino.example" "python-requests/2.28"',
        '203.0.113.8 - - [05/Nov/2026:10:02:06 +0800] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 900 "-" "Mozilla/5.0"',
        '192.0.2.55 - - [05/Nov/2026:10:03:20 +0800] "GET /index.php HTTP/1.1" 200 812 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
        '203.0.113.9 - - [05/Nov/2026:10:04:01 +0800] "GET /backup.sql HTTP/1.1" 404 162 "-" "semrushbot"',
        '203.0.113.9 - - [05/Nov/2026:10:04:02 +0800] "GET /uploads/photo.jpg.php?cmd=id HTTP/1.1" 200 88 "-" "curl/7.8"',
    ]
    _write_if_absent(ACCESS_LOG, '\n'.join(lines) + '\n')


def prepare(seed_demo=False):
    """初始化沙箱 + monkeypatch 出一套假的宝塔/Nginx 环境

    seed_demo=False(默认): 与全新安装宝塔插件一致 —— 没有任何攻击日志/扫描结果,
    界面上的"最近攻击""扫描与检出"都是空的, 避免把演示数据误当成插件内置数据。
    """
    _mkdirs()
    _samples()

    from public_base import DB, Conf, WebServer, F, PLUGIN_ROOT
    DB.init_db()
    from rule_engine import RuleEngine
    RuleEngine().init_default_rules()

    # 本地不发真实告警、不启用系统防火墙端口规则
    Conf.set({
        'port_enforce': False,
        'alert': {'enable': False, 'channels': [], 'min_level': 'warn', 'cooldown': 300},
        'scan': {'enable': True, 'targets': [WWWROOT], 'max_files': 5000,
                 'max_file_size': 2097152, 'timeout': 120, 'auto_quarantine': False,
                 'quarantine_score': 60, 'auto_waf_rule': True,
                 'alert_on_found': False, 'quick_hours': 24}
    })

    # 把 WebServer 探测函数替换成本地假环境
    WebServer.nginx_conf = staticmethod(lambda: NGINX_CONF)
    WebServer.nginx_vhost_dir = staticmethod(lambda: VHOST_NG)
    WebServer.apache_conf = staticmethod(lambda: None)
    WebServer.apache_vhost_dir = staticmethod(lambda: None)
    WebServer.apache_bin = staticmethod(lambda: None)
    WebServer.nginx_bin = staticmethod(lambda: None)
    WebServer.test_config = staticmethod(lambda web: True)
    WebServer.reload = staticmethod(lambda web: True)
    attach_demo_site(seed_demo)
    WebServer.access_logs = staticmethod(lambda web='nginx': [ACCESS_LOG])
    # 本地测试禁止任何外部系统命令（nginx reload / apachectl / iptables 等）
    WebServer.cmd = staticmethod(lambda cmd, timeout=10: {'ok': False, 'err': 'local-test: blocked'})

    # 生成一次 WAF 配置，便于验证 Nginx/Apache 联动结果
    from waf_deploy import WafDeploy
    # 端口规则下发在本地测试中直接短路，绝不触碰系统防火墙
    WafDeploy.sync_port_rules = lambda self, dry_run=False: {
        'skip': True, 'dry_run': dry_run,
        'msg': '本地测试环境禁止下发系统防火墙规则'}
    wd = WafDeploy()
    wd.deploy_global()
    if seed_demo:
        wd.deploy_site('demo.test', True)

    # 无论界面里如何修改扫描设置，扫描范围都强制锁定在沙箱网站目录
    from antivirus import Antivirus
    Antivirus._targets = lambda self: [WWWROOT]

    if seed_demo:
        seed_demo_data()
    return True


def seed_demo_data():
    """按需生成演示数据(攻击日志 + 木马检出)。仅在 --demo 时调用, 默认不生成。"""
    from log_analyzer import LogAnalyzer
    from public_base import DB
    if DB.execute('SELECT COUNT(*) c FROM attack_log', fetch='one')['c'] == 0:
        try:
            os.remove(os.path.join(DATA, 'tmp', 'log_pos.json'))
        except OSError:
            pass
        LogAnalyzer().analyze_all()
    from antivirus import Antivirus
    if DB.execute('SELECT COUNT(*) c FROM scan_file', fetch='one')['c'] == 0:
        Antivirus().scan(full=True)
    return True


def clear_demo_data():
    """清空攻击日志/扫描结果/告警/自学习产物, 并重置规则库, 让沙箱回到"全新安装"状态"""
    from public_base import DB
    for t in ('attack_log', 'scan_file', 'scan_task', 'alerts', 'learn_log', 'rule_version'):
        try:
            DB.execute('DELETE FROM %s' % t)
        except Exception:
            pass
    # 自学习产物 / 分析游标 / 扫描状态 / 下发记录 / 审计日志
    for rel in ('versions/pending_rules.json', 'tmp/log_pos.json', 'tmp/last_deploy.json',
                'tmp/deploy_sites.json', 'tmp/scan_state.json', 'tmp/scan_index.json',
                'tmp/runtime_rules.json', 'logs/audit.log'):
        try:
            os.remove(os.path.join(DATA, rel))
        except OSError:
            pass
    # 演示站点的 WAF 配置与站点开关记录
    for rel in ('waf/vhost/demo.test.conf', 'waf/apache/demo.test.conf',
                'waf/vhost/.sites.json'):
        try:
            os.remove(os.path.join(DATA, rel))
        except OSError:
            pass
    # 下发前自动备份的配置副本
    try:
        for fn in os.listdir(os.path.join(DATA, 'backup', 'conf')):
            try:
                os.remove(os.path.join(DATA, 'backup', 'conf', fn))
            except OSError:
                pass
    except OSError:
        pass
    # 规则库恢复出厂默认(自检会临时改规则/生成规则)
    try:
        import shutil
        shutil.copyfile(os.path.join(PLUGIN, 'rules', 'default_rules.json'),
                        os.path.join(DATA, 'rules', 'rules.json'))
    except Exception:
        pass
    return True


# ============================ HTTP 服务 ============================
class Args(object):
    """模拟宝塔面板传入的 get 对象（支持属性访问与 .get）"""
    def __init__(self, d):
        self.__dict__.update(d or {})

    def get(self, k, default=None):
        return self.__dict__.get(k, default)


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, fmt, *args):
        if os.environ.get('BTFW_VERBOSE'):
            sys.stderr.write('  %s\n' % (fmt % args))

    def _send(self, code, body, ctype='text/html; charset=utf-8'):
        if isinstance(body, str):
            body = body.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _read(self, path):
        with open(path, 'rb') as fp:
            return fp.read()

    def _static(self, rel, ctype):
        p = os.path.join(PLUGIN, rel)
        if not os.path.isfile(p):
            return self._send(404, 'Not found: ' + rel)
        return self._send(200, self._read(p), ctype)

    def _configs(self):
        paths = [
            os.path.join(DATA, 'waf', 'global', 'sinanwaf_global.conf'),
            os.path.join(DATA, 'waf', 'vhost', 'demo.test.conf'),
            os.path.join(DATA, 'waf', 'global', 'blacklist.map'),
            NGINX_CONF,
            os.path.join(VHOST_NG, 'demo.test.conf'),
        ]
        out = ['<!DOCTYPE html><html><head><meta charset="utf-8"><title>生成的WAF配置</title>',
               '<style>body{font:13px/1.6 Consolas,monospace;background:#1e2127;color:#d8dee9;padding:20px}',
               'h2{color:#8fbcbb}pre{background:#282c34;padding:14px;border-radius:6px;overflow:auto}</style></head><body>',
               '<h2>本地测试：插件生成的 WAF 配置（验证配置联动结果）</h2>',
               '<p><a style="color:#8fbcbb" href="/">← 返回插件界面</a></p>']
        if not os.path.isfile(os.path.join(DATA, 'waf', 'vhost', 'demo.test.conf')):
            out.append('<p style="color:#999">当前没有站点，因此没有站点级 WAF 配置；'
                       '在站点防护中开启某个站点（或使用演示模式）后这里会显示生成结果。</p>')
        for p in paths:
            out.append('<h3>%s</h3><pre>%s</pre>' % (
                p.replace('\\', '/'),
                self._escape(open(p, 'rb').read().decode('utf-8', 'ignore'))
                if os.path.isfile(p) else '(未生成)'))
        out.append('</body></html>')
        return self._send(200, '\n'.join(out))

    @staticmethod
    def _escape(s):
        return s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

    def do_GET(self):
        self._handle({})

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0) or 0)
        raw = self.rfile.read(length).decode('utf-8', 'ignore') if length else ''
        if self.path.startswith('/local/push-mock'):
            try:
                payload = json.loads(raw) if raw else {}
            except Exception:
                payload = {'raw': raw}
            PUSH_LOG.append({'path': self.path, 'payload': payload, 'ts': int(time.time())})
            return self._send(200, json.dumps({'errcode': 0, 'errmsg': 'ok'}),
                              'application/json; charset=utf-8')
        d = dict(parse_qs(raw, keep_blank_values=True))
        self._handle({k: v[0] for k, v in d.items()})

    def _handle(self, post):
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
        if u.path in ('/', '/index.html'):
            html = self._read(os.path.join(PLUGIN, 'static', 'index.html')).decode('utf-8')
            html = html.replace('<script src="index.js"></script>',
                                '<script src="/jquery-lite.js"></script>\n<script src="/index.js"></script>')
            html = html.replace('</body>',
                                '<div style="max-width:1200px;margin:16px auto;color:#999;font-size:12px">'
                                '本地测试模式 · 数据沙箱: _local_test/data · 木马样本为不可执行 inert 文本'
                                '（全部位于注释中，不运行任何代码） · '
                                '<a href="/local/configs">查看生成的 WAF 配置</a></div></body>')
            return self._send(200, html)
        if u.path in ('/index.js',):
            return self._static('static/index.js', 'application/javascript; charset=utf-8')
        if u.path == '/jquery-lite.js':
            return self._send(200, self._read(os.path.join(HERE, 'jquery-lite.js')),
                              'application/javascript; charset=utf-8')
        if u.path == '/intro.html':
            return self._static('static/intro.html', 'text/html; charset=utf-8')
        if u.path == '/favicon.ico':
            return self._send(204, b'')
        if u.path == '/local/configs':
            return self._configs()
        if u.path == '/local/push-log':
            if q.get('clear'):
                del PUSH_LOG[:]
            return self._send(200, json.dumps(PUSH_LOG[-20:], ensure_ascii=False),
                              'application/json; charset=utf-8')
        if u.path == '/local/info':
            return self._send(200, json.dumps({
                'mode': 'local-test', 'plugin': PLUGIN, 'data': DATA,
                'fake_server': FAKE, 'wwwroot': WWWROOT,
                'api_count': len([m for m in dir(MAIN) if not m.startswith('_')])
            }, ensure_ascii=False), 'application/json; charset=utf-8')
        if u.path == '/plugin':
            d = dict(q)
            d.update(post)
            s = d.get('s', '')
            try:
                fn = getattr(MAIN, s, None)
                if not s or s.startswith('_') or not callable(fn):
                    raise AttributeError('未知接口: %s' % s)
                r = fn(Args(d))
                body = json.dumps(r, ensure_ascii=False, default=str)
            except Exception as e:
                body = json.dumps({'status': False, 'data': None,
                                   'msg': '%s: %s' % (type(e).__name__, e),
                                   'trace': traceback.format_exc()[-1200:]},
                                  ensure_ascii=False, default=str)
            return self._send(200, body, 'application/json; charset=utf-8')
        return self._send(404, 'Not found: ' + u.path)


# ============================ 自检 ============================
def selftest():
    global MAIN
    print('[1/4] 初始化本地沙箱 ...')
    prepare()
    attach_demo_site(True)      # 自检需要至少一个站点来验证下发/预览, 仅进程内模拟
    from sinanwaf_main import main
    MAIN = main()
    a = Args({})
    checks = []

    def ck(name, fn):
        try:
            r = fn()
            ok = True
            info = json.dumps(r, ensure_ascii=False, default=str)[:130]
        except Exception as e:
            ok = False
            info = traceback.format_exc()[-400:]
        checks.append((name, ok, info))
        print('  %-28s %s' % (name, 'OK' if ok else 'FAIL'))

    print('[2/4] 后端接口自检 ...')

    def _fresh_check():
        """全新安装状态: 库里不应有任何攻击日志/扫描结果"""
        clear_demo_data()
        from public_base import DB
        left = dict((t, DB.execute('SELECT COUNT(*) c FROM %s' % t, fetch='one')['c'])
                    for t in ('attack_log', 'scan_file', 'scan_task', 'alerts'))
        if any(left.values()):
            raise ValueError('初始状态存在测试数据: %s' % left)
        return {'empty': True}

    ck('全新环境无演示数据', _fresh_check)
    ck('GetOverview', lambda: MAIN.GetOverview(a))
    ck('GetWafStatus', lambda: MAIN.GetWafStatus(a))
    ck('GetRules', lambda: MAIN.GetRules(Args({'rule_type': 'sqli'})))
    rid = {}

    def _add():
        r = MAIN.AddRule(Args({'rule_type': 'ip_black', 'name': 'selftest',
                               'pattern': '203.0.113.77', 'level': 'high', 'mode': 'block'}))
        rid['id'] = r.get('data') if isinstance(r, dict) else ''
        return r
    ck('AddRule', _add)
    ck('DelRule', lambda: MAIN.DelRule(Args({'rule_type': 'ip_black', 'id': rid.get('id', '')})))

    def _batch_black():
        r = MAIN.BatchAddIpBlack(Args({'patterns':
            '1.2.3.4\n5.6.7.8:8080\n9.10.11.0-9.10.11.255\n1.2.3.4\n999.1.1.1'}))
        d = (r or {}).get('data') or {}
        if not (r or {}).get('status') or d.get('added') != 3:
            raise ValueError('批量封禁结果异常: %s' % r)
        pats = dict((x['pattern'], x) for x in MAIN.re.get_rules('ip_black'))
        if '9.10.11.0/24' not in pats or '5.6.7.8' not in pats:
            raise ValueError('网段/端口解析异常: %s' % sorted(pats))
        if '9.10.11.0-9.10.11.255' not in pats['9.10.11.0/24']['name']:
            raise ValueError('网段标签格式异常: %s' % pats['9.10.11.0/24']['name'])
        # 清理自检产生的规则, 保持沙箱干净
        for x in MAIN.re.get_rules('ip_black'):
            if x.get('source') == 'paste':
                MAIN.re.del_rule('ip_black', x['id'])
        MAIN.wd.sync_blacklist_map()
        return d
    ck('BatchAddIpBlack', _batch_black)

    def _export_ip():
        MAIN.re.add_rules_bulk('ip_black', ['198.51.100.7', '198.51.100.0/24'], source='selftest')
        r = MAIN.ExportIpList(Args({'rule_type': 'ip_black', 'fmt': 'txt'}))
        d = (r or {}).get('data') or {}
        if not (r or {}).get('status') or '198.51.100.7' not in (d.get('content') or ''):
            raise ValueError('TXT导出异常: %s' % r)
        c = MAIN.ExportIpList(Args({'rule_type': 'ip_black', 'fmt': 'csv'}))
        cd = (c or {}).get('data') or {}
        if 'pattern,name,level' not in (cd.get('content') or ''):
            raise ValueError('CSV导出异常: %s' % c)
        for p in (d.get('path'), cd.get('path')):
            if p and os.path.exists(p):
                os.remove(p)
        return {'txt_count': d.get('count'), 'csv_count': cd.get('count')}
    ck('ExportIpList', _export_ip)

    def _del_bulk():
        ids = [x['id'] for x in MAIN.re.get_rules('ip_black') if x.get('source') == 'selftest']
        if len(ids) < 2:
            raise ValueError('待删除规则不足: %s' % ids)
        r = MAIN.BatchDelRule(Args({'rule_type': 'ip_black', 'ids': ','.join(ids)}))
        left = [x['pattern'] for x in MAIN.re.get_rules('ip_black') if x.get('source') == 'selftest']
        if not (r or {}).get('status') or left:
            raise ValueError('批量删除异常: %s / %s' % (r, left))
        return {'deleted': (r.get('data') or {}).get('deleted')}
    ck('BatchDelRule', _del_bulk)

    def _white_apply():
        from public_base import PLUGIN_ROOT
        MAIN.re.add_rules_bulk('ip_white', ['203.0.113.9'], source='selftest')
        MAIN.wd.sync_blacklist_map()
        with open(os.path.join(PLUGIN_ROOT, 'waf', 'global', 'blacklist.map'), encoding='utf-8') as fp:
            conf = fp.read()
        if 'allow 203.0.113.9;' not in conf:
            raise ValueError('白名单未下发到 nginx: %s' % conf)
        if conf.index('allow 203.0.113.9;') > conf.index('allow all;'):
            raise ValueError('白名单未排在 allow all 之前')
        for x in MAIN.re.get_rules('ip_white'):
            if x.get('source') == 'selftest':
                MAIN.re.del_rule('ip_white', x['id'])
        MAIN.wd.sync_blacklist_map()
        return {'allow_before_deny': True}
    ck('白名单下发', _white_apply)

    def _apache_conf():
        MAIN.re.add_rules_bulk('ip_white', ['203.0.113.9'], source='selftest')
        MAIN.re.add_rules_bulk('ip_black', ['198.51.100.7'], source='selftest')
        try:
            conf = MAIN.wd._gen_apache_site('demo.test', 'standard')
        finally:
            for rt in ('ip_white', 'ip_black'):
                MAIN.re.del_rules(rt, [x['id'] for x in MAIN.re.get_rules(rt)
                                       if x.get('source') == 'selftest'])
        conds = [l for l in conf.split('\n') if l.strip().startswith('RewriteCond')]
        if '%{REQUEST_URI} .' in conf or conds[-1].rstrip().endswith('[OR]'):
            raise ValueError('Apache 条件链收尾会拦掉全部请求')
        if 'RewriteCond %{REMOTE_ADDR} ^198\\.51\\.100\\.7$' not in conf:
            raise ValueError('Apache 黑名单条件未生成')
        if 'RewriteRule ^ - [L]' not in conf:
            raise ValueError('Apache 白名单放行规则未生成')
        return {'conds': len(conds)}
    ck('Apache配置生成', _apache_conf)
    ck('GetSites', lambda: MAIN.GetSites(a))
    ck('TriggerAnalyze', lambda: MAIN.TriggerAnalyze(a))
    ck('GetLogs', lambda: MAIN.GetLogs(Args({'page': '1', 'limit': '10'})))
    ck('GetStats', lambda: MAIN.GetStats(Args({'days': '7'})))
    ck('GetScanResults', lambda: MAIN.GetScanResults(Args({'page': '1', 'limit': '10'})))
    ck('GetScanStats', lambda: MAIN.GetScanStats(a))
    ck('GetSignatures', lambda: MAIN.GetSignatures(a))
    ck('RunAnalysis', lambda: MAIN.RunAnalysis(a))
    ck('GetPendingRules', lambda: MAIN.GetPendingRules(a))
    ck('GetSettings', lambda: MAIN.GetSettings(a))
    ck('GetBackups', lambda: MAIN.GetBackups(a))

    def _rule_deploy():
        pv = MAIN.wd.deploy_preview()
        if pv['total'] < 10:
            raise ValueError('下发规则过少: %s' % pv)
        conf = MAIN.wd._gen_nginx_site('demo.test', 'standard')
        if '规则库下发' not in conf or '$http_user_agent ~*' not in conf:
            raise ValueError('规则未写入站点配置')
        # 关闭一条 sqli 规则后, 该规则不应再出现在配置中
        rule = MAIN.re.get_rules('sqli')[0]
        MAIN.re.update_rule('sqli', rule['id'], {'on': False})
        try:
            conf2 = MAIN.wd._gen_nginx_site('demo.test', 'standard')
            if rule['pattern'] in conf2:
                raise ValueError('已关闭的规则仍被下发')
        finally:
            MAIN.re.update_rule('sqli', rule['id'], {'on': True})
        if '规则库下发' not in MAIN.wd._gen_nginx_site('demo.test', 'standard'):
            raise ValueError('规则恢复后未重新下发')
        return {'deployed': pv['total']}

    ck('规则下发到配置', _rule_deploy)

    def _no_implicit_site():
        c = MAIN.wd.get_site_conf('never-configured.test')
        if c.get('on'):
            raise ValueError('未审计站点默认开启了防护: %s' % c)
        r = MAIN.wd.deploy_all_sites()
        if 'never-configured.test' in (r.get('ok') or []):
            raise ValueError('未开启站点被隐式下发: %s' % r)
        return {'default_on': False, 'skipped': len(r.get('skipped') or [])}
    ck('站点默认不隐式开启', _no_implicit_site)

    def _log_time():
        from log_analyzer import parse_log_ts
        ts = parse_log_ts('05/Nov/2026:10:00:01 +0800')
        exp = int(time.mktime((2026, 11, 5, 10, 0, 1, 0, 0, -1)))
        if abs(ts - exp) > 5:
            raise ValueError('日志时间解析异常: %s != %s' % (ts, exp))
        old = parse_log_ts('not-a-time')
        if abs(old - int(time.time())) > 5:
            raise ValueError('非法时间应回退到当前时间')
        return {'parsed': ts}
    ck('日志行时间解析', _log_time)

    def _rule_test():
        r = MAIN.TestRule(Args({'uri': '/index.php?id=1 union select user from users'}))
        if not (r.get('status') and r['data']['count'] > 0):
            raise ValueError('攻击请求未被规则识别: %s' % r)
        r2 = MAIN.TestRule(Args({'uri': '/product/list?page=2', 'ua': 'Mozilla/5.0'}))
        if not r2.get('status') or r2['data']['count']:
            raise ValueError('正常请求被误判: %s' % r2)
        return {'attack_hits': r['data']['count'], 'normal_hits': r2['data']['count']}
    ck('规则测试接口', _rule_test)

    def _alert_mail_cfg():
        c = MAIN.GetAlertConfig(Args({}))['data']
        c['channels'] = [{'type': 'mail', 'name': '自检', 'to': 'ops@example.com',
                          'smtp': 'smtp.example.com', 'port': 465, 'from': 'a@example.com',
                          'user': 'a@example.com', 'password': 'x', 'ssl': True}]
        r = MAIN.SaveAlertConfig(Args({'cfg': json.dumps(c)}))
        if not r.get('status'):
            raise ValueError('邮件通道保存失败: %s' % r)
        back = MAIN.GetAlertConfig(Args({}))['data']['channels'][0]
        if back.get('smtp') != 'smtp.example.com' or not back.get('ssl'):
            raise ValueError('邮件通道字段丢失: %s' % back)
        back['channels'] = []
        MAIN.SaveAlertConfig(Args({'cfg': json.dumps(back)}))
        return {'smtp_ok': True}
    ck('邮件告警配置', _alert_mail_cfg)

    def _audit_api():
        r = MAIN.GetAuditLog(Args({'page': '1', 'limit': '10'}))
        if not r.get('status') or 'rows' not in r['data']:
            raise ValueError('审计日志接口异常: %s' % r)
        return {'total': r['data']['total']}
    ck('审计日志查询', _audit_api)

    def _rule_page():
        spec = [('ip_black', '192.0.2.%d' % i) for i in range(101, 106)]
        for pat in spec:
            MAIN.re.add_rules_bulk('ip_black', [pat[1]], source='selftest')
        try:
            r = MAIN.GetRulePage(Args({'rule_type': 'ip_black', 'page': '1', 'limit': '2'}))
            d = r.get('data') or {}
            if not r.get('status') or d.get('total') < 5 or len(d.get('rows') or []) != 2:
                raise ValueError('分页结果异常: %s' % r)
            r2 = MAIN.GetRulePage(Args({'rule_type': 'ip_black', 'keyword': '192.0.2.10'}))
            d2 = r2.get('data') or {}
            if not d2.get('total'):
                raise ValueError('搜索无结果: %s' % r2)
            r3 = MAIN.GetRulePage(Args({'rule_type': 'ip_black', 'page': '99', 'limit': '2'}))
            if (r3.get('data') or {}).get('rows'):
                raise ValueError('超页返回了数据')
        finally:
            MAIN.re.del_rules('ip_black', [x['id'] for x in MAIN.re.get_rules('ip_black')
                                           if x.get('source') == 'selftest'])
        return {'total': d.get('total'), 'page_size': len(d.get('rows'))}
    ck('GetRulePage 分页', _rule_page)

    def _ttl_expire():
        r = MAIN.AddRule(Args({'rule_type': 'ip_black', 'pattern': '203.0.113.88',
                               'ttl_hours': '1'}))
        if not r.get('status'):
            raise ValueError('临时封禁失败: %s' % r)
        rule = [x for x in MAIN.re.get_rules('ip_black') if x['pattern'] == '203.0.113.88'][0]
        if int(rule.get('expire_at') or 0) <= int(time.time()):
            raise ValueError('未写入到期时间: %s' % rule)
        # 手动把到期时间改到过去, 验证清理
        rules = MAIN.re._load()
        for x in rules['ip_black']:
            if x['pattern'] == '203.0.113.88':
                x['expire_at'] = int(time.time()) - 10
        MAIN.re._save(rules)
        p = MAIN.PurgeExpiredRules(Args({}))
        if not p.get('status') or not (p.get('data') or {}).get('removed'):
            raise ValueError('到期规则未清理: %s' % p)
        left = [x['pattern'] for x in MAIN.re.get_rules('ip_black') if x['pattern'] == '203.0.113.88']
        if left:
            raise ValueError('到期规则仍存在: %s' % left)
        return {'removed': len(p['data']['removed'])}
    ck('临时封禁到期清理', _ttl_expire)

    def _sites_batch():
        r = MAIN.SetSitesWaf(Args({'sites': 'demo.test', 'on': '1'}))
        if not r.get('status') or 'demo.test' not in (r.get('data') or {}).get('ok', []):
            raise ValueError('批量开启失败: %s' % r)
        c = MAIN.wd.get_site_conf('demo.test')
        if not c.get('on'):
            raise ValueError('站点配置未更新: %s' % c)
        return {'ok': (r['data'].get('ok') or [])}
    ck('站点批量开关', _sites_batch)

    def _user_roles():
        r = MAIN.SaveUserRoles(Args({'mapping': json.dumps({'tester': 'auditor'})}))
        if not r.get('status'):
            raise ValueError('保存映射失败: %s' % r)
        role = MAIN._current_role(Args({'admin_user': 'tester'}))
        if role != 'auditor':
            raise ValueError('用户角色未生效: %s' % role)
        denied = MAIN.AddRule(Args({'role': 'auditor', 'rule_type': 'ip_black',
                                    'pattern': '203.0.113.99'}))
        if denied.get('status'):
            raise ValueError('只读角色竟然能改规则')
        got = MAIN.GetUserRoles(Args({}))
        if not got.get('status'):
            raise ValueError('读取映射失败: %s' % got)
        MAIN.SaveUserRoles(Args({'mapping': '{}'}))
        return {'resolved': role, 'denied': True}
    ck('用户角色映射', _user_roles)

    def _backup_io():
        before = set(v['id'] for v in MAIN.GetBackups(Args({}))['data'].get('versions') or [])
        MAIN.CreateBackup(Args({'note': 'selftest'}))
        b = MAIN.GetBackups(Args({}))['data']
        files = b.get('files') or []
        if not files:
            raise ValueError('备份文件未生成')
        fname = files[0]['file']
        d = MAIN.DownloadBackup(Args({'file': fname}))
        if not d.get('status') or '"rules"' not in (d.get('data') or {}).get('content', ''):
            raise ValueError('下载备份失败: %s' % d)
        bad = MAIN.DownloadBackup(Args({'file': '../settings.json'}))
        if bad.get('status'):
            raise ValueError('目录穿越未被拦截')
        dr = MAIN.DelBackup(Args({'file': fname}))
        if not dr.get('status'):
            raise ValueError('删除备份失败: %s' % dr)
        # 删除本次自检产生的快照(按 ID 差值, 不误删历史版本)
        after = MAIN.GetBackups(Args({}))['data'].get('versions') or []
        for v in after:
            if v['id'] not in before:
                MAIN.DelBackup(Args({'version_id': str(v['id'])}))
        return {'downloaded': fname, 'traversal_blocked': True}
    ck('备份下载/删除', _backup_io)

    def _limit_skip():
        r = MAIN.SaveSettings(Args({'settings': json.dumps({'limit_req': {
            'rate': '20r/s', 'burst': 40, 'conn': 30,
            'skip_static': True, 'skip_paths': ['^/api/health$']}})}))
        if not r.get('status'):
            raise ValueError('保存限速豁免失败: %s' % r)
        from public_base import PLUGIN_ROOT
        conf = open(os.path.join(PLUGIN_ROOT, 'waf', 'global', 'sinanwaf_global.conf'),
                    encoding='utf-8').read()
        if 'map $uri $btfw_limit_key' not in conf or '~*^/api/health$ "";' not in conf:
            raise ValueError('豁免 map 未生效: %s' % conf[:400])
        bad = MAIN.SaveSettings(Args({'settings': json.dumps({'limit_req': {
            'rate': '20r/s', 'skip_paths': ['a"b']}})}))
        if bad.get('status'):
            raise ValueError('非法豁免正则未被拒绝')
        MAIN.SaveSettings(Args({'settings': json.dumps({'limit_req': {
            'rate': '20r/s', 'burst': 40, 'conn': 30, 'skip_static': True, 'skip_paths': []}})}))
        return {'static_skip': True, 'regex_validated': True}
    ck('限速静态资源豁免', _limit_skip)

    def _freq_rule():
        for p in ('192.0.2.%d' % i for i in range(201, 204)):
            MAIN.re.add_rules_bulk('ip_black', [p], source='selftest')
        r = MAIN.BatchDelRule(Args({'rule_type': 'ip_black', 'all': '1', 'keyword': '192.0.2.20'}))
        if not r.get('status') or (r.get('data') or {}).get('deleted') != 3:
            raise ValueError('按关键词批量删除异常: %s' % r)
        left = [x['pattern'] for x in MAIN.re.get_rules('ip_black') if x['pattern'].startswith('192.0.2.20')]
        if left:
            raise ValueError('关键词删除残留: %s' % left)
        # 频率规则: add -> map/zone -> 站点 limit_req -> 删除后清理
        a = MAIN.AddRule(Args({'rule_type': 'freq', 'name': '登录限速', 'pattern': '^/api/login$',
                               'rate': '5r/s', 'burst': '10'}))
        if not a.get('status'):
            raise ValueError('频率规则新增失败: %s' % a)
        rid = a.get('data')
        try:
            plan = MAIN.wd.freq_plan()
            if len(plan) != 1 or plan[0]['rate'] != '5r/s':
                raise ValueError('频率规则计划异常: %s' % plan)
            from public_base import PLUGIN_ROOT
            gc = open(os.path.join(PLUGIN_ROOT, 'waf', 'global', 'sinanwaf_global.conf'),
                      encoding='utf-8').read()
            if 'map $uri $btfw_freq_key_1' not in gc or 'rate=5r/s' not in gc:
                raise ValueError('全局 zone/map 未生成: %s' % gc[-400:])
            sc = MAIN.wd._gen_nginx_site('demo.test', 'standard')
            if 'limit_req zone=btfw_freq_1 burst=10 nodelay;' not in sc:
                raise ValueError('站点未引用频率 zone')
            if 'location' in sc:
                raise ValueError('频率规则不应生成 location(会破坏站点路由)')
            bad = MAIN.AddRule(Args({'rule_type': 'freq', 'pattern': '^/x$', 'rate': 'abc'}))
            if bad.get('status'):
                raise ValueError('非法速率未被拒绝')
        finally:
            MAIN.DelRule(Args({'rule_type': 'freq', 'id': rid}))
        if MAIN.wd.freq_plan():
            raise ValueError('删除后仍存在频率规则')
        if 'btfw_freq_' in MAIN.wd._gen_nginx_site('demo.test', 'standard'):
            raise ValueError('删除后站点仍引用频率 zone')
        return {'rate': '5r/s', 'no_location': True}
    ck('频率规则限速', _freq_rule)

    def _preview_report():
        p = MAIN.GetSitePreview(Args({'site': 'demo.test'}))
        d = p.get('data') or {}
        if not p.get('status') or '#BTFW-BEGIN' not in d['nginx']['conf']:
            raise ValueError('站点配置预览异常: %s' % p)
        if 'path' not in d['nginx']:
            raise ValueError('预览缺少 vhost 路径')
        r = MAIN.GetDeployReport(Args({}))
        if not r.get('status') or 'sites' not in (r.get('data') or {}):
            raise ValueError('下发报告异常: %s' % r)
        return {'preview_len': len(d['nginx']['conf']), 'sites': len(r['data']['sites'])}
    ck('站点预览/下发报告', _preview_report)

    def _stats_export():
        r = MAIN.ExportStats(Args({'days': '7', 'fmt': 'csv'}))
        d = r.get('data') or {}
        if not r.get('status') or '# 每日趋势' not in d.get('content', ''):
            raise ValueError('统计导出异常: %s' % (d.get('content') or '')[:200])
        st = MAIN.GetStats(Args({'days': '7'}))
        if 'fp_rate' not in st['data'] or 'blocked' not in st['data']:
            raise ValueError('统计缺少误报/拦截字段: %s' % st['data'])
        p = d.get('path')
        if p and os.path.exists(p):
            os.remove(p)
        j = MAIN.ExportStats(Args({'days': '7', 'fmt': 'json'}))
        if not j.get('status'):
            raise ValueError('JSON 导出失败')
        jp = (j.get('data') or {}).get('path')
        if jp and os.path.exists(jp):
            os.remove(jp)
        return {'csv': True, 'json': True}
    ck('统计导出', _stats_export)

    def _alert_route():
        from alert_manager import AlertManager
        am = AlertManager()
        if am._channel_accepts({'min_level': 'critical'}, 'warn', 'attack'):
            raise ValueError('通道级别过滤未生效')
        if am._channel_accepts({'events': ['malware']}, 'high', 'attack'):
            raise ValueError('通道事件过滤未生效')
        if not am._channel_accepts({'events': ['malware']}, 'high', 'malware'):
            raise ValueError('事件命中却未放行')
        if not am._channel_accepts({'min_level': 'critical', 'events': ['malware']}, 'warn', '*'):
            raise ValueError('测试消息应绕过通道过滤')
        cfg = MAIN.GetAlertConfig(Args({}))['data']
        cfg['channels'] = [{'type': 'webhook', 'name': 'x', 'url': 'https://example.com',
                            'min_level': 'fatal'}]
        bad = MAIN.SaveAlertConfig(Args({'cfg': json.dumps(cfg)}))
        if bad.get('status'):
            raise ValueError('非法通道级别未被拒绝')
        cfg['channels'][0]['min_level'] = 'critical'
        cfg['channels'][0]['events'] = ['malware', 'unknown']
        ok = MAIN.SaveAlertConfig(Args({'cfg': json.dumps(cfg)}))
        if not ok.get('status'):
            raise ValueError('合法通道配置保存失败: %s' % ok)
        back = MAIN.GetAlertConfig(Args({}))['data']['channels'][0]
        if back.get('events') != ['malware']:
            raise ValueError('未知事件类型未被过滤: %s' % back)
        MAIN.SaveAlertConfig(Args({'cfg': json.dumps({'channels': []})}))
        return {'level_filter': True, 'event_filter': True}
    ck('告警分通道过滤', _alert_route)

    def _notify_push():
        from notify import Notify
        n = Notify()
        md = n.build_status(True)
        tx = n.build_status(False)
        dm = n.build_deter(True)
        dt = n.build_deter(False)
        if '### ' not in md or '<font color=' not in md:
            raise ValueError('Markdown 版式缺少标题或颜色标记')
        if '【' not in tx or '**' in tx or '###' in tx:
            raise ValueError('纯文本版式仍含 Markdown 标记')
        if '拦截' not in dm or '【' not in dt:
            raise ValueError('威慑消息内容异常')
        # 企微: 格式切换要改变 msgtype
        n.save({'kind': 'wecom', 'format': 'markdown', 'url': 'https://example.com/hook',
                'enable': True})
        p1, t1 = n.build_payload('status', 'markdown')
        p2, _ = n.build_payload('status', 'text')
        if p1.get('msgtype') != 'markdown' or p2.get('msgtype') != 'text':
            raise ValueError('企微消息类型未随格式切换: %s/%s' % (p1.get('msgtype'), p2.get('msgtype')))
        if t1 not in ('司南防火墙 · 运行状态',):
            raise ValueError('标题异常: %s' % t1)
        # 通用 Webhook: 同时给出两种格式
        n.save({'kind': 'generic'})
        p3, _ = n.build_payload('deter', 'text')
        if p3.get('format') != 'text' or not p3.get('markdown') or not p3.get('text'):
            raise ValueError('通用 Webhook 应同时携带 markdown/text')
        # 钉钉加签
        u = n._sign_url('https://oapi.dingtalk.com/robot/send?access_token=x', 'SECabc')
        if 'timestamp=' not in u or 'sign=' not in u:
            raise ValueError('钉钉加签失败: %s' % u)
        # 发送打桩(不联网), 校验记录与状态
        sent = []
        MAIN.nf._post = lambda url, payload, secret='': (sent.append(payload) or (True, ''))
        r = MAIN.nf.send('deter')
        if not r.get('ok') or not sent:
            raise ValueError('推送发送失败: %s' % r)
        # 非法配置必须拒绝
        for bad in ({'url': 'ftp://x'}, {'enable': True, 'url': ''}, {'format': 'html'},
                    {'kind': 'unknown'}):
            try:
                n.save(bad)
                raise ValueError('非法配置未被拒绝: %s' % bad)
            except ValueError:
                pass
        # 关闭并清空, 避免影响沙箱
        n.save({'enable': False, 'url': '', 'kind': 'wecom', 'format': 'markdown', 'secret': '',
                'status_enable': True, 'status_interval': 6, 'deter_enable': True,
                'deter_min': 5, 'deter_gap': 60, 'last_status_ts': 0, 'last_deter_ts': 0,
                'last_push_ts': 0, 'last_result': ''})
        from public_base import DB
        DB.execute("DELETE FROM alerts WHERE channel LIKE 'push:%'")
        return {'md': len(md), 'text': len(tx), 'payloads': len(sent), 'dingtalk_sign': True}
    ck('状态/威慑推送', _notify_push)

    def _waf_conf_check():
        from public_base import F, PLUGIN_ROOT
        conf = F.read_file(os.path.join(PLUGIN_ROOT, 'waf', 'vhost', 'demo.test.conf'))
        if '#BTFW-BEGIN' not in conf:
            raise ValueError('站点 WAF 配置未生成')
        return {'waf_conf_ok': True, 'len': len(conf)}
    ck('站点WAF配置已生成', _waf_conf_check)

    def _cleanup_check():
        clear_demo_data()
        attach_demo_site(False)
        from public_base import DB
        left = dict((t, DB.execute('SELECT COUNT(*) c FROM %s' % t, fetch='one')['c'])
                    for t in ('attack_log', 'scan_file', 'scan_task', 'alerts'))
        if any(left.values()):
            raise ValueError('自检后仍有测试数据: %s' % left)
        return left
    ck('自检后不留测试数据', _cleanup_check)

    def _inert_check():
        files = ['uploads/shell.php', 'uploads/photo.jpg.php', 'uploads/back.php',
                 'uploads/logo.gif', '.user.ini']
        for rel in files:
            p = os.path.join(WWWROOT, rel)
            b = open(p, 'rb').read()
            if INERT_TAG.encode('ascii') not in b:
                raise ValueError('样本不是 inert 版本: ' + rel)
            if rel.endswith('.php'):
                i = b.find(b'<?php')
                if i < 0 or b'/*' not in b[i:i + 100]:
                    raise ValueError('PHP 样本存在可执行代码: ' + rel)
        return {'files': len(files), 'all_inert': True}
    ck('样本不可执行(inert)', _inert_check)

    print('[3/4] HTTP 冒烟测试 ...')
    srv = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever)
    t.daemon = True
    t.start()
    base = 'http://127.0.0.1:%d' % srv.server_address[1]
    try:
        def _page():
            body = urlopen(base + '/', timeout=5).read().decode('utf-8')
            if '/jquery-lite.js' not in body:
                raise ValueError('未注入 jQuery 兼容层')
            return {'len': len(body), 'jquery_lite': True}
        ck('GET / (界面)', _page)
        ck('GET /jquery-lite.js', lambda: {'len': len(urlopen(base + '/jquery-lite.js', timeout=5).read())})
        ck('GET /local/configs', lambda: {'len': len(urlopen(base + '/local/configs', timeout=5).read())})
        ck('API GetOverview', lambda: json.loads(urlopen(
            base + '/plugin?action=a&name=sinanwaf&s=GetOverview', timeout=5).read().decode('utf-8')))
        ck('API GetScanStats', lambda: json.loads(urlopen(
            base + '/plugin?action=a&name=sinanwaf&s=GetScanStats', timeout=5).read().decode('utf-8')))

        def _post():
            req = Request(base + '/plugin?action=a&name=sinanwaf',
                          data=b's=GetLogs&page=1&limit=5',
                          headers={'Content-Type': 'application/x-www-form-urlencoded'})
            r = json.loads(urlopen(req, timeout=5).read().decode('utf-8'))
            if not r.get('status'):
                raise ValueError(str(r)[:200])
            return {'rows': len(r['data']['rows']), 'total': r['data']['total']}
        ck('POST API GetLogs', _post)
    finally:
        srv.shutdown()
        srv.server_close()

    print('[4/4] 结果汇总')
    bad = [c for c in checks if not c[1]]
    for name, ok, info in checks:
        if not ok:
            print('  !! %s : %s' % (name, info))
    print('\n总计 %d 项, 通过 %d 项, 失败 %d 项' % (len(checks), len(checks) - len(bad), len(bad)))
    print('沙箱数据: %s' % DATA)
    return 0 if not bad else 1


def serve(demo=False):
    global MAIN
    print('正在初始化本地测试环境 ...')
    prepare(seed_demo=demo)
    from sinanwaf_main import main
    MAIN = main()
    url = 'http://127.0.0.1:%d/' % PORT
    print('''
============================================================
  司南防火墙 本地测试服务器已启动
  界面:        %s
  生成的配置:  %s/local/configs
  数据沙箱:    %s
  模拟站点:    %s
  数据状态:    %s
  按 Ctrl+C 停止服务
============================================================''' % (
        url, url.rstrip('/'), DATA,
        'demo.test（仅演示模式）' if demo else '（无，与全新面板一致）',
        '演示数据已生成（仅沙箱内）' if demo else '全新空白：无站点、无日志、无扫描结果'))

    def open_browser():
        time.sleep(1.0)
        if os.environ.get('BTFW_NO_BROWSER'):
            return
        try:
            webbrowser.open(url)
        except Exception:
            pass
    bt = threading.Thread(target=open_browser)
    bt.daemon = True
    bt.start()
    srv = ThreadingHTTPServer(('127.0.0.1', PORT), Handler)
    srv.daemon_threads = True
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print('\n已停止。')
    finally:
        srv.server_close()


if __name__ == '__main__':
    if '--selftest' in sys.argv:
        sys.exit(selftest())
    if '--clear' in sys.argv:          # 仅清空演示/测试数据后退出
        prepare()
        clear_demo_data()
        print('已清空沙箱内的攻击日志、扫描结果与告警记录: %s' % DATA)
        sys.exit(0)
    serve(demo='--demo' in sys.argv)
