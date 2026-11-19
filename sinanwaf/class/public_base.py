#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 公共工具：路径、配置读写、SQLite、锁、Web服务探测、面板模块兼容层
import os, sys, json, time, hashlib, sqlite3, threading
try:
    import fcntl          # Linux/宝塔生产环境
except ImportError:
    fcntl = None          # Windows 本地测试环境

if '/www/server/panel' not in sys.path:
    sys.path.insert(0, '/www/server/panel')
try:
    from BTPanel import cache  # noqa
except Exception:
    cache = None

# 生产环境默认 /www/server/sinanwaf；本地测试可通过 BTFW_LOCAL_ROOT 重定向
PLUGIN_ROOT = os.environ.get('BTFW_LOCAL_ROOT') or '/www/server/sinanwaf'
PLUGIN_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

for _d in (PLUGIN_ROOT, os.path.join(PLUGIN_ROOT, 'rules'),
           os.path.join(PLUGIN_ROOT, 'waf', 'vhost'),
           os.path.join(PLUGIN_ROOT, 'waf', 'apache'),
           os.path.join(PLUGIN_ROOT, 'waf', 'global'),
           os.path.join(PLUGIN_ROOT, 'logs'), os.path.join(PLUGIN_ROOT, 'db'),
           os.path.join(PLUGIN_ROOT, 'backup'), os.path.join(PLUGIN_ROOT, 'backup', 'conf'),
           os.path.join(PLUGIN_ROOT, 'versions'), os.path.join(PLUGIN_ROOT, 'tmp'),
           os.path.join(PLUGIN_ROOT, 'quarantine')):
    try:
        if not os.path.isdir(_d):
            os.makedirs(_d)
    except Exception:
        pass


def _atomic_replace(src, dst):
    """原子替换文件：Python3 用 os.replace，Python2 退化为 remove+rename"""
    if hasattr(os, 'replace'):
        os.replace(src, dst)
        return
    try:
        if os.path.exists(dst):
            os.remove(dst)
    except OSError:
        pass
    os.rename(src, dst)


def _thread_id():
    """线程ID：兼容 Python2.7（无 threading.get_ident）"""
    try:
        return threading.get_ident()
    except AttributeError:
        return threading.current_thread().ident


def _communicate(proc, timeout=20):
    """subprocess 通信：Python2 的 communicate 不支持 timeout 参数"""
    try:
        return proc.communicate(timeout=timeout)
    except TypeError:
        return proc.communicate()


class F(object):
    """文件与配置工具"""
    @staticmethod
    def read_json(path, default=None):
        try:
            with open(path, 'rb') as fp:
                return json.loads(fp.read().decode('utf-8'))
        except Exception:
            return default

    @staticmethod
    def write_json(path, data):
        tmp = path + '.tmp'
        with open(tmp, 'wb') as fp:
            fp.write(json.dumps(data, ensure_ascii=False, indent=2).encode('utf-8'))
        _atomic_replace(tmp, path)

    @staticmethod
    def read_file(path, default=''):
        try:
            with open(path, 'rb') as fp:
                return fp.read().decode('utf-8', 'ignore')
        except Exception:
            return default

    @staticmethod
    def write_file(path, data):
        tmp = path + '.tmp'
        with open(tmp, 'wb') as fp:
            if isinstance(data, str):
                data = data.encode('utf-8')
            fp.write(data)
        _atomic_replace(tmp, path)

    @staticmethod
    def read_text_smart(path, limit=4 * 1024 * 1024):
        """读取文本文件(<=limit 字节)供浏览器下载, 自动兼容 utf-8/gbk; 超限返回空串"""
        try:
            if not path or not os.path.exists(path) or os.path.getsize(path) > limit:
                return ''
            with open(path, 'rb') as fp:
                raw = fp.read()
        except Exception:
            return ''
        for enc in ('utf-8-sig', 'utf-8', 'gbk'):
            try:
                return raw.decode(enc)
            except Exception:
                continue
        return raw.decode('utf-8', 'ignore')


class Lock(object):
    """进程内互斥（低资源，避免引入额外依赖）"""
    _mu = threading.Lock()
    _locks = {}

    @classmethod
    def get(cls, name):
        with cls._mu:
            if name not in cls._locks:
                cls._locks[name] = threading.RLock()
            return cls._locks[name]


class FLock(object):
    """任务互斥锁：Linux 用 fcntl 文件锁(跨进程)，Windows 本地测试退化为进程内锁"""
    def __init__(self, name='sinanwaf.lock'):
        self.path = os.path.join(PLUGIN_ROOT, 'tmp', name)
        self.name = name
        self.fp = None
        self._mu = None

    def __enter__(self):
        if fcntl is None:
            mu = Lock.get('flock_' + self.name)
            if not mu.acquire(False):
                raise IOError('another task is running')
            self._mu = mu
            return self
        self.fp = open(self.path, 'w')
        try:
            fcntl.flock(self.fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except Exception:
            self.fp.close()
            self.fp = None
            raise IOError('another task is running')
        return self

    def __exit__(self, *a):
        if self._mu:
            try:
                self._mu.release()
            except Exception:
                pass
        if self.fp:
            try:
                fcntl.flock(self.fp, fcntl.LOCK_UN)
                self.fp.close()
            except Exception:
                pass
        return False


class Conf(object):
    """插件主配置（settings.json）"""
    PATH = os.path.join(PLUGIN_ROOT, 'settings.json')

    DEFAULT = {
        'waf_on': True,
        'mode': 'standard',                 # loose / standard / strict
        'cc': {'enable': True, 'limit': 120, 'time': 60, 'deny': 600},
        'limit_req': {'rate': '20r/s', 'burst': 40, 'conn': 30},
        'block_return': 403,
        'log_keep_days': 90,
        'auto_learn': True,                 # 递归自学习开关
        'auto_apply': 'confirm',            # confirm=生成待确认 / auto=自动应用
        'fp_rate_limit': 0.15,              # 误报率超过此阈值自动降级/回滚
        'port_enforce': False,              # 端口规则是否下发系统防火墙(需显式开启)
        'scan': {                           # 木马查杀配置(详见 antivirus.DEFAULT_SCAN)
            'enable': True, 'auto_quarantine': False, 'quarantine_score': 60,
            'auto_waf_rule': True, 'alert_on_found': True, 'quick_hours': 24,
            'max_file_size': 2097152, 'max_files': 60000, 'timeout': 900
        },
        'alert': {
            'enable': True,
            'channels': [],                 # [{type: webhook|dingtalk|wecom|mail, ...}]
            'min_level': 'warn',
            'cooldown': 300                 # 同类告警冷却秒数
        },
        'permissions': {                    # 权限管理：角色 -> 可执行操作
            'admin': ['*'],
            'operator': ['view', 'logs', 'toggle', 'alert', 'scan'],
            'auditor': ['view', 'logs']
        },
        'notify': {                         # 状态/威慑 Webhook 推送(详见 class/notify.py)
            'enable': False, 'url': '', 'kind': 'wecom', 'format': 'markdown', 'secret': '',
            'status_enable': True, 'status_interval': 6,
            'deter_enable': True, 'deter_min': 5, 'deter_gap': 60
        },
        'audit': True
    }

    @classmethod
    def get(cls, key=None, default=None):
        data = F.read_json(cls.PATH, {}) or {}
        # 必须深拷贝默认值: 旧实现 dict(DEFAULT) 是浅拷贝, 嵌套 dict 与 DEFAULT 共享引用,
        # 一次 Conf.get + 修改就会污染默认值, 导致保存的配置被再次读回的旧值覆盖
        merged = json.loads(json.dumps(cls.DEFAULT))
        for k, v in data.items():
            if isinstance(v, dict) and isinstance(merged.get(k), dict):
                merged[k].update(v)
            else:
                merged[k] = v
        if key is None:
            return merged
        return merged.get(key, default)

    @classmethod
    def set(cls, kv):
        data = cls.get()
        data.update(kv)
        F.write_json(cls.PATH, data)
        return True

    @classmethod
    def audit(cls, action, detail=''):
        if not cls.get('audit', True):
            return
        log = os.path.join(PLUGIN_ROOT, 'logs', 'audit.log')
        line = '%s | %s | %s | %s\n' % (
            time.strftime('%Y-%m-%d %H:%M:%S'),
            os.environ.get('BT_USER', 'admin'), action, str(detail)[:500])
        try:
            with open(log, 'a') as fp:
                fp.write(line)
        except Exception:
            pass


class DB(object):
    """SQLite 存储攻击日志/统计/规则版本/告警/反馈，低资源占用"""
    PATH = os.path.join(PLUGIN_ROOT, 'db', 'sinanwaf.db')
    _conn = {}
    _mu = threading.Lock()

    @classmethod
    def conn(cls):
        tid = _thread_id()
        with cls._mu:
            if tid not in cls._conn:
                c = sqlite3.connect(cls.PATH, timeout=10)
                c.execute('PRAGMA journal_mode=WAL')
                c.execute('PRAGMA synchronous=NORMAL')
                cls._conn[tid] = c
            return cls._conn[tid]

    @classmethod
    def init_db(cls):
        c = cls.conn()
        c.executescript('''
        CREATE TABLE IF NOT EXISTS attack_log(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER, ip TEXT, site TEXT, method TEXT, uri TEXT,
            ua TEXT, referer TEXT, rule TEXT, rule_type TEXT, level TEXT,
            action TEXT, payload TEXT, fp INTEGER DEFAULT 0);
        CREATE INDEX IF NOT EXISTS idx_attack_ts ON attack_log(ts);
        CREATE INDEX IF NOT EXISTS idx_attack_ip ON attack_log(ip);
        CREATE INDEX IF NOT EXISTS idx_attack_type ON attack_log(rule_type);
        CREATE TABLE IF NOT EXISTS rule_version(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, tag TEXT,
            summary TEXT, rules BLOB, active INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS alerts(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, channel TEXT,
            level TEXT, title TEXT, body TEXT, ok INTEGER DEFAULT 0,
            cool_key TEXT DEFAULT '');
        CREATE TABLE IF NOT EXISTS learn_log(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, stage TEXT,
            detail TEXT);
        CREATE TABLE IF NOT EXISTS scan_file(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, path TEXT, site TEXT,
            size INTEGER, mtime INTEGER, md5 TEXT, level TEXT, score INTEGER,
            reasons TEXT, action TEXT, fp INTEGER DEFAULT 0,
            quarantined INTEGER DEFAULT 0, qpath TEXT DEFAULT '');
        CREATE INDEX IF NOT EXISTS idx_scan_score ON scan_file(score);
        CREATE INDEX IF NOT EXISTS idx_scan_path ON scan_file(path);
        CREATE TABLE IF NOT EXISTS scan_task(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, type TEXT,
            files INTEGER, threats INTEGER, duration INTEGER, status TEXT, detail TEXT);
        ''')
        # 老库迁移: alerts 增加 cool_key(同类告警冷却键)
        try:
            cols = [r[1] for r in c.execute('PRAGMA table_info(alerts)').fetchall()]
            if 'cool_key' not in cols:
                c.execute("ALTER TABLE alerts ADD COLUMN cool_key TEXT DEFAULT ''")
        except Exception:
            pass
        c.commit()

    @classmethod
    def execute(cls, sql, params=(), fetch=False):
        c = cls.conn()
        cur = c.execute(sql, params)
        c.commit()
        if fetch == 'all':
            cols = [d[0] for d in cur.description] if cur.description else []
            return [dict(zip(cols, r)) for r in cur.fetchall()]
        if fetch == 'one':
            cols = [d[0] for d in cur.description] if cur.description else []
            r = cur.fetchone()
            return dict(zip(cols, r)) if r else None
        return cur.lastrowid


class WebServer(object):
    """探测本机 Nginx / Apache 与宝塔面板常用路径"""
    @staticmethod
    def nginx_conf():
        for p in ('/www/server/nginx/conf/nginx.conf',):
            if os.path.exists(p):
                return p
        return None

    @staticmethod
    def nginx_vhost_dir():
        p = '/www/server/panel/vhost/nginx'
        return p if os.path.exists(p) else None

    @staticmethod
    def apache_conf():
        for p in ('/www/server/apache/conf/httpd.conf', '/www/server/apache/conf/extra/httpd-vhosts.conf',
                  '/etc/httpd/conf/httpd.conf'):
            if os.path.exists(p):
                return p
        return None

    @staticmethod
    def apache_vhost_dir():
        for p in ('/www/server/panel/vhost/apache', '/etc/httpd/conf/extra'):
            if os.path.exists(p):
                return p
        return None

    @staticmethod
    def nginx_bin():
        for p in ('/www/server/nginx/sbin/nginx', '/usr/sbin/nginx', '/usr/local/nginx/sbin/nginx'):
            if os.path.exists(p):
                return p
        return None

    @staticmethod
    def apache_bin():
        for p in ('/www/server/apache/bin/httpd', '/usr/sbin/httpd', '/usr/sbin/apachectl'):
            if os.path.exists(p):
                return p
        return None

    @staticmethod
    def test_config(web):
        """配置下发前校验语法，避免把站点搞挂"""
        import subprocess
        b = WebServer.nginx_bin() if web == 'nginx' else WebServer.apache_bin()
        if not b:
            return None    # 无法校验
        cmd = [b, '-t']
        if web == 'apache' and os.path.basename(b) in ('httpd', 'apachectl'):
            cmd = [b, '-t']
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            _communicate(p, 20)
            return p.returncode == 0
        except Exception:
            return False

    @staticmethod
    def cmd(cmd, timeout=10):
        import subprocess
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = _communicate(p, timeout)
            return {'ok': p.returncode == 0,
                    'out': out.decode('utf-8', 'ignore') if isinstance(out, bytes) else out,
                    'err': err.decode('utf-8', 'ignore') if isinstance(err, bytes) else err}
        except Exception as e:
            return {'ok': False, 'err': str(e)}

    @staticmethod
    def access_logs(web='nginx'):
        """返回访问日志文件列表（含切割历史，供分析器回溯）"""
        logs = []
        if web == 'nginx':
            logs.append('/www/wwwlogs/access.log')
            d = '/www/wwwlogs'
        else:
            logs.append('/www/wwwlogs/access_log')
            d = '/www/wwwlogs'
        try:
            if os.path.exists(d):
                for f in os.listdir(d):
                    if f.startswith('access.log-') or f.endswith('-access.log'):
                        logs.append(os.path.join(d, f))
        except Exception:
            pass
        return [p for p in sorted(set(logs)) if os.path.exists(p)]

    @staticmethod
    def reload(web):
        import subprocess
        cmds = {
            'nginx': ['/etc/init.d/nginx', 'reload'],
            'apache': ['/etc/init.d/httpd', 'graceful'],
        }
        c = cmds.get(web)
        if not c or not os.path.exists(c[0]):
            return False
        try:
            r = subprocess.Popen(c, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = _communicate(r, 30)
            return r.returncode == 0
        except Exception:
            return False

    @staticmethod
    def get_sites():
        """联动宝塔站点列表"""
        sites = []
        try:
            import public
            data = public.M('sites').field('name,path,status,ps').select()
            for s in data:
                sites.append({'name': s['name'], 'path': s['path'],
                              'status': s['status'], 'ps': s.get('ps', '')})
        except Exception:
            vd = WebServer.nginx_vhost_dir()
            if vd:
                for f in os.listdir(vd):
                    if f.endswith('.conf') and not f.startswith('.') and f != 'default.conf':
                        sites.append({'name': f[:-5], 'path': '', 'status': 1, 'ps': ''})
        return sites


class S(object):
    """安全小工具"""
    @staticmethod
    def valid_ip(ip):
        import re
        if not ip or len(ip) > 45:
            return False
        ip = str(ip)
        if ':' in ip:      # IPv6: 只做字符与段数粗校验
            return bool(re.match(r'^[0-9a-fA-F:]+$', ip)) and ip.count(':') >= 2
        return S.ip_to_int(ip) is not None

    @staticmethod
    def valid_cidr(cidr):
        import re
        if '/' not in cidr:
            return False
        ip, bits = cidr.split('/', 1)
        if not S.valid_ip(ip) or ':' in ip:
            return False
        return bits.isdigit() and 0 <= int(bits) <= 32

    # ---------- IPv4 解析 / 网段与区间换算 ----------
    @staticmethod
    def ip_to_int(ip):
        """IPv4 -> 32 位整数, 格式非法或越界返回 None"""
        parts = str(ip or '').strip().split('.')
        if len(parts) != 4:
            return None
        n = 0
        for p in parts:
            if not p.isdigit() or len(p) > 3 or int(p) > 255:
                return None
            n = (n << 8) | int(p)
        return n

    @staticmethod
    def int_to_ip(n):
        n = int(n) & 0xffffffff
        return '%d.%d.%d.%d' % ((n >> 24) & 255, (n >> 16) & 255,
                                (n >> 8) & 255, n & 255)

    @staticmethod
    def ip_range_to_cidrs(start, end):
        """连续 IPv4 区间 -> 最小 CIDR 列表(不依赖 ipaddress, 兼容 Python2.7)"""
        a, b = S.ip_to_int(start), S.ip_to_int(end)
        if a is None or b is None or a > b:
            return []
        out = []
        while a <= b:
            prefix = 0
            while prefix < 32:
                mask = (0xffffffff << (32 - prefix)) & 0xffffffff
                if (a & mask) == a:
                    break
                prefix += 1
            while prefix < 32:
                size = 1 << (32 - prefix)
                if a + size - 1 <= b:
                    break
                prefix += 1
            size = 1 << (32 - prefix)
            out.append('%s/%d' % (S.int_to_ip(a), prefix))
            a += size
        return out

    @staticmethod
    def normalize_ip_pattern(pattern):
        """IP / CIDR / 区间(x.x.x.0-x.x.x.255, ~, 至) -> 规范化列表([单IP] 或 [CIDR])"""
        import re
        p = re.sub(r'\s+', '', str(pattern or ''))
        if not p:
            return []
        p = p.replace('~', '-').replace('—', '-').replace('－', '-').replace('至', '-')
        m = re.match(r'^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3})$', p)
        if m:
            return S.ip_range_to_cidrs(m.group(1), m.group(2))
        if ':' in p:      # IPv6 等: 原样保留, 交由 web 服务器校验
            return [p] if ('/' not in p and S.valid_ip(p)) else []
        if '/' in p:
            ip, _, bits = p.partition('/')
            base = S.ip_to_int(ip)
            if base is None or not bits.isdigit() or int(bits) > 32:
                return []
            prefix = int(bits)
            mask = ((0xffffffff << (32 - prefix)) & 0xffffffff) if prefix else 0
            return ['%s/%d' % (S.int_to_ip(base & mask), prefix)]
        n = S.ip_to_int(p)
        return [S.int_to_ip(n)] if n is not None else []

    @staticmethod
    def extract_ip_patterns(text):
        """从任意文本提取 IP/网段/区间(去重保序, 自动兼容带端口与混合文本)"""
        import re
        raw = str(text or '')
        raw = re.sub(r'(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}', r'\1', raw)   # 拆掉端口
        out, seen = [], set()
        for tok in re.split(r'''[\s,;、，；|"'`]+''', raw):
            tok = tok.strip().strip('()[]{}<>')
            if not tok:
                continue
            pats = S.normalize_ip_pattern(tok)
            if not pats:      # url?ip=1.2.3.4 之类混合文本: 兜底抠出 IP
                for ip in re.findall(r'(?:\d{1,3}\.){3}\d{1,3}', tok):
                    pats.extend(S.normalize_ip_pattern(ip))
            for p in pats:
                if p not in seen:
                    seen.add(p)
                    out.append(p)
        return out

    @staticmethod
    def valid_regexp(p):
        """防御性校验正则，避免 ReDoS 与恶意注入"""
        import re
        if not p or len(p) > 512:
            return False
        try:
            re.compile(p)
        except Exception:
            return False
        # 限制嵌套量词导致的指数回溯
        if re.search(r'[*+]\)\s*[*+{]', p):
            return False
        return True

    # 兼容别名
    clean_regexp = valid_regexp
