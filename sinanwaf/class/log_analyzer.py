#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 日志分析器：增量tail解析访问日志 -> 规则匹配 -> 攻击入库 + 统计聚合
# 特性：游标断点续读、批量提交、正则预编译、超长行跳过，资源占用低
import os, re, json, time
try:
    from urllib.parse import unquote
except ImportError:      # Python2
    from urllib import unquote
from collections import Counter
from public_base import F, Conf, DB, PLUGIN_ROOT, WebServer, Lock
from rule_engine import RuleEngine

POS_FILE = os.path.join(PLUGIN_ROOT, 'tmp', 'log_pos.json')

NGINX_LINE = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<uri>\S+)[^"]*"\s+'
    r'(?P<status>\d{3})\s+\d+\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"')
APACHE_LINE = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<uri>\S+)[^"]*"\s+(?P<status>\d{3})')
LOG_TIME_RE = re.compile(r'^(\d{1,2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})')
_MONTHS = {'jan': 1, 'feb': 2, 'mar': 3, 'apr': 4, 'may': 5, 'jun': 6,
           'jul': 7, 'aug': 8, 'sep': 9, 'oct': 10, 'nov': 11, 'dec': 12}


def parse_log_ts(text, fallback=None):
    """访问日志时间 -> unix 时间戳; 兼容 05/Nov/2026:10:00:01 +0800 与 ISO 格式"""
    now = int(time.time())
    s = str(text or '').strip()
    try:
        m = LOG_TIME_RE.match(s)
        if m:
            d, mon, y, hh, mm, ss = m.groups()
            mon = _MONTHS.get(mon.lower())
            if mon:
                ts = int(time.mktime((int(y), mon, int(d), int(hh), int(mm), int(ss), 0, 0, -1)))
                # 明显异常(日志时间超前或过旧)时回退, 避免污染统计
                if now - 400 * 86400 < ts < now + 2 * 86400:
                    return ts
        ts = int(float(s))
        if 1000000000 < ts < now + 2 * 86400:
            return ts
    except Exception:
        pass
    return int(fallback or now)


class LogAnalyzer(object):
    def __init__(self):
        self._mu = Lock.get('analyze')

    # ---------- 游标 ----------
    def _load_pos(self):
        return F.read_json(POS_FILE, {}) or {}

    def _save_pos(self, pos):
        F.write_json(POS_FILE, pos)

    # ---------- 匹配 ----------
    def match_request(self, ip, method, uri, ua, referer, site='', ts=None):
        """对单条请求执行全量规则匹配，返回命中的规则列表"""
        rt = RuleEngine().load_runtime()
        hits = []
        if ip in rt['ips'].get('white', set()):
            return hits  # 白名单直接放行
        for wcidr in rt.get('cidr_white') or []:
            if ip_in_cidr(ip, wcidr):
                return hits
        if ip in rt['ips'].get('black', set()):
            hits.append({'rule_type': 'ip_black', 'rule': 'IP黑名单', 'level': 'high',
                         'payload': ip, 'id': 'ip_black', 'mode': 'block'})
            return hits
        for cidr in rt.get('cidr', []):
            if ip_in_cidr(ip, cidr):
                hits.append({'rule_type': 'ip_black', 'rule': 'IP段封禁', 'level': 'high',
                             'payload': cidr, 'id': 'cidr', 'mode': 'block'})
        try:
            from region import RegionDB
            country = RegionDB().lookup(ip)
            if country:
                for rg in rt.get('regions', []):
                    if rg.get('pattern') == country:
                        hits.append({'rule_type': 'ip_region', 'rule': '地区封禁:%s' % country,
                                     'level': 'medium', 'payload': country, 'id': rg.get('id'),
                                     'mode': rg.get('mode', 'block')})
        except ImportError:
            pass
        scan = unquote(uri)[:2048]
        targets = [('sqli', scan), ('xss', scan), ('path_scan', scan.lower()),
                   ('trojan', scan.lower()), ('upload', scan),
                   ('url', uri), ('ua', ua), ('referer', referer), ('bot', ua)]
        for rtype, text in targets:
            for r in rt['regex'].get(rtype, []):
                try:
                    if r['re'].search(text):
                        hits.append({'rule_type': rtype, 'rule': r['name'] or r['id'],
                                     'level': r['level'], 'payload': text[:512], 'id': r['id'],
                                     'mode': r.get('mode', 'block')})
                except Exception:
                    continue
        return hits

    # ---------- 批量分析 ----------
    def analyze_all(self, max_lines=200000):
        """增量解析所有访问日志，返回本次统计（供面板与计划任务）

        修正点:
        - 记录真实读取偏移(而非文件大小), 避免单轮达上限后丢日志
        - 单轮按行数真实限流(旧实现 max_lines*4096 等于没有上限)
        - 使用日志行内时间入库, 统计趋势/今日才准确
        - 单轮内去重, 避免游标回退或重叠读取产生重复攻击记录
        """
        with self._mu:
            pos = self._load_pos()
            new_pos = {}
            stats = {'lines': 0, 'attacks': 0, 'ips': Counter(), 'types': Counter(),
                     'top_uris': Counter(), 'sites': Counter(), 'dedupe': 0}
            batch = []
            hit_cnt = {}      # 规则命中统计 {(rule_type, rule_id): n}, 供效果评估
            seen = set()      # 单轮去重: (ip, ts, uri)
            logs = (WebServer.access_logs('nginx') or [])[:5]  # 只取最近5个文件，控资源
            quota = max_lines
            for path in logs:
                if quota <= 0:
                    new_pos[path] = pos.get(path) or {'i': os.path.getsize(path), 'inode': 0}
                    continue
                try:
                    size = os.path.getsize(path)
                except OSError:
                    continue
                key = path
                inode = os.stat(path).st_ino
                if key not in pos:
                    # 首次分析: 回溯最近 2MB 历史日志(而非直接跳到文件尾)
                    offset = max(0, size - 2 * 1024 * 1024)
                elif pos[key].get('inode') != inode:
                    offset = 0           # 日志已切割，从头读新文件
                else:
                    offset = min(pos[key].get('i', 0), size)
                if offset >= size:
                    new_pos[key] = {'i': size, 'inode': inode}
                    continue
                read = 0
                read_bytes = 0
                buf = ''
                stop = False
                with open(path, 'rb') as fp:
                    fp.seek(offset)
                    while not stop:
                        chunk = fp.read(65536)
                        if not chunk:
                            break
                        read_bytes += len(chunk)
                        buf += chunk.decode('utf-8', 'ignore')
                        if '\n' in buf:
                            head, buf = buf.rsplit('\n', 1)
                            lines = head.split('\n')
                        else:
                            lines = []
                        for line in lines:
                            read += 1
                            stats['lines'] += 1
                            rec = self._parse_line(line)
                            if rec:
                                hits = self.match_request(**rec)
                                if hits:
                                    dkey = (rec['ip'], rec['ts'], rec['uri'][:120])
                                    if dkey in seen:
                                        stats['dedupe'] += 1
                                        continue
                                    seen.add(dkey)
                                    stats['attacks'] += 1
                                    stats['ips'][rec['ip']] += 1
                                    stats['sites'][site_of(rec['uri'])] += 1
                                    for h in hits:
                                        stats['types'][h['rule_type']] += 1
                                        stats['top_uris'][rec['uri'][:200]] += 1
                                        if h['rule_type'] not in ('ip_black', 'ip_region') and h.get('id'):
                                            hk = (h['rule_type'], h['id'])
                                            hit_cnt[hk] = hit_cnt.get(hk, 0) + 1
                                        batch.append((rec['ts'], rec['ip'], rec.get('site', ''),
                                                      rec['method'], rec['uri'][:1000], rec['ua'][:300],
                                                      rec['referer'][:300], h['rule'], h['rule_type'],
                                                      h['level'],
                                                      'block' if h.get('mode') == 'block' else 'log',
                                                      h['payload'][:1000]))
                            if len(batch) >= 500:
                                self._flush(batch)
                                batch = []
                            if read >= max_lines or read >= quota:
                                stop = True
                                break
                        if stop:
                            break
                quota -= read
                # 真实新偏移 = 起始 + 已读字节 - 未处理尾巴(精确到字节, 避免丢行/重复)
                try:
                    tail = len(buf.encode('utf-8'))
                except Exception:
                    tail = 0
                new_pos[key] = {'i': max(offset, offset + read_bytes - tail), 'inode': inode}
                self._flush(batch)
                batch = []
                if read >= max_lines:
                    break
            self._save_pos(new_pos)
            self._flush(batch)
            if hit_cnt:
                try:
                    RuleEngine().mark_hits_bulk(hit_cnt)
                except Exception:
                    pass
            return {'lines': stats['lines'], 'attacks': stats['attacks'],
                    'duplicated': stats['dedupe'],
                    'top_ips': stats['ips'].most_common(20),
                    'types': dict(stats['types']),
                    'top_uris': stats['top_uris'].most_common(30),
                    'sites': dict(stats['sites'])}

    def _parse_line(self, line):
        m = NGINX_LINE.search(line)
        if not m:
            m = APACHE_LINE.search(line)
            if not m:
                return None
            ua, referer = '', ''
        else:
            ua, referer = m.group('ua'), m.group('referer')
        try:
            d = m.groupdict()
            ip = d['ip']
            if not re.match(r'^\d', ip) and ':' not in ip:
                return None
            ts = parse_log_ts(d.get('time'))
            return {'ip': ip, 'method': d.get('method', 'GET'),
                    'uri': d.get('uri', '/'), 'ua': d.get('ua') or ua,
                    'referer': d.get('referer') or referer,
                    'site': site_of(d.get('uri', '/')), 'ts': ts}
        except Exception:
            return None

    def _flush(self, batch):
        if not batch:
            return
        c = DB.conn()
        c.executemany('INSERT INTO attack_log(ts,ip,site,method,uri,ua,referer,rule,rule_type,level,action,payload)'
                      ' VALUES(?,?,?,?,?,?,?,?,?,?,?,?)', batch)
        c.commit()

    # ---------- 查询 ----------
    def get_logs(self, page=1, limit=20, rule_type=None, ip=None, level=None,
                 start=None, end=None, keyword=None):
        where, params = ['1=1'], []
        if rule_type:
            where.append('rule_type=?'); params.append(rule_type)
        if ip:
            where.append('ip=?'); params.append(ip)
        if level:
            where.append('level=?'); params.append(level)
        if start:
            where.append('ts>=?'); params.append(int(start))
        if end:
            where.append('ts<=?'); params.append(int(end))
        if keyword:
            where.append('(uri LIKE ? OR payload LIKE ? OR rule LIKE ?)')
            params += ['%%%s%%' % keyword] * 3
        cond = ' AND '.join(where)
        total = DB.execute('SELECT COUNT(*) c FROM attack_log WHERE %s' % cond, params, fetch='one')['c']
        rows = DB.execute(
            'SELECT * FROM attack_log WHERE %s ORDER BY id DESC LIMIT ? OFFSET ?' % cond,
            params + [limit, (page - 1) * limit], fetch='all')
        for r in rows:
            r['time_str'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(r['ts']))
        return {'total': total, 'rows': rows, 'page': page, 'limit': limit}

    @staticmethod
    def day_start(ts=None):
        """自然日零点(本地时区), 用于"今日拦截"口径"""
        lt = time.localtime(ts or time.time())
        return int(time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, 0, 0, 0, 0, 0, -1)))

    def get_stats(self, days=7):
        """可视化统计：趋势 / 类型分布 / Top IP / 拦截与误报拆分"""
        since = int(time.time()) - days * 86400
        trend = DB.execute(
            "SELECT date(ts,'unixepoch','localtime') d, COUNT(*) c, "
            "SUM(CASE WHEN fp=0 THEN 1 ELSE 0 END) ok FROM attack_log WHERE ts>=? "
            "GROUP BY d ORDER BY d", (since,), fetch='all')
        types = DB.execute(
            'SELECT rule_type t, COUNT(*) c FROM attack_log WHERE ts>=? GROUP BY t ORDER BY c DESC',
            (since,), fetch='all')
        topips = DB.execute(
            'SELECT ip, COUNT(*) c FROM attack_log WHERE ts>=? GROUP BY ip ORDER BY c DESC LIMIT 10',
            (since,), fetch='all')
        total = DB.execute('SELECT COUNT(*) c FROM attack_log WHERE ts>=?', (since,), fetch='one')['c']
        period = DB.execute(
            "SELECT SUM(CASE WHEN fp=1 THEN 1 ELSE 0 END) fp, "
            "SUM(CASE WHEN action='block' AND fp=0 THEN 1 ELSE 0 END) blocked "
            'FROM attack_log WHERE ts>=?', (since,), fetch='one') or {}
        day0 = self.day_start()
        agg = DB.execute(
            "SELECT COUNT(*) c, SUM(CASE WHEN fp=1 THEN 1 ELSE 0 END) fp, "
            "SUM(CASE WHEN action='block' AND fp=0 THEN 1 ELSE 0 END) blocked "
            'FROM attack_log WHERE ts>=?', (day0,), fetch='one') or {}
        today = int(agg.get('c') or 0)
        fp_total = int(period.get('fp') or 0)
        return {'days': days, 'total': total, 'today': today,
                'fp': fp_total, 'blocked': int(period.get('blocked') or 0),
                'fp_rate': round(float(fp_total) / total, 4) if total else 0,
                'today_fp': int(agg.get('fp') or 0),
                'today_blocked': int(agg.get('blocked') or 0),
                'day_start': day0,
                'trend': trend, 'types': types, 'top_ips': topips}

    def export_logs(self, fmt='json', start=None, end=None, rule_type=None,
                    keyword=None, ip=None, level=None):
        rows = self.get_logs(1, 100000, rule_type=rule_type, ip=ip, level=level,
                             start=start, end=end, keyword=keyword)['rows']
        path = os.path.join(PLUGIN_ROOT, 'logs', 'export_%s.%s' % (time.strftime('%Y%m%d%H%M%S'), fmt))
        if fmt == 'csv':
            import csv
            with open(path, 'w') as fp:
                w = csv.writer(fp, lineterminator='\n')
                w.writerow(['time', 'ip', 'site', 'method', 'uri', 'rule', 'type', 'level', 'action', 'payload'])
                for r in rows:
                    w.writerow([r['time_str'], r['ip'], r['site'], r['method'], r['uri'],
                                r['rule'], r['rule_type'], r['level'], r['action'],
                                (r.get('payload') or '')[:200]])
        else:
            F.write_json(path, rows)
        Conf.audit('export_logs', '%s/%d条' % (fmt, len(rows)))
        return path

    def export_stats(self, days=7, fmt='csv'):
        """统计报表导出: CSV(分段落) / JSON; 返回 (path, content, mime, filename)"""
        days = max(1, min(int(days or 7), 365))
        st = self.get_stats(days)
        fp = int(st.get('fp') or 0)
        blocked = int(st.get('blocked') or 0)
        total = int(st.get('total') or 0)
        ts = time.strftime('%Y%m%d%H%M%S')
        fname = 'stats_%dd_%s.%s' % (days, ts, fmt)
        path = os.path.join(PLUGIN_ROOT, 'logs', fname)
        if fmt == 'json':
            content = json.dumps({'days': days, 'generated_at': time.strftime('%Y-%m-%d %H:%M:%S'),
                                  'summary': {'total': total, 'blocked': blocked,
                                              'fp': fp, 'today': st.get('today', 0),
                                              'types': len(st.get('types') or []),
                                              'ips': len(st.get('top_ips') or [])},
                                  'trend': st.get('trend') or [],
                                  'types': st.get('types') or [],
                                  'top_ips': st.get('top_ips') or []},
                                 ensure_ascii=False, indent=2)
            mime = 'application/json;charset=utf-8'
        else:
            lines = ['# 司南防火墙 统计报表', '# 区间,近 %d 天' % days,
                     '# 生成时间,%s' % time.strftime('%Y-%m-%d %H:%M:%S'), '',
                     '# 汇总', 'metric,value',
                     'total,%d' % total, 'blocked,%d' % blocked, 'false_positive,%d' % fp,
                     'today,%d' % int(st.get('today') or 0), '',
                     '# 每日趋势', 'date,count']
            for x in st.get('trend') or []:
                lines.append('%s,%s' % (x.get('d', ''), x.get('c', 0)))
            lines += ['', '# 类型分布', 'type,count,percent']
            for x in st.get('types') or []:
                c = int(x.get('c') or 0)
                lines.append('%s,%d,%.2f%%' % (x.get('t', ''), c, (c * 100.0 / total) if total else 0))
            lines += ['', '# Top 攻击来源', 'ip,count,percent']
            for x in st.get('top_ips') or []:
                c = int(x.get('c') or 0)
                lines.append('%s,%d,%.2f%%' % (x.get('ip', ''), c, (c * 100.0 / total) if total else 0))
            content = '\ufeff' + '\n'.join(lines) + '\n'
            mime = 'text/csv;charset=utf-8'
        F.write_file(path, content)
        Conf.audit('export_stats', '%sd %s' % (days, fmt))
        return path, content, mime, fname

    def cleanup_old(self):
        """日志保留策略(旧版本 log_keep_days 配置从未生效, 数据库无限增长)"""
        days = int(Conf.get('log_keep_days', 90) or 0)
        removed = 0
        if days > 0:
            cutoff = int(time.time()) - days * 86400
            row = DB.execute('SELECT COUNT(*) c FROM attack_log WHERE ts<?', (cutoff,), fetch='one')
            removed = int((row or {}).get('c') or 0)
            if removed:
                DB.execute('DELETE FROM attack_log WHERE ts<?', (cutoff,))
        # 学习轨迹/告警历史只保留最近 3000 条, 避免无限膨胀
        DB.execute('DELETE FROM learn_log WHERE id NOT IN '
                   '(SELECT id FROM learn_log ORDER BY id DESC LIMIT 3000)')
        DB.execute('DELETE FROM alerts WHERE id NOT IN '
                   '(SELECT id FROM alerts ORDER BY id DESC LIMIT 3000)')
        return {'removed': removed, 'keep_days': days}

    def mark_fp(self, log_id, fp=1):
        """误报标记（反馈进入自学习闭环）"""
        row = DB.execute('SELECT * FROM attack_log WHERE id=?', (log_id,), fetch='one')
        if not row:
            raise ValueError('记录不存在')
        DB.execute('UPDATE attack_log SET fp=? WHERE id=?', (fp, log_id))
        if fp:
            RuleEngine().mark_hit(row['rule_type'], row['rule'], fp=True)
        Conf.audit('mark_fp', '%s=%s' % (log_id, fp))
        return True

    def clear_logs(self, before_days=None):
        if before_days:
            DB.execute('DELETE FROM attack_log WHERE ts<?',
                       (int(time.time()) - before_days * 86400,))
        else:
            DB.execute('DELETE FROM attack_log')
        DB.execute("DELETE FROM sqlite_sequence WHERE name='attack_log'")
        return True


# ---------- 工具 ----------
def ip_in_cidr(ip, cidr):
    """IPv4 CIDR 匹配（纯 socket/struct 实现，兼容 Python2.7 与 3.x）"""
    try:
        import socket, struct
        to_int = lambda x: struct.unpack('!I', socket.inet_aton(x))[0]
        addr, bits = cidr.split('/', 1)
        bits = int(bits)
        if not 0 <= bits <= 32:
            return False
        mask = ((0xffffffff << (32 - bits)) & 0xffffffff) if bits else 0
        return (to_int(ip) & mask) == (to_int(addr) & mask)
    except Exception:
        return False


def site_of(uri):
    """从 URI 推断归属站点标识；文件名/查询串视为站点根路径"""
    if not uri.startswith('/'):
        return uri[:40]
    seg = uri.lstrip('/').split('/')[0]
    if not seg or '?' in seg or '.' in seg:
        return 'default'
    return seg[:40]


def _consumed(*a):
    return 0
