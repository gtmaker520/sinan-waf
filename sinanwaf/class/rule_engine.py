#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 规则引擎：规则 CRUD / 匹配 / 导入导出 / 备份恢复 / 版本管理
# 规则类型:
#   ip_black / ip_white / ip_region / port_proto / url / ua / referer
#   sqli / xss / upload / trojan / bot / path_scan / freq
import os, re, json, time, copy
from public_base import F, Conf, DB, PLUGIN_ROOT, PLUGIN_DIR, Lock, S

RULE_PATH = os.path.join(PLUGIN_ROOT, 'rules', 'rules.json')
RULE_TYPES = ['ip_black', 'ip_white', 'ip_region', 'port_proto', 'url',
              'ua', 'referer', 'sqli', 'xss', 'upload', 'trojan',
              'bot', 'path_scan', 'freq']

_RUNTIME = None      # 进程内预编译规则缓存（模块级，跨实例共享）


class RuleEngine(object):
    def __init__(self):
        self._mu = Lock.get('rules')

    # ---------- 存储 ----------
    def _load(self):
        rules = F.read_json(RULE_PATH)
        if not rules:
            rules = {t: [] for t in RULE_TYPES}
        for t in RULE_TYPES:
            rules.setdefault(t, [])
        return rules

    def _save(self, rules):
        F.write_json(RULE_PATH, rules)
        self.compile_runtime()

    def init_default_rules(self):
        """从内置默认规则库初始化（幂等）"""
        if os.path.exists(RULE_PATH):
            return False
        default = F.read_json(os.path.join(PLUGIN_DIR, 'rules', 'default_rules.json'))
        if not default:
            default = {t: [] for t in RULE_TYPES}
        F.write_json(RULE_PATH, default)
        self.compile_runtime()
        return True

    # ---------- 运行时编译（正则预编译，热路径零开销） ----------
    def compile_runtime(self):
        with self._mu:
            rules = self._load()
            compiled = {'regex': {}, 'ips': {'black': set(), 'white': set()},
                        'cidr': [], 'regions': [], 'port': [], 'freq': []}
            for t in ('url', 'ua', 'referer', 'sqli', 'xss', 'upload',
                      'trojan', 'bot', 'path_scan'):
                lst = []
                for r in rules.get(t, []):
                    if not r.get('on', True):
                        continue
                    pat = r.get('pattern', '')
                    if not S.valid_regexp(pat):
                        continue
                    try:
                        lst.append({'id': r['id'], 'name': r.get('name', ''),
                                    're': re.compile(pat, re.I), 'level': r.get('level', 'high'),
                                    'mode': r.get('mode', 'block')})
                    except Exception:
                        continue
                compiled['regex'][t] = lst
            for r in rules.get('ip_black', []):
                if not r.get('on', True):
                    continue        # 界面关掉的名单不应继续参与日志命中(与 Nginx 侧保持一致)
                if '/' in r.get('pattern', ''):
                    compiled['cidr'].append(r['pattern'])
                else:
                    compiled['ips']['black'].add(r['pattern'])
            for r in rules.get('ip_white', []):
                if not r.get('on', True):
                    continue
                if '/' in r.get('pattern', ''):
                    compiled['cidr_white'] = compiled.get('cidr_white', []) + [r['pattern']]
                else:
                    compiled['ips']['white'].add(r['pattern'])
            compiled['regions'] = [r for r in rules.get('ip_region', []) if r.get('on', True)]
            compiled['port'] = [r for r in rules.get('port_proto', []) if r.get('on', True)]
            compiled['freq'] = [r for r in rules.get('freq', []) if r.get('on', True)]
            # 编译对象(re.Pattern)与set不可JSON序列化: 内存缓存 + 落盘仅写可序列化摘要
            global _RUNTIME
            _RUNTIME = compiled
            F.write_json(os.path.join(PLUGIN_ROOT, 'tmp', 'runtime_rules.json'), {
                'compiled_at': int(time.time()),
                'regex_counts': dict((k, len(v)) for k, v in compiled['regex'].items()),
                'ip_black_count': len(compiled['ips']['black']),
                'ip_white_count': len(compiled['ips']['white']),
                'cidr_count': len(compiled['cidr'])
            })
            return True

    def load_runtime(self):
        """命中检测热路径: 直接返回内存中的预编译规则"""
        if _RUNTIME is None:
            self.compile_runtime()
        return _RUNTIME

    # ---------- CRUD ----------
    def get_rules(self, rule_type=None):
        rules = self._load()
        if rule_type:
            return rules.get(rule_type, [])
        return rules

    def page_rules(self, rule_type, page=1, limit=20, keyword='', only_on=None):
        """服务端分页(IP 名单量大时避免把全部规则取到前端过滤)"""
        rules = list(self.get_rules(rule_type) or [])
        kw = str(keyword or '').strip().lower()
        if kw:
            rules = [r for r in rules
                     if kw in ('%s %s %s' % (r.get('pattern', ''), r.get('name') or '',
                                             r.get('note') or '')).lower()]
        if only_on is not None:
            rules = [r for r in rules if bool(r.get('on')) == bool(only_on)]
        rules.sort(key=lambda x: -int(x.get('ctime') or 0))
        try:
            page = max(1, int(page or 1))
        except (TypeError, ValueError):
            page = 1
        try:
            limit = max(1, min(int(limit or 20), 200))
        except (TypeError, ValueError):
            limit = 20
        total = len(rules)
        start = (page - 1) * limit
        rows = rules[start:start + limit]
        now = int(time.time())
        for r in rows:
            r.setdefault('expire_at', 0)
            r['expired'] = bool(r.get('expire_at')) and int(r['expire_at']) <= now
        return {'total': total, 'rows': rows, 'page': page, 'limit': limit}

    def purge_expired(self, now=None):
        """清理到期规则(临时封禁), 返回被删除的规则列表"""
        now = int(now or time.time())
        removed = []
        with self._mu:
            rules = self._load()
            for t in RULE_TYPES:
                lst = rules.get(t, [])
                keep = []
                for r in lst:
                    ea = int(r.get('expire_at') or 0)
                    if ea and ea <= now:
                        removed.append({'type': t, 'pattern': r.get('pattern'),
                                        'id': r.get('id')})
                    else:
                        keep.append(r)
                if len(keep) != len(lst):
                    rules[t] = keep
            if removed:
                self._save(rules)
        if removed:
            Conf.audit('purge_expired', ', '.join('%s:%s' % (x['type'], x['pattern'])
                                                 for x in removed[:20]))
        return removed

    @staticmethod
    def _normalize_pattern(rule_type, pattern):
        """校验并规范化规则内容(新增与编辑共用), 非法时抛 ValueError"""
        pattern = str(pattern or '').strip()
        if not pattern:
            raise ValueError('规则内容不能为空')
        if rule_type in ('ip_black', 'ip_white'):
            pats = S.normalize_ip_pattern(pattern)
            if len(pats) > 1:
                raise ValueError('该区间跨多个网段, 请使用"IP快速封禁"批量添加')
            if not pats:
                raise ValueError('非法的 IP / 网段: %s' % pattern[:64])
            return pats[0]
        if rule_type in ('url', 'ua', 'referer', 'sqli', 'xss', 'upload', 'trojan', 'bot',
                         'path_scan', 'freq'):
            if not S.valid_regexp(pattern):
                raise ValueError('非法的正则表达式(长度<=512 且不能有嵌套量词): %s' % pattern[:64])
            return pattern
        if len(pattern) > 512:
            raise ValueError('规则内容过长(<=512): %s' % pattern[:64])
        return pattern

    @staticmethod
    def normalize_rate(rate):
        """频率规则速率: nginx limit_req 语法, 形如 10r/s 或 120r/m"""
        r = re.sub(r'\s+', '', str(rate or '')).lower()
        if not re.match(r'^\d{1,6}r/[sm]$', r):
            raise ValueError('速率格式应为 10r/s 或 120r/m')
        n = int(r.split('r/')[0])
        if n < 1 or n > 100000:
            raise ValueError('速率需在 1 ~ 100000 之间')
        return r

    @staticmethod
    def normalize_burst(burst):
        try:
            n = int(burst or 0)
        except (TypeError, ValueError):
            n = 0
        if n < 0:
            n = 0
        return min(n, 10000)

    def add_rule(self, rule_type, name, pattern, level='high', mode='block', note='', source='manual',
                 expire_at=0, rate='', burst=0):
        assert rule_type in RULE_TYPES, 'unknown rule type'
        pattern = self._normalize_pattern(rule_type, pattern)
        extra = {}
        if rule_type == 'freq':
            extra = {'rate': self.normalize_rate(rate), 'burst': self.normalize_burst(burst)}
        with self._mu:
            rules = self._load()
            for r in rules[rule_type]:
                if r['pattern'] == pattern:
                    raise ValueError('规则已存在')
            rid = 'r_%s_%s' % (rule_type[:4], hashlib_id(pattern)[:8])
            item = {
                'id': rid, 'name': name or pattern[:32], 'pattern': pattern,
                'level': level, 'mode': mode, 'note': note,
                'source': source, 'on': True, 'ctime': int(time.time()),
                'expire_at': int(expire_at or 0),
                'hits': 0, 'fp': 0}
            item.update(extra)
            rules[rule_type].append(item)
            self._save(rules)
        Conf.audit('add_rule', '%s %s%s' % (rule_type, pattern,
                                            ' (临时至 %s)' % time.strftime('%m-%d %H:%M', time.localtime(expire_at))
                                            if expire_at else ''))
        return rid

    def add_rules_bulk(self, rule_type, patterns, level='high', mode='block',
                       note='', source='manual', limit=5000, expire_at=0):
        """批量新增(单次读写落盘), 返回 {'added','duplicated','invalid','total'}"""
        assert rule_type in RULE_TYPES, 'unknown rule type'
        raw = [str(p).strip() for p in (patterns or []) if str(p).strip()]
        total = len(raw)
        norm, invalid = [], 0
        seen_new = set()
        for p in raw:
            if rule_type in ('ip_black', 'ip_white'):
                pats = S.normalize_ip_pattern(p)
                if not pats:
                    invalid += 1
                    continue
                p = pats[0]
            if p in seen_new:
                continue
            seen_new.add(p)
            norm.append(p)
            if len(norm) >= limit:
                break
        added, duplicated = 0, 0
        with self._mu:
            rules = self._load()
            exists = set(r['pattern'] for r in rules[rule_type])
            for p in norm:
                if p in exists:
                    duplicated += 1
                    continue
                exists.add(p)
                rules[rule_type].append({
                    'id': 'r_%s_%s' % (rule_type[:4], hashlib_id(p)[:8]),
                    'name': (note or '批量封禁') + ' ' + _range_label(p), 'pattern': p,
                    'level': level, 'mode': mode, 'note': '', 'source': source,
                    'on': True, 'ctime': int(time.time()), 'expire_at': int(expire_at or 0),
                    'hits': 0, 'fp': 0})
                added += 1
            if added:
                self._save(rules)
        if added:
            Conf.audit('add_rules_bulk', '%s +%d' % (rule_type, added))
        return {'added': added, 'duplicated': duplicated, 'invalid': invalid,
                'total': total}

    def del_rules(self, rule_type, ids=None, all_flag=False, keyword=None):
        """批量删除(单次落盘); all_flag=True 清空该类型; keyword 命中(IP/名称)才删"""
        assert rule_type in RULE_TYPES, 'unknown rule type'
        ids = set(ids or [])
        kw = str(keyword or '').strip().lower()
        removed = 0
        with self._mu:
            rules = self._load()
            before = len(rules[rule_type])
            if all_flag and not kw:
                rules[rule_type] = []
            elif all_flag and kw:
                rules[rule_type] = [r for r in rules[rule_type]
                                    if kw not in ('%s %s' % (r.get('pattern', ''), r.get('name', ''))).lower()]
            elif ids:
                rules[rule_type] = [r for r in rules[rule_type] if r['id'] not in ids]
            else:
                return 0
            removed = before - len(rules[rule_type])
            if removed:
                self._save(rules)
        if removed:
            Conf.audit('del_rules', '%s -%d' % (rule_type, removed))
        return removed

    def del_rule(self, rule_type, rid):
        with self._mu:
            rules = self._load()
            before = len(rules[rule_type])
            rules[rule_type] = [r for r in rules[rule_type] if r['id'] != rid]
            if len(rules[rule_type]) == before:
                raise ValueError('规则不存在')
            self._save(rules)
        Conf.audit('del_rule', '%s %s' % (rule_type, rid))
        return True

    def update_rule(self, rule_type, rid, kv):
        # 编辑规则同样需要校验: 非法内容会写进 Nginx 配置, 导致下发失败并整站回滚
        if 'pattern' in kv:
            kv['pattern'] = self._normalize_pattern(rule_type, kv['pattern'])
        if rule_type == 'freq':
            if 'rate' in kv:
                kv['rate'] = self.normalize_rate(kv['rate'])
            if 'burst' in kv:
                kv['burst'] = self.normalize_burst(kv['burst'])
        with self._mu:
            rules = self._load()
            hit = None
            for r in rules[rule_type]:
                if r['id'] == rid:
                    for k in ('name', 'pattern', 'level', 'mode', 'on', 'note', 'rate', 'burst'):
                        if k in kv and (k in ('rate', 'burst') and rule_type != 'freq'):
                            continue
                        if k in kv:
                            r[k] = kv[k]
                    hit = r
            if not hit:
                raise ValueError('规则不存在')
            self._save(rules)
        Conf.audit('update_rule', '%s %s %s' % (rule_type, rid, kv))
        return True

    # ---------- 导入导出 / 备份恢复 ----------
    def export_rules(self):
        data = {'meta': {'export_time': int(time.time()),
                         'version': Conf.get('__version__', '1.0')},
                'rules': self._load()}
        return data

    def import_rules(self, data, mode='merge'):
        """mode: merge=合并(跳过重复) / cover=覆盖"""
        if not isinstance(data, dict) or 'rules' not in data:
            raise ValueError('无效的规则文件')
        with self._mu:
            rules = self._backup_snapshot('import')
            if mode == 'cover':
                new = {t: [] for t in RULE_TYPES}
            else:
                new = self._load()
            for t in RULE_TYPES:
                for r in data['rules'].get(t, []):
                    if not isinstance(r, dict) or 'pattern' not in r:
                        continue
                    if any(x['pattern'] == r['pattern'] for x in new[t]):
                        continue
                    if t in ('ip_black', 'ip_white') and not (S.valid_ip(r['pattern']) or S.valid_cidr(r['pattern'])):
                        continue
                    r.setdefault('id', 'r_%s_%s' % (t[:4], hashlib_id(str(r['pattern']))[:8]))
                    r.setdefault('on', True)
                    r.setdefault('source', 'import')
                    new[t].append(r)
            self._save(new)
        Conf.audit('import_rules', mode)
        return True

    def _backup_snapshot(self, tag):
        DB.execute('INSERT INTO rule_version(ts,tag,summary,rules,active) VALUES(?,?,?,?,0)',
                   (int(time.time()), tag, 'auto backup',
                    json.dumps(self._load(), ensure_ascii=False)))
        return self._load()

    def create_backup(self, note=''):
        with self._mu:
            self._backup_snapshot(note or 'manual')
        path = os.path.join(PLUGIN_ROOT, 'backup', 'rules_%s.json' % time.strftime('%Y%m%d%H%M%S'))
        F.write_json(path, self.export_rules())
        return path

    def list_backups(self):
        rows = DB.execute('SELECT id,ts,tag,summary,active FROM rule_version ORDER BY id DESC LIMIT 50', fetch='all')
        files = []
        bd = os.path.join(PLUGIN_ROOT, 'backup')
        for f in sorted(os.listdir(bd), reverse=True) if os.path.exists(bd) else []:
            if f.endswith('.json'):
                files.append({'file': f, 'time': f[6:-5]})
        return {'versions': rows, 'files': files}

    def restore(self, version_id=None, file=None):
        with self._mu:
            if file:
                data = F.read_json(os.path.join(PLUGIN_ROOT, 'backup', file))
                if not data:
                    raise ValueError('备份文件无效')
                self._backup_snapshot('before-restore')
                F.write_json(RULE_PATH, data['rules'])
                self.compile_runtime()
            else:
                row = DB.execute('SELECT rules FROM rule_version WHERE id=?', (version_id,), fetch='one')
                if not row:
                    raise ValueError('版本不存在')
                self._backup_snapshot('before-rollback')
                F.write_json(RULE_PATH, json.loads(row['rules']))
                self.compile_runtime()
        Conf.audit('restore_rules', str(version_id or file))
        return True

    def mark_hit(self, rule_type, rid, fp=False):
        """规则命中/误报计数（供效果评估）; rid 支持规则ID或名称(兼容历史日志)"""
        with self._mu:
            rules = self._load()
            lst = rules.get(rule_type, [])
            target = None
            for r in lst:
                if r['id'] == rid:
                    target = r
                    break
            if target is None and rid:
                for r in lst:
                    if r.get('name') == rid:
                        target = r
                        break
            if target is None:
                return False
            target['hits'] = target.get('hits', 0) + 1
            if fp:
                target['fp'] = target.get('fp', 0) + 1
            F.write_json(RULE_PATH, rules)
        return True

    def mark_hits_bulk(self, counter):
        """批量累加命中计数: {(rule_type, rule_id): n} -> 实际更新的规则条数"""
        if not counter:
            return 0
        changed = 0
        with self._mu:
            rules = self._load()
            for (rtype, rid), cnt in counter.items():
                for r in rules.get(rtype, []):
                    if r['id'] == rid:
                        r['hits'] = r.get('hits', 0) + int(cnt)
                        changed += 1
                        break
            if changed:
                self._save(rules)
        return changed


def hashlib_id(s):
    import hashlib
    return hashlib.md5(s.encode('utf-8', 'ignore')).hexdigest()


def _range_label(pattern):
    """/24 网段规则显示为 x.x.x.0-x.x.x.255, 与界面生成格式保持一致"""
    import re
    m = re.match(r'^(\d{1,3}(?:\.\d{1,3}){3})/24$', str(pattern))
    if not m:
        return str(pattern)
    base = m.group(1)
    return '%s-%s255' % (base, base[:base.rfind('.') + 1])
