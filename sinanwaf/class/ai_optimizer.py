#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 递归自我优化引擎（核心）
# 循环: 特征分析 -> 规则生成/优化 -> 效果评估 -> 误报监控 -> 自动调优/回滚 -> 记录学习轨迹
# 设计要点:
#   - 无第三方ML依赖, 统计+启发式实现, 保证低资源与兼容性
#   - 每轮生成规则版本快照, 支持一键回滚
#   - 误报率超阈值自动降级(模式变宽松)或回滚上一版本
import os, re, json, time, math
from collections import Counter, defaultdict
from public_base import F, Conf, DB, PLUGIN_ROOT, Lock, FLock
from rule_engine import RULE_PATH
from rule_engine import RuleEngine

VER_DIR = os.path.join(PLUGIN_ROOT, 'versions')


class AiOptimizer(object):
    EVAL_WINDOW_DAYS = 7        # 误报率统计窗口(滚动), 避免历史误报永久拖累
    STABLE_INTERVAL = 86400     # 稳定版本快照间隔(每天一次)
    ROLLBACK_COOLDOWN = 6 * 3600  # 自动回滚冷却, 防止每轮反复回滚

    def __init__(self):
        self._mu = Lock.get('ai')

    # ================= 主循环 =================
    def run_cycle(self):
        if not Conf.get('auto_learn', True):
            return {'skip': '自学习已关闭'}
        try:
            with FLock('ai.lock'):
                with self._mu:
                    r = {}
                    r['analyze'] = self.analyze_features()
                    r['generated'] = self.generate_rules(r['analyze'])
                    r['optimized'] = self.optimize_existing()
                    r['eval'] = self.evaluate_rules()
                    r['auto'] = self.auto_tune(r['eval'])
                    r['rollback'] = r['auto'].get('rolled_back', False)
                    self.log('cycle', json.dumps(r, ensure_ascii=False)[:2000])
                    return r
        except IOError:
            return {'skip': 'another cycle running'}

    # ================= 1. 特征分析 =================
    def analyze_features(self):
        """从近期攻击日志提取攻击特征: 高频IP/URI模式/攻击工具/时段"""
        since = int(time.time()) - 7 * 86400
        rows = DB.execute(
            'SELECT ip,uri,ua,rule_type,rule,ts,fp FROM attack_log WHERE ts>=? LIMIT 200000',
            (since,), fetch='all')
        if not rows:
            return {'empty': True}
        ips = Counter(r['ip'] for r in rows if not r['fp'])
        uris = Counter(r['uri'] for r in rows if not r['fp'])
        uas = Counter(r['ua'][:200] for r in rows if not r['fp'])
        types = Counter(r['rule_type'] for r in rows if not r['fp'])
        fp_types = Counter(r['rule_type'] for r in rows if r['fp'])
        # 攻击者画像: 单IP高频且命中多类型 => 强攻击者, 建议封禁
        ip_profile = {}
        for r in rows:
            p = ip_profile.setdefault(r['ip'], {'hits': 0, 'types': set(), 'fp': 0})
            p['hits'] += 1
            p['types'].add(r['rule_type'])
            if r['fp']:
                p['fp'] += 1
        strong_attackers = [
            {'ip': ip, 'hits': p['hits'], 'types': sorted(p['types']),
             'confidence': round(min(1.0, p['hits'] / 50.0) * (1.0 if p['fp'] == 0 else 0.5), 2)}
            for ip, p in ip_profile.items()
            if p['hits'] >= 10 and len(p['types']) >= 2 and p['fp'] == 0]
        strong_attackers.sort(key=lambda x: -x['hits'])
        # URI 模式归纳: 去掉具体参数, 找共性路径
        uri_patterns = Counter()
        for u, c in uris.items():
            common = re.sub(r'([\?&][^&\s]*)', '?PARAM', u)[:200]
            uri_patterns[common] += c
        # 新出现UA特征(工具指纹)
        tool_ua = [u for u in uas if re.search(
            r'(sqlmap|nikto|nmap|masscan|gobuster|dirbuster|hydra|wpscan|python|curl|go-http|zgrab)', u, re.I)]
        return {'total': len(rows), 'top_ips': ips.most_common(15),
                'top_uris': uri_patterns.most_common(20),
                'types': dict(types), 'fp_types': dict(fp_types),
                'tool_uas': tool_ua[:20],
                'strong_attackers': strong_attackers[:20]}

    # ================= 2. 规则生成 =================
    def generate_rules(self, feats):
        """根据特征生成候选规则。auto_apply=auto 自动入库, 否则进入待确认队列"""
        if feats.get('empty'):
            return 0
        re_ = RuleEngine()
        existing = re_.get_rules()
        gen, pending, auto_ip = 0, [], 0
        mode = Conf.get('auto_apply', 'confirm')

        # 2.1 强攻击者 -> IP黑名单
        # auto_apply=confirm 时必须走人工确认, 否则与"生成待确认规则, 杜绝误报"的承诺矛盾
        for a in feats.get('strong_attackers', []):
            if a['confidence'] < 0.6:
                continue
            if any(r['pattern'] == a['ip'] for r in existing.get('ip_black', [])):
                continue
            if mode == 'auto':
                re_.add_rule('ip_black', '自动封禁:%s' % a['ip'], a['ip'],
                             level='high', mode='block',
                             note='自学习: %d次攻击/类型%s' % (a['hits'], ','.join(a['types'])),
                             source='auto')
                gen += 1
                auto_ip += 1
            else:
                pending.append({'type': 'ip_black', 'name': '自动封禁:%s' % a['ip'],
                                'pattern': a['ip'],
                                'reason': '%d次攻击/覆盖类型%s, 置信度%.2f' % (
                                    a['hits'], ','.join(a['types']), a['confidence'])})

        # 2.2 高频工具UA -> UA黑名单
        for ua in feats.get('tool_uas', []):
            m = re.search(r'([a-zA-Z][\w\-]{3,20})/[\d.]+', ua)
            token = m.group(1).lower() if m else None
            if token and len(token) > 3 and not any(
                    token in r['pattern'] for r in existing.get('ua', [])):
                pat = r'\b%s\b' % re.escape(token)
                if mode == 'auto':
                    re_.add_rule('ua', '自动识别工具:%s' % token, pat,
                                 level='medium', mode='block',
                                 note='自学习: 近7天高频工具UA', source='auto')
                    gen += 1
                else:
                    pending.append({'type': 'ua', 'name': '自动识别工具:%s' % token,
                                    'pattern': pat, 'reason': '高频工具UA'})

        # 2.3 高频探测URI -> 敏感路径规则(仅统计型, 高阈值才自动)
        for u, c in feats.get('top_uris', []):
            if c < 30:
                continue
            ext = u.rsplit('.', 1)[-1].split('?')[0].lower()
            if ext in ('env', 'sql', 'bak', 'old', 'git', 'ini', 'yml', 'conf', 'log', 'tar', 'gz'):
                pat = r'\.' + re.escape(ext) + r'(\?|$)'
                if not any(r['pattern'] == pat for r in existing.get('path_scan', [])):
                    if mode == 'auto':
                        re_.add_rule('path_scan', '自动拦截:%s文件' % ext, pat,
                                     level='medium', mode='block',
                                     note='自学习: 近7天被探测%d次' % c, source='auto')
                        gen += 1
                    else:
                        pending.append({'type': 'path_scan', 'name': '自动拦截:%s文件' % ext,
                                        'pattern': pat, 'reason': '近7天被探测%d次' % c})
        if pending:
            self.save_pending(pending)
        # 自动封禁的 IP 必须立刻写入 Nginx 名单并 reload, 否则"封了但没生效"
        if auto_ip:
            self._apply_ip_rules_live()
        return gen

    @staticmethod
    def _apply_ip_rules_live():
        try:
            from waf_deploy import WafDeploy
            from public_base import WebServer
            wd = WafDeploy()
            wd.sync_blacklist_map()
            for web in ('nginx', 'apache'):
                if WebServer.test_config(web) is False:
                    continue
                WebServer.reload(web)
        except Exception:
            pass

    def save_pending(self, items):
        path = os.path.join(VER_DIR, 'pending_rules.json')
        old = F.read_json(path, []) or []
        seen = {x.get('pattern') for x in old}
        for it in items:
            if it['pattern'] not in seen:
                it['ts'] = int(time.time())
                old.append(it)
        F.write_json(path, old[-200:])

    def get_pending(self):
        return F.read_json(os.path.join(VER_DIR, 'pending_rules.json'), []) or []

    def approve_pending(self, pattern, approve=True):
        items = self.get_pending()
        left = []
        n = 0
        for it in items:
            if it.get('pattern') == pattern:
                if approve:
                    RuleEngine().add_rule(it['type'], it['name'], it['pattern'],
                                          level='medium', mode='block',
                                          note='人工确认:' + it.get('reason', ''), source='auto-approved')
                    n += 1
            else:
                left.append(it)
        F.write_json(os.path.join(VER_DIR, 'pending_rules.json'), left)
        return n

    # ================= 3. 规则优化 =================
    def optimize_existing(self):
        """基于命中与误报统计优化既有规则: 高误报降级/静默, 高命中保持"""
        re_ = RuleEngine()
        rules = re_.get_rules()
        changed = 0
        fp_limit = Conf.get('fp_rate_limit', 0.15)
        for t in rules:
            for r in rules[t]:
                hits, fps = r.get('hits', 0), r.get('fp', 0)
                if hits >= 20 and float(fps) / hits > fp_limit and r.get('mode') == 'block':
                    # 误报率过高: block -> 仅记录, 避免影响正常业务
                    r['mode'] = 'log'
                    r['note'] = (r.get('note', '') + ' | 自动降级: 误报率%.0f%%' % (fps * 100 / hits))[-200:]
                    changed += 1
                elif hits == 0 and r.get('source') == 'auto' and \
                        int(time.time()) - r.get('ctime', 0) > 30 * 86400:
                    r['on'] = False   # 30天零命中的自动规则自动休眠
                    changed += 1
        if changed:
            F.write_json(RULE_PATH, rules)
            re_.compile_runtime()
        return {'changed': changed}

    # ================= 4. 效果评估 =================
    def evaluate_rules(self):
        """规则效果评估: 每条规则拦截量 / 误报率 / 全局指标

        全局误报率改为"滚动窗口"统计: 旧实现用全量历史 fp/总数, 一旦误报过就永远
        降不下来, 导致每轮自动回滚, 规则永远无法稳定。
        """
        re_ = RuleEngine()
        rules = re_.get_rules()
        out = []
        for t in rules:
            for r in rules[t]:
                hits, fps = r.get('hits', 0), r.get('fp', 0)
                out.append({'type': t, 'id': r['id'], 'name': r.get('name', ''),
                            'hits': hits, 'fp': fps,
                            'fp_rate': round(float(fps) / hits, 3) if hits else 0,
                            'on': r.get('on', True), 'mode': r.get('mode', 'block'),
                            'source': r.get('source', 'manual')})
        out.sort(key=lambda x: -x['hits'])
        since = int(time.time()) - self.EVAL_WINDOW_DAYS * 86400
        win = DB.execute('SELECT COUNT(*) c, SUM(CASE WHEN fp=1 THEN 1 ELSE 0 END) f '
                         'FROM attack_log WHERE ts>=?', (since,), fetch='one') or {}
        all_total = int(win.get('c') or 0)
        fp_total = int(win.get('f') or 0)
        return {'rules': out[:100], 'fp_total': fp_total, 'all_total': all_total,
                'window_days': self.EVAL_WINDOW_DAYS,
                'fp_rate': round(float(fp_total) / all_total, 4) if all_total else 0}

    # ================= 5. 自动调优与回滚 =================
    def auto_tune(self, ev):
        """全局误报率超限 -> 快照并回滚至上一稳定版本 + 通知"""
        if ev.get('all_total', 0) < 200:
            return {'skip': '样本不足'}   # 避免冷启动误判
        limit = Conf.get('fp_rate_limit', 0.15)
        now = int(time.time())
        if ev.get('fp_rate', 0) <= limit:
            # 正常: 每天最多保存一次稳定版本(旧实现每10分钟写一次, 且只保留20条)
            last = DB.execute("SELECT ts FROM rule_version WHERE tag='stable' "
                              'ORDER BY id DESC LIMIT 1', fetch='one')
            if not last or now - int(last.get('ts') or 0) >= self.STABLE_INTERVAL:
                self.save_version('stable', '%d天误报率%.2f%%' %
                                  (self.EVAL_WINDOW_DAYS, ev['fp_rate'] * 100))
                return {'ok': True, 'rolled_back': False, 'snapshot': True}
            return {'ok': True, 'rolled_back': False}
        # 冷却: 避免误报数据未更新时每轮重复回滚
        last_rb = int(Conf.get('last_rollback_ts', 0) or 0)
        if last_rb and now - last_rb < self.ROLLBACK_COOLDOWN:
            return {'rolled_back': False,
                    'reason': '距上次回滚不足%d小时' % (self.ROLLBACK_COOLDOWN // 3600)}
        ver = self.save_version('before-rollback', '误报率超限%.2f%%' % (ev['fp_rate'] * 100))
        last = DB.execute('SELECT id FROM rule_version WHERE id<? AND tag=? ORDER BY id DESC LIMIT 1',
                          (ver, 'stable'), fetch='one')
        if last:
            RuleEngine().restore(version_id=last['id'])
            Conf.set({'last_rollback_ts': now})
            try:
                from alert_manager import AlertManager
                AlertManager().send('warn', '规则自动回滚',
                                    '近%d天误报率 %.2f%% 超过阈值 %.0f%%, 已自动回滚规则至版本 #%s' % (
                                        self.EVAL_WINDOW_DAYS, ev['fp_rate'] * 100,
                                        limit * 100, last['id']), event='rollback')
            except Exception:
                pass
            self.log('rollback', 'rollback to #%s, fp_rate=%.3f' % (last['id'], ev['fp_rate']))
            return {'rolled_back': True, 'to': last['id']}
        return {'rolled_back': False, 'reason': 'no stable version'}

    def save_version(self, tag, summary=''):
        rules = json.dumps(RuleEngine().get_rules(), ensure_ascii=False)
        path = os.path.join(VER_DIR, '%s_%s.json' % (tag, time.strftime('%Y%m%d')))
        F.write_json(path, {'tag': tag, 'summary': summary,
                            'time': int(time.time()), 'rules': json.loads(rules)})
        vid = DB.execute('INSERT INTO rule_version(ts,tag,summary,rules,active) VALUES(?,?,?,?,1)',
                         (int(time.time()), tag, summary, rules))
        # 版本表瘦身: 每类tag保留20条
        DB.execute("DELETE FROM rule_version WHERE tag=? AND id NOT IN "
                   "(SELECT id FROM rule_version WHERE tag=? ORDER BY id DESC LIMIT 20)", (tag, tag))
        return vid

    def log(self, stage, detail):
        DB.execute('INSERT INTO learn_log(ts,stage,detail) VALUES(?,?,?)',
                   (int(time.time()), stage, detail[:4000]))

    def get_learn_history(self, limit=50):
        rows = DB.execute('SELECT * FROM learn_log ORDER BY id DESC LIMIT ?', (limit,), fetch='all')
        for r in rows:
            r['time_str'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(r['ts']))
            try:
                r['detail'] = json.loads(r['detail'])
            except Exception:
                pass
        return rows
