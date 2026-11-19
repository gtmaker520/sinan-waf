#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 状态下发器: 把"系统运行状态 / 拦截威慑"推送到 Webhook
# 支持 企业微信机器人 / 钉钉机器人 / 通用 Webhook, 每种都可用 Markdown 或纯文本
#   - Markdown: 企微/钉钉客户端内排版好看(标题/引用/加粗/警示色)
#   - 纯文本: 无任何标记, 兼容性最高, 适合转发到个人微信或短信网关
import os, re, json, time, hmac, hashlib, base64

try:
    from urllib.request import Request
    import urllib.request as _u
except ImportError:                       # Python2
    from urllib2 import Request
    import urllib2 as _u

from public_base import F, Conf, DB, PLUGIN_ROOT
from rule_engine import RuleEngine

KINDS = ('wecom', 'dingtalk', 'generic')
FORMATS = ('markdown', 'text')

KIND_NAME = {'wecom': '企业微信机器人', 'dingtalk': '钉钉机器人', 'generic': '通用 Webhook'}
MODE_NAME = {'loose': '宽松', 'standard': '标准', 'strict': '严格'}
RULE_NAME = {
    'sqli': 'SQL注入', 'xss': 'XSS', 'upload': '文件上传', 'trojan': '木马',
    'bot': '恶意爬虫', 'path_scan': '敏感路径', 'url': 'URL', 'ua': 'UA',
    'referer': 'Referer', 'freq': '频率', 'ip_black': 'IP黑名单',
    'ip_white': 'IP白名单', 'ip_region': '地区', 'port_proto': '端口',
}

DEFAULT = {
    'enable': False,
    'url': '',                  # webhook 地址
    'kind': 'wecom',            # wecom / dingtalk / generic
    'format': 'markdown',       # markdown / text
    'secret': '',               # 钉钉加签密钥(可选)
    'status_enable': True,      # 定时推送运行状态
    'status_interval': 6,       # 小时
    'deter_enable': True,       # 达到阈值后推送拦截威慑
    'deter_min': 5,             # 至少这么多条新拦截才推
    'deter_gap': 60,            # 最小间隔(分钟), 防止刷屏
    'last_status_ts': 0,
    'last_deter_ts': 0,
    'last_push_ts': 0,
    'last_result': '',
}

WECOM_MD_LIMIT = 3800
TEXT_LIMIT = 1800


class Notify(object):
    # ================= 配置 =================
    @staticmethod
    def cfg():
        c = dict(DEFAULT)
        c.update(Conf.get('notify', {}) or {})
        return c

    def save(self, kv):
        cur = self.cfg()
        for k in DEFAULT:
            if k in kv:
                cur[k] = kv[k]
        url = str(cur.get('url') or '').strip()
        if url and not re.match(r'^https?://', url, re.I):
            raise ValueError('推送地址必须以 http:// 或 https:// 开头')
        if cur.get('enable') and not url:
            raise ValueError('开启推送前请先填写 Webhook 地址')
        if str(cur.get('kind')) not in KINDS:
            raise ValueError('不支持的机器人类型')
        if str(cur.get('format')) not in FORMATS:
            raise ValueError('不支持的格式，仅 markdown / text')
        cur['url'] = url
        cur['status_interval'] = max(1, min(int(cur.get('status_interval') or 6), 168))
        cur['deter_min'] = max(1, min(int(cur.get('deter_min') or 5), 10000))
        cur['deter_gap'] = max(5, min(int(cur.get('deter_gap') or 60), 1440))
        cur['status_enable'] = bool(cur.get('status_enable'))
        cur['deter_enable'] = bool(cur.get('deter_enable'))
        cur['enable'] = bool(cur.get('enable'))
        Conf.set({'notify': cur})
        Conf.audit('save_notify', '%s %s %s' % (cur['kind'], cur['format'], cur['url'][:80]))
        return cur

    # ================= 数据采集 =================
    def _site_count(self):
        try:
            data = F.read_json(os.path.join(PLUGIN_ROOT, 'waf', 'vhost', '.sites.json'), {}) or {}
            if not Conf.get('waf_on', True):
                return 0
            return len([1 for k, v in data.items() if isinstance(v, dict) and v.get('on')])
        except Exception:
            return 0

    def summary(self):
        now = int(time.time())
        # 自然日零点(本地时区)
        lt = time.localtime(now)
        day0 = int(time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, 0, 0, 0, 0, 0, -1)))
        s = {'now': time.strftime('%m-%d %H:%M', lt), 'today': 0, 'ips': 0, 'week': 0,
             'types': [], 'black': 0, 'pending': 0, 'threats': 0, 'last_scan': '尚未扫描',
             'waf_on': bool(Conf.get('waf_on', True)), 'mode': Conf.get('mode', 'standard'),
             'sites': self._site_count(), 'total_rules': 0, 'on_rules': 0,
             'fp_rate': 0, 'last_attack': None, 'last_analyze': Conf.get('last_analyze') or 0}
        s['mode_name'] = MODE_NAME.get(s['mode'], s['mode'])

        row = DB.execute('SELECT COUNT(*) c FROM attack_log WHERE ts>=? AND fp=0',
                         (day0,), fetch='one') or {}
        s['today'] = int(row.get('c') or 0)
        row = DB.execute('SELECT COUNT(DISTINCT ip) c FROM attack_log WHERE ts>=? AND fp=0',
                         (day0,), fetch='one') or {}
        s['ips'] = int(row.get('c') or 0)
        row = DB.execute('SELECT COUNT(*) c FROM attack_log WHERE ts>=? AND fp=0',
                         (now - 7 * 86400,), fetch='one') or {}
        s['week'] = int(row.get('c') or 0)
        s['types'] = DB.execute(
            'SELECT rule_type t, COUNT(*) c FROM attack_log WHERE ts>=? AND fp=0 '
            'GROUP BY rule_type ORDER BY c DESC LIMIT 3', (day0,), fetch='all') or []

        row = DB.execute('SELECT COUNT(*) c, SUM(fp) f FROM attack_log WHERE ts>=?',
                         (now - 7 * 86400,), fetch='one') or {}
        total7, fp7 = int(row.get('c') or 0), int(row.get('f') or 0)
        s['fp_rate'] = round(float(fp7) / total7, 4) if total7 else 0

        try:
            rules = RuleEngine().get_rules()
            s['total_rules'] = sum(len(v) for v in rules.values())
            s['on_rules'] = sum(1 for v in rules.values() for r in v if r.get('on', True))
            s['black'] = len([r for r in rules.get('ip_black', []) if r.get('on', True)])
        except Exception:
            pass

        try:
            pend = F.read_json(os.path.join(PLUGIN_ROOT, 'versions', 'pending_rules.json'), []) or []
            s['pending'] = len(pend)
        except Exception:
            pass

        row = DB.execute("SELECT COUNT(*) c FROM scan_file WHERE quarantined=0 AND fp=0 "
                         "AND level IN ('critical','high')", fetch='one') or {}
        s['threats'] = int(row.get('c') or 0)
        row = DB.execute('SELECT ts,type,files,threats FROM scan_task ORDER BY id DESC LIMIT 1',
                         fetch='one')
        if row:
            s['last_scan'] = '%s %s（检查 %s 个文件，检出 %s 个）' % (
                time.strftime('%m-%d %H:%M', time.localtime(row['ts'])),
                '全量' if row.get('type') == 'full' else '增量',
                row.get('files', 0), row.get('threats', 0))

        row = DB.execute('SELECT ts,ip,rule_type,rule,uri FROM attack_log '
                         'ORDER BY id DESC LIMIT 1', fetch='one')
        if row:
            s['last_attack'] = '%s ｜ %s ｜ %s' % (
                row.get('ip', ''), RULE_NAME.get(row.get('rule_type'), row.get('rule_type')),
                str(row.get('uri') or '')[:60])
        return s

    # ================= 文案渲染 =================
    @staticmethod
    def _types_txt(types):
        if not types:
            return '暂无'
        return '、'.join('%s %s 次' % (RULE_NAME.get(x['t'], x['t']), x['c']) for x in types)

    def _render(self, title, subtitle, groups, footer, md):
        out = []
        if md:
            out.append('### %s' % title)
            if subtitle:
                out.append('> %s' % subtitle)
        else:
            out.append('【%s】' % title)
            if subtitle:
                out.append(subtitle)
        for name, lines in groups:
            out.append('')
            out.append('**%s**' % name if md else name)
            for ln in lines:
                if ln is None:
                    continue
                out.append(('- %s' % ln) if md else ('· %s' % ln))
        if footer:
            out.append('')
            out.append(('<font color="comment">%s</font>' % footer) if md else ('—— %s' % footer))
        return '\n'.join(out)

    def build_status(self, md=True):
        """系统运行状态消息"""
        s = self.summary()
        b = (lambda x: '**%s**' % x) if md else (lambda x: str(x))
        w = (lambda x: '<font color="warning">%s</font>' % x) if md else (lambda x: str(x))
        state = w('运行中') if s['waf_on'] else w('已关闭')
        subtitle = '防护：%s ｜ 模式：%s ｜ 站点：%s 个 ｜ 更新：%s' % (
            state, s['mode_name'], b(s['sites']), s['now'])
        groups = [
            ('拦截概况（今日）', [
                '拦截请求：%s 次' % b(s['today']),
                '涉及 IP：%s 个 ｜ 黑白名单：%s 条' % (b(s['ips']), b(s['black'])),
                '主要类型：%s' % self._types_txt(s['types']),
            ]),
            ('规则与自学习', [
                '启用规则：%s / 共 %s 条' % (b(s['on_rules']), b(s['total_rules'])),
                '近 7 天误报率：%s' % b('%.1f%%' % (s['fp_rate'] * 100)),
                '待确认规则：%s 条' % b(s['pending']),
                '最近分析：%s' % (time.strftime('%m-%d %H:%M', time.localtime(s['last_analyze']))
                              if s['last_analyze'] else '尚未分析'),
            ]),
            ('木马查杀', [
                '待处理高危：%s 个' % w(s['threats']) if s['threats'] else '待处理高危：0 个',
                '最近扫描：%s' % s['last_scan'],
            ]),
        ]
        if s['last_attack']:
            groups.append(('最近拦截', [s['last_attack']]))
        return self._render('司南防火墙 · 运行状态', subtitle, groups,
                            '由司南防火墙自动推送，可在插件「告警中心」调整频率或关闭', md)

    def build_deter(self, md=True):
        """拦截威慑消息(适合推送到群里)"""
        s = self.summary()
        b = (lambda x: '**%s**' % x) if md else (lambda x: str(x))
        w = (lambda x: '<font color="warning">%s</font>' % x) if md else (lambda x: str(x))
        subtitle = '本站已启用智能 WAF 防护，攻击行为将被记录并自动封禁'
        groups = [('今日防护战报', [
            '拦截恶意请求：%s 次' % w(s['today']),
            '涉及来源 IP：%s 个' % b(s['ips']),
            '已封禁名单：%s 条' % b(s['black']),
            '主要攻击类型：%s' % self._types_txt(s['types']),
        ]), ('累计防护（近 7 天）', [
            '累计拦截：%s 次' % b(s['week']),
        ])]
        if s['last_attack']:
            groups.append(('最近拦截', [s['last_attack']]))
        return self._render('司南防火墙 · 拦截威慑', subtitle, groups,
                            '攻击已留痕，持续攻击将自动封禁并上报', md)

    def build(self, msg_kind='status', fmt='markdown'):
        md = str(fmt) != 'text'
        text = self.build_deter(md) if str(msg_kind) == 'deter' else self.build_status(md)
        title = '司南防火墙 · 拦截威慑' if str(msg_kind) == 'deter' else '司南防火墙 · 运行状态'
        return title, text

    # ================= 发送 =================
    def build_payload(self, msg_kind='status', fmt=None):
        c = self.cfg()
        fmt = fmt or c.get('format') or 'markdown'
        md_flag = str(fmt) != 'text'
        title, content = self.build(msg_kind, fmt)
        md_content = self.build(msg_kind, 'markdown')[1]
        text_content = self.build(msg_kind, 'text')[1]
        kind = c.get('kind') or 'wecom'
        if kind == 'wecom':
            if md_flag:
                return {'msgtype': 'markdown',
                        'markdown': {'content': content[:WECOM_MD_LIMIT]}}, title
            return {'msgtype': 'text', 'text': {'content': content[:TEXT_LIMIT]}}, title
        if kind == 'dingtalk':
            if md_flag:
                return {'msgtype': 'markdown',
                        'markdown': {'title': title, 'text': content[:WECOM_MD_LIMIT]}}, title
            return {'msgtype': 'text', 'text': {'content': content[:TEXT_LIMIT]}}, title
        # 通用 Webhook: 同时给出两种格式, 由接收端自行取用
        return {'source': 'sinanwaf', 'type': msg_kind, 'title': title,
                'format': fmt, 'content': content,
                'markdown': md_content[:WECOM_MD_LIMIT], 'text': text_content[:TEXT_LIMIT],
                'time': time.strftime('%Y-%m-%d %H:%M:%S')}, title

    @staticmethod
    def _sign_url(url, secret):
        """钉钉加签: timestamp + HMAC-SHA256"""
        ts = str(int(round(time.time() * 1000)))
        sign = base64.b64encode(hmac.new(secret.encode('utf-8'),
                                         ('%s\n%s' % (ts, secret)).encode('utf-8'),
                                         hashlib.sha256).digest())
        if isinstance(sign, bytes):
            sign = sign.decode('ascii')
        try:
            from urllib.parse import quote_plus as _qp
        except ImportError:               # Python2
            from urllib import quote_plus as _qp
        sep = '&' if '?' in url else '?'
        return '%s%stimestamp=%s&sign=%s' % (url, sep, ts, _qp(sign))

    def _post(self, url, payload, secret=''):
        body = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        req = Request(url, data=body, headers={'Content-Type': 'application/json'})
        try:
            resp = _u.urlopen(req, timeout=8)
            code = resp.getcode()
            raw = resp.read(400).decode('utf-8', 'ignore')
            ok = code == 200
            # 企微/钉钉在 200 里也可能返回 errcode
            if ok and raw:
                try:
                    j = json.loads(raw)
                    if j.get('errcode') not in (None, 0):
                        ok = False
                        raw = str(j.get('errmsg') or raw)
                except Exception:
                    pass
            return ok, ('' if ok else ('HTTP %s %s' % (code, raw))[:200])
        except Exception as e:
            return False, str(e)[:200]

    def send(self, msg_kind='status'):
        c = self.cfg()
        if not c.get('url'):
            return {'ok': False, 'msg': '未配置 Webhook 地址'}
        payload, title = self.build_payload(msg_kind, c.get('format'))
        url = c['url']
        if c.get('kind') == 'dingtalk' and c.get('secret'):
            try:
                url = self._sign_url(url, c['secret'])
            except Exception:
                pass
        ok, err = self._post(url, payload, c.get('secret'))
        now = int(time.time())
        level = 'info'
        try:
            DB.execute('INSERT INTO alerts(ts,channel,level,title,body,ok,cool_key) '
                       'VALUES(?,?,?,?,?,?,?)',
                       (now, 'push:%s' % msg_kind, level, title,
                        (payload.get('markdown', {}).get('content') if isinstance(payload.get('markdown'), dict)
                         else payload.get('content', ''))[:2000], 1 if ok else 0,
                        'push|%s|%s' % (msg_kind, now // 600)))
        except Exception:
            pass
        upd = {'last_push_ts': now,
               'last_result': ('%s 推送成功' % KIND_NAME.get(c.get('kind'), c.get('kind')))
               if ok else ('推送失败: %s' % err)}
        if msg_kind == 'status':
            upd['last_status_ts'] = now
        elif msg_kind == 'deter':
            upd['last_deter_ts'] = now
        cur = self.cfg()
        cur.update(upd)
        try:
            Conf.set({'notify': cur})
        except Exception:
            pass
        return {'ok': ok, 'msg': upd['last_result'], 'kind': msg_kind,
                'format': c.get('format'), 'title': title}

    # ================= 计划任务调用 =================
    def maybe_push(self):
        c = self.cfg()
        if not c.get('enable') or not c.get('url'):
            return {'skip': 'disabled'}
        now = int(time.time())
        out = {}
        try:
            if c.get('status_enable'):
                gap = int(c.get('status_interval') or 6) * 3600
                if now - int(c.get('last_status_ts') or 0) >= gap:
                    out['status'] = self.send('status')
            if c.get('deter_enable'):
                since = max(int(c.get('last_deter_ts') or 0), now - 86400)
                row = DB.execute('SELECT COUNT(*) c FROM attack_log WHERE ts>=? AND fp=0',
                                 (since,), fetch='one') or {}
                n = int(row.get('c') or 0)
                gap = int(c.get('deter_gap') or 60) * 60
                if n >= int(c.get('deter_min') or 5) and now - int(c.get('last_deter_ts') or 0) >= gap:
                    out['deter'] = self.send('deter')
        except Exception as e:
            out['error'] = str(e)
        return out or {'skip': 'not_due'}

    # ================= 预览 =================
    def preview(self):
        return {
            'status': {'markdown': self.build_status(True), 'text': self.build_status(False)},
            'deter': {'markdown': self.build_deter(True), 'text': self.build_deter(False)},
        }
