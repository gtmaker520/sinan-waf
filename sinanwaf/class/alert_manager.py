#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 多通道告警: Webhook / 钉钉 / 企业微信 / 宝塔邮件通道
# 特性: 级别过滤、同类告警冷却(防轰炸)、摘要批量发送、发送历史入库
import os, re, json, time, socket, ssl
try:
    from urllib.request import Request as _Req
    import urllib.request as _u
except ImportError:
    from urllib2 import Request as _Req
    import urllib2 as _u
from public_base import Conf, DB, PLUGIN_ROOT, Lock, F

LEVELS = {'info': 0, 'warn': 1, 'high': 2, 'critical': 3}


class AlertManager(object):
    def __init__(self):
        self._mu = Lock.get('alert')

    # ---------- 告警入口 ----------
    @staticmethod
    def _cool_key(title):
        """冷却键: 把标题里的 IP/数字归一化, 让"同一类告警"共享冷却(旧版按完整标题去重, 几乎不生效)"""
        import re as _re
        return _re.sub(r'\d{1,3}(?:\.\d{1,3}){3}', 'IP',
                       _re.sub(r'\d+', 'N', str(title or '')))[:120]

    @staticmethod
    def _in_silence(cfg):
        """静默时段(如 23:00-07:00): 期间不发送非强制告警, 支持跨零点"""
        s = cfg.get('silence') or {}
        if not s.get('enable'):
            return False

        def _m(v):
            h, _, mi = str(v or '0:0').partition(':')
            return int(h or 0) * 60 + int(mi or 0)

        try:
            now = time.localtime()
            cur = now.tm_hour * 60 + now.tm_min
            start, end = _m(s.get('start', '23:00')), _m(s.get('end', '07:00'))
        except (TypeError, ValueError):
            return False
        if start == end:
            return False
        return (start <= cur < end) if start < end else (cur >= start or cur < end)

    @staticmethod
    def _channel_accepts(ch, level, event):
        """通道级过滤: 临时停用 + 最低级别 + 关心的事件类型; event='*' 表示测试消息"""
        if ch.get('enable') is False:      # 单独停用的通道不参与发送
            return False
        if event == '*':
            return True
        ml = str(ch.get('min_level') or '')
        if ml and LEVELS.get(level, 0) < LEVELS.get(ml, 0):
            return False
        evs = ch.get('events')
        if isinstance(evs, list) and evs and event not in evs:
            return False
        return True

    def send(self, level, title, body, force=False, event='attack', only_index=None):
        cfg = Conf.get('alert', {})
        if not cfg.get('enable') and not force:
            return False
        if LEVELS.get(level, 0) < LEVELS.get(cfg.get('min_level', 'warn'), 1) and not force:
            return False
        if not force and self._in_silence(cfg):
            return False
        # 冷却: 同类告警在冷却期内只发一次
        cool = int(cfg.get('cooldown', 300))
        key = self._cool_key(title)
        last = DB.execute('SELECT ts FROM alerts WHERE cool_key=? ORDER BY id DESC LIMIT 1',
                          (key,), fetch='one')
        if last and not force and int(time.time()) - last['ts'] < cool:
            return False
        results = []
        for idx, ch in enumerate(cfg.get('channels', [])):
            if only_index is not None and int(only_index) != idx:
                continue
            if not self._channel_accepts(ch, level, event):
                continue
            ok = False
            try:
                ok = bool(getattr(self, '_send_' + ch['type'])(ch, level, title, body))
            except Exception:
                ok = False
            results.append({'channel': ch.get('type'), 'name': ch.get('name', ''), 'ok': ok})
            try:
                DB.execute('INSERT INTO alerts(ts,channel,level,title,body,ok,cool_key) '
                           'VALUES(?,?,?,?,?,?,?)',
                           (int(time.time()), ch.get('type'), level, title,
                            body[:4000], 1 if ok else 0, key))
            except Exception:
                pass
        return results

    def _send_webhook(self, ch, level, title, body):
        data = json.dumps({'title': title, 'level': level, 'body': body,
                           'time': time.strftime('%Y-%m-%d %H:%M:%S')})
        return self._post(ch['url'], data, ch.get('secret'))

    def _send_dingtalk(self, ch, level, title, body):
        data = json.dumps({
            'msgtype': 'markdown',
            'markdown': {'title': '【%s】%s' % (level, title),
                         'text': '### 司南防火墙告警\n**级别**: %s\n**%s**\n\n%s\n\n%s' % (
                             level, title, body, time.strftime('%Y-%m-%d %H:%M:%S'))}})
        return self._post(ch['url'], data, ch.get('secret'))

    def _send_wecom(self, ch, level, title, body):
        data = json.dumps({'msgtype': 'text',
                           'text': {'content': '【司南防火墙 %s】%s\n%s' % (level, title, body[:1800])}})
        return self._post(ch['url'], data)

    def _send_mail(self, ch, level, title, body):
        """走宝塔面板内置邮件(sendmail/smtp)模块"""
        try:
            import public
            if hasattr(public, 'send_mail'):
                return public.send_mail(title, body)
        except Exception:
            pass
        # 退化为本地 sendmail
        try:
            import smtplib
            from email.mime.text import MIMEText
            msg = MIMEText(body, 'plain', 'utf-8')
            msg['Subject'] = '[sinanwaf %s] %s' % (level, title)
            msg['From'] = ch.get('from', 'sinanwaf@localhost')
            msg['To'] = ch['to']
            s = smtplib.SMTP(ch.get('smtp', '127.0.0.1'), int(ch.get('port', 25)), timeout=10)
            if ch.get('ssl'):
                s.starttls()
            if ch.get('user'):
                s.login(ch['user'], ch['password'])
            s.sendmail(msg['From'], [ch['to']], msg.as_string())
            s.quit()
            return True
        except Exception:
            return False

    def _post(self, url, data, secret=None):
        if secret and 'oapi.dingtalk.com' in url:
            # 钉钉机器人加签: sign = base64(hmac_sha256(secret, timestamp+"\n"+secret))
            try:
                import hmac, hashlib, base64
                try:
                    from urllib.parse import quote_plus
                except ImportError:
                    from urllib import quote_plus
                ts = str(int(time.time() * 1000))
                digest = hmac.new(secret.encode('utf-8'),
                                  ('%s\n%s' % (ts, secret)).encode('utf-8'),
                                  hashlib.sha256).digest()
                url += ('&' if '?' in url else '?') + 'timestamp=%s&sign=%s' % (
                    ts, quote_plus(base64.b64encode(digest)))
            except Exception:
                pass
        req = _Req(url, data=data.encode('utf-8'),
                   headers={'Content-Type': 'application/json'})
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            resp = _u.urlopen(req, timeout=8, context=ctx)
            return resp.getcode() == 200
        except Exception:
            return False

    # ---------- 攻击实时告警（由分析器触发） ----------
    def on_attack(self, hits, ip, uri):
        """高频攻击者触发即时告警"""
        if len(hits) >= 3:
            self.send('high', '检测到高频攻击行为: %s' % ip,
                      'IP: %s\nURI: %s\n命中规则: %s' % (ip, uri[:200],
                                                        '、'.join(set(h['rule'] for h in hits))),
                      event='attack')

    # ---------- 摘要（计划任务每10分钟调用, 低频发送） ----------
    def flush_digest(self):
        since = int(time.time()) - 600
        row = DB.execute('SELECT COUNT(*) c FROM attack_log WHERE ts>=?', (since,), fetch='one')
        if not row['c']:
            return False
        types = DB.execute('SELECT rule_type t, COUNT(*) c FROM attack_log WHERE ts>=? '
                           'GROUP BY t ORDER BY c DESC LIMIT 5', (since,), fetch='all')
        top = DB.execute('SELECT ip, COUNT(*) c FROM attack_log WHERE ts>=? '
                         'GROUP BY ip ORDER BY c DESC LIMIT 5', (since,), fetch='all')
        body = '近10分钟拦截攻击 %d 次\n类型: %s\nTop IP: %s' % (
            row['c'],
            ', '.join('%s(%d)' % (r['t'], r['c']) for r in types),
            ', '.join('%s(%d)' % (r['ip'], r['c']) for r in top))
        if row['c'] >= 100:
            return self.send('critical', '攻击高峰: 10分钟内%d次' % row['c'], body,
                             force=True, event='digest')
        return self.send('info', '防护摘要: 10分钟内%d次' % row['c'], body, event='digest')

    # ---------- 历史 ----------
    def history(self, page=1, limit=20):
        total = DB.execute('SELECT COUNT(*) c FROM alerts', fetch='one')['c']
        rows = DB.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT ? OFFSET ?',
                          (limit, (page - 1) * limit), fetch='all')
        for r in rows:
            r['time_str'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(r['ts']))
        return {'total': total, 'rows': rows}
