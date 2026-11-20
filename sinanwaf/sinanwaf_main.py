#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 司南防火墙 - 宝塔面板插件主入口
# 面板通过 /plugin?action=a&name=sinanwaf&s=<方法名> 调用下方 public 方法
# 权限: 依赖面板登录态; 插件内再做细粒度权限(角色)与操作审计
import os, re, sys, json, time, traceback, threading

PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PLUGIN_DIR)
sys.path.insert(0, os.path.join(PLUGIN_DIR, 'class'))

from public_base import Conf, DB, F, PLUGIN_ROOT, PLUGIN_DIR, WebServer, S, FLock
from rule_engine import RuleEngine, RULE_TYPES
from log_analyzer import LogAnalyzer
from waf_deploy import WafDeploy
from ai_optimizer import AiOptimizer
from alert_manager import AlertManager
from antivirus import Antivirus
from notify import Notify


class main(object):
    def __init__(self):
        DB.init_db()
        RuleEngine().init_default_rules()
        self.re = RuleEngine()
        self.la = LogAnalyzer()
        self.wd = WafDeploy()
        self.ao = AiOptimizer()
        self.am = AlertManager()
        self.av = Antivirus()
        self.nf = Notify()

    # ---------- 权限检查 ----------
    def _current_role(self, get):
        """解析当前登录用户角色

        优先级:
          1. 面板反向代理注入的 role 参数（最可靠, 需要一个注入点）
          2. 面板会话用户名（BT_USER / 请求参数 admin_user）-> settings.json 的 user_roles 映射
          3. 兜底 admin（与旧版本行为一致, 不会因为拿不到用户而锁死管理入口）
        """
        role = str(getattr(get, 'role', '') or '').strip()
        if role:
            return role
        user = str(getattr(get, 'admin_user', '') or '').strip() or \
            str(os.environ.get('BT_USER', '') or os.environ.get('USER', '') or '').strip()
        mapping = Conf.get('user_roles', {}) or {}
        if user and isinstance(mapping, dict) and user in mapping:
            return str(mapping[user])
        return 'admin'

    def _check_perm(self, perm, get):
        role = self._current_role(get)
        perms = Conf.get('permissions', {}).get(role, [])
        if '*' in perms or perm in perms:
            return role
        raise RuntimeError('当前角色[%s]无权限执行此操作' % role)

    def _resp(self, ok, data=None, msg=''):
        return {'status': True if ok else False, 'data': data, 'msg': msg}

    @staticmethod
    def _req_id(get):
        """取记录 ID: 面板传入的 get 对象缺字段时抛 AttributeError, 统一做健壮解析"""
        v = str(getattr(get, 'id', '') or '')
        if not v.isdigit():
            raise ValueError('缺少记录 ID')
        return int(v)

    # ================= 总览 =================
    def GetOverview(self, get):
        self._check_perm('view', get)
        try:
            st = self.la.get_stats(days=1)
        except Exception:
            st = {'total': 0, 'today': 0}
        try:
            scan = self.av.get_stats()
        except Exception:
            scan = {'levels': [], 'quarantined': 0}
        try:
            pending = len(self.ao.get_pending())
        except Exception:
            pending = 0
        return self._resp(True, {
            'waf_on': Conf.get('waf_on'),
            'mode': Conf.get('mode'),
            'today_attacks': st.get('today', 0),
            'total_rules': sum(len(v) for v in self.re.get_rules().values()),
            'auto_learn': Conf.get('auto_learn'),
            'auto_apply': Conf.get('auto_apply'),
            'fp_rate': self.ao.evaluate_rules().get('fp_rate', 0),
            'fp_window': self.ao.EVAL_WINDOW_DAYS,
            'server_status': self.wd.status(),
            'scan_threats': scan['levels'],
            'scan_quarantined': scan['quarantined'],
            'pending_rules': pending,
            'last_analyze': self._last_analyze_time(),
            'sites': len(WebServer.get_sites())
        })

    @staticmethod
    def _last_analyze_time():
        p = os.path.join(PLUGIN_ROOT, 'tmp', 'log_pos.json')
        try:
            return int(os.path.getmtime(p))
        except OSError:
            return 0

    # ================= 开关与模式 =================
    def SetWafStatus(self, get):
        """真正的一键启停: 重写所有已注入站点的WAF配置 -> 校验 -> reload"""
        self._check_perm('toggle', get)
        on = str(getattr(get, 'on', '0')) == '1'
        try:
            r = self.wd.enable_all(on)
            Conf.audit('set_waf_status', on)
            return self._resp(True, r, '防火墙已%s, %d个站点已联动' %
                              ('开启' if on else '关闭', len(r.get('sites', []))))
        except Exception as e:
            return self._resp(False, msg='启停失败(已回滚): %s' % e)

    def DeployGlobal(self, get):
        """手动重新部署全局层(Nginx/Apache限速zone、黑名单、模块)"""
        self._check_perm('toggle', get)
        try:
            r = self.wd.deploy_global()
            return self._resp(True, r, self._deploy_msg('全局WAF配置', r))
        except Exception as e:
            return self._resp(False, msg='全局WAF配置下发失败: %s' % e)

    def GetWafStatus(self, get):
        self._check_perm('view', get)
        return self._resp(True, self.wd.status())

    def GetSitePreview(self, get):
        """预览站点将要写入的 Nginx/Apache 配置与 vhost 注入状态(只读, 不改动文件)"""
        self._check_perm('view', get)
        site = str(getattr(get, 'site', '') or '')
        if not site:
            return self._resp(False, msg='缺少站点参数')
        try:
            return self._resp(True, self.wd.site_preview(site))
        except Exception as e:
            return self._resp(False, msg='生成预览失败: %s' % e)

    def GetDeployReport(self, get):
        """最近一次下发结果 + 各站点最近一次下发状态"""
        self._check_perm('view', get)
        try:
            return self._resp(True, self.wd.deploy_report())
        except Exception as e:
            return self._resp(False, msg=str(e))

    def ExportStats(self, get):
        """统计报表导出(CSV/JSON), 浏览器直接下载"""
        self._check_perm('view', get)
        try:
            days = int(getattr(get, 'days', 7) or 7)
            fmt = str(getattr(get, 'fmt', '') or 'csv').lower()
            if fmt not in ('csv', 'json'):
                fmt = 'csv'
            path, content, mime, fname = self.la.export_stats(days, fmt)
            return self._resp(True, {'path': path, 'filename': fname,
                                     'content': content, 'mime': mime}, '统计已导出')
        except Exception as e:
            return self._resp(False, msg='导出失败: %s' % e)

    def GetDeployPreview(self, get):
        """规则下发预览: 哪些规则会真正写入 Web 服务器配置, 哪些被跳过"""
        self._check_perm('view', get)
        return self._resp(True, self.wd.deploy_preview())

    @staticmethod
    def _deploy_msg(title, r):
        """把下发结果(成功/失败/跳过)如实反馈给界面, 不再固定提示"已下发" """
        r = r or {}
        fail = r.get('fail') or []
        ok = r.get('ok')
        parts = []
        if isinstance(ok, list):
            parts.append('成功 %d 个站点' % len(ok))
        elif r.get('nginx') or r.get('apache'):
            parts.append('已生效: ' + ','.join([w for w in ('nginx', 'apache') if r.get(w)]))
        if fail:
            detail = '; '.join([('%s(%s)' % (x.get('site'), x.get('error'))) if isinstance(x, dict) else str(x)
                                for x in fail[:3]])
            parts.append('失败 %d 个: %s' % (len(fail), detail))
        if r.get('skipped'):
            parts.append('未开启防护 %d 个' % len(r['skipped']))
        if r.get('errors'):
            parts.append('错误: ' + '; '.join(r['errors'][:2]))
        return '%s %s' % (title, ('，'.join(parts) if parts else '已执行'))

    def SyncPortRules(self, get):
        """端口/协议规则下发系统防火墙(需先显式开启 port_enforce; 支持 dry_run 预演)"""
        self._check_perm('admin', get)
        try:
            dry = str(getattr(get, 'dry_run', '0')) == '1'
            r = self.wd.sync_port_rules(dry_run=dry)
            if r.get('skip'):
                return self._resp(False, r, r.get('msg'))
            if dry:
                return self._resp(True, r, '预演: 将封禁 %s, 跳过 %d 条' %
                                  (','.join(r.get('plan') or []) or '无', len(r.get('ignored') or [])))
            msg = '已下发 %d 条端口规则' % len(r.get('applied') or [])
            if r.get('failed'):
                msg += '，失败 %d 条' % len(r['failed'])
            if r.get('ignored'):
                msg += '，跳过 %d 条(受保护/格式错误)' % len(r['ignored'])
            msg += ('，已持久化' if r.get('persisted') else '，未持久化(重启后失效)')
            return self._resp(True, r, msg)
        except Exception as e:
            return self._resp(False, msg='端口规则下发失败: %s' % e)

    def SetPortEnforce(self, get):
        """显式开关: 端口规则是否允许下发到系统防火墙"""
        self._check_perm('admin', get)
        on = str(getattr(get, 'on', '0')) == '1'
        Conf.set({'port_enforce': on})
        Conf.audit('set_port_enforce', on)
        return self._resp(True, {'port_enforce': on},
                          '已开启端口强制封禁' if on else '已关闭端口强制封禁(不再改动系统防火墙)')

    def GetDeployLog(self, get):
        """最近一次部署记录"""
        self._check_perm('view', get)
        return self._resp(True, self.wd.status().get('last_deploy') or {})

    def SetMode(self, get):
        self._check_perm('toggle', get)
        mode = str(getattr(get, 'mode', '') or '')
        if mode not in ('loose', 'standard', 'strict'):
            return self._resp(False, msg='无效模式')
        Conf.set({'mode': mode})
        # 只重新下发"已开启防护"的站点, 不再给未开启站点隐式注入配置
        r = self.wd.deploy_all_sites()
        Conf.audit('set_mode', '%s %s' % (mode, r))
        return self._resp(True, r, '防护模式已切换为%s并重新下发(%s)' % (mode, self._deploy_msg('', r).strip()))

    def ReloadWaf(self, get):
        self._check_perm('toggle', get)
        m = self.wd.sync_blacklist_map()
        r = self.wd.deploy_all_sites()
        return self._resp(True, dict(r, blacklist=m),
                          self._deploy_msg('WAF配置', r) +
                          ('；名单写入 %d 条' % m.get('written', 0) if m.get('written') else ''))

    def SetAutoLearn(self, get):
        """自学习总开关(旧版本该配置只展示、不生效)"""
        self._check_perm('ai', get)
        on = str(getattr(get, 'on', '0')) == '1'
        Conf.set({'auto_learn': on})
        Conf.audit('set_auto_learn', on)
        return self._resp(True, {'auto_learn': on}, '自学习已%s' % ('开启' if on else '关闭'))

    # ================= 规则管理 =================
    def GetRules(self, get):
        self._check_perm('view', get)
        t = getattr(get, 'rule_type', None)
        return self._resp(True, self.re.get_rules(t))

    def GetRulePage(self, get):
        """服务端分页(IP 名单): 避免规则量大时把全量数据取到前端再过滤"""
        self._check_perm('view', get)
        rt = str(getattr(get, 'rule_type', '') or '')
        if rt not in RULE_TYPES:
            return self._resp(False, msg='无效的规则类型')
        only_on = None
        on_flag = str(getattr(get, 'on', '') or '')
        if on_flag in ('0', '1'):
            only_on = on_flag == '1'
        return self._resp(True, self.re.page_rules(
            rt,
            page=int(getattr(get, 'page', 1) or 1),
            limit=int(getattr(get, 'limit', 20) or 20),
            keyword=getattr(get, 'keyword', '') or '',
            only_on=only_on))

    def PurgeExpiredRules(self, get):
        """清理已到期的临时封禁规则并重新下发"""
        self._check_perm('rule', get)
        removed = self.re.purge_expired()
        if not removed:
            return self._resp(True, {'removed': []}, '没有到期的临时规则')
        self._apply_ip_rules()
        r = self.wd.deploy_all_sites()
        return self._resp(True, {'removed': removed}, '已解封 %d 条到期规则(%s)' %
                          (len(removed), self._deploy_msg('', r).strip()))

    def TestRule(self, get):
        """规则测试: 用给定 URI/UA/Referer 走一遍规则匹配, 预判误伤(不下发任何配置)"""
        self._check_perm('view', get)
        # 未填 IP 时不做名单匹配, 避免 127.0.0.1 命中默认白名单导致"任何请求都不拦截"的误导结果
        ip = str(getattr(get, 'ip', '') or '')
        try:
            hits = self.la.match_request(
                ip=ip, method=str(getattr(get, 'method', 'GET') or 'GET'),
                uri=str(getattr(get, 'uri', '') or '/'),
                ua=str(getattr(get, 'ua', '') or ''),
                referer=str(getattr(get, 'referer', '') or ''))
        except Exception as e:
            return self._resp(False, msg='测试失败: %s' % e)
        white = bool(ip) and any(r.get('pattern') == ip and r.get('on', True)
                                 for r in self.re.get_rules('ip_white'))
        return self._resp(True, {'hits': hits, 'count': len(hits), 'ip': ip or '(未指定)',
                                 'whitelisted': white})

    def _apply_ip_rules(self):
        """IP 名单变更后: 重写黑白名单文件 -> 语法校验 -> reload(失败保留原配置不中断服务)"""
        m = self.wd.sync_blacklist_map()
        done = []
        for web in ('nginx', 'apache'):
            try:
                if WebServer.test_config(web) is False:
                    continue
                if WebServer.reload(web):
                    done.append(web)
            except Exception:
                continue
        self._ip_apply_note = self._apply_note(done, m)
        return done

    @staticmethod
    def _apply_note(done, m):
        """名单变更后的提示: 未重载/未写入的条目要明确告知, 避免"以为封了" """
        note = ''
        if not done:
            note += '；Web 服务未重载，请到"系统诊断"检查'
        if m and m.get('skipped_count'):
            note += '；%d 条规则格式无法写入 Nginx 名单' % m['skipped_count']
        return note

    def _after_rule_change(self, rt):
        """规则发生变化后立刻下发, 让"启停/新增规则"真正影响拦截而不是只写日志"""
        if rt in ('ip_black', 'ip_white'):
            self._apply_ip_rules()
            return getattr(self, '_ip_apply_note', '') or ''
        note = ''
        if rt in ('url', 'ua', 'referer', 'sqli', 'xss', 'upload',
                  'trojan', 'bot', 'path_scan', 'freq'):
            try:
                if rt == 'freq':
                    # 频率规则会新增 map/zone, 必须先刷新全局文件再生成站点配置
                    self.wd.deploy_global()
                r = self.wd.deploy_all_sites()
                if r.get('fail'):
                    note += '；%d 个站点配置下发失败，请到系统诊断查看' % len(r['fail'])
                elif not r.get('ok'):
                    note += '；当前没有已开启防护的站点，规则暂未生效'
            except Exception as e:
                note += '；站点配置下发失败: %s' % e
        elif rt == 'port_proto' and Conf.get('port_enforce'):
            try:
                self.wd.sync_port_rules()
            except Exception:
                pass
        return note

    def AddRule(self, get):
        self._check_perm('rule', get)
        try:
            rt = str(getattr(get, 'rule_type', '') or '')
            if rt not in RULE_TYPES:
                return self._resp(False, msg='无效的规则类型')
            name = str(getattr(get, 'name', '') or '')
            pattern = str(getattr(get, 'pattern', '') or '')
            level = str(getattr(get, 'level', '') or 'high')
            mode = str(getattr(get, 'mode', '') or 'block')
            note = str(getattr(get, 'note', '') or '')
            if not pattern:
                return self._resp(False, msg='规则内容不能为空')
            expire_at = self._ttl_to_ts(getattr(get, 'ttl_hours', 0))
            rate = str(getattr(get, 'rate', '') or '')
            burst = getattr(get, 'burst', 0)
            if rt == 'freq' and not rate:
                return self._resp(False, msg='频率规则需要填写速率，如 10r/s')
            rid = self.re.add_rule(rt, name, pattern, level, mode, note, expire_at=expire_at,
                                   rate=rate, burst=burst)
            extra = '，%s' % time.strftime('%m-%d %H:%M 自动解封',
                                          time.localtime(expire_at)) if expire_at else ''
            return self._resp(True, rid, '规则已添加' + extra + self._after_rule_change(rt))
        except Exception as e:
            return self._resp(False, msg=str(e))

    @staticmethod
    def _ttl_to_ts(hours):
        """小时数 -> 到期时间戳(0=永久, 上限 365 天)"""
        try:
            h = float(hours or 0)
        except (TypeError, ValueError):
            return 0
        if h <= 0:
            return 0
        return int(time.time() + min(h, 24 * 365) * 3600)

    def BatchAddIpBlack(self, get):
        """批量封禁: 粘贴文本中的 IP / 网段 / 区间(x.x.x.0-x.x.x.255) -> IP黑名单"""
        self._check_perm('rule', get)
        try:
            raw = getattr(get, 'patterns', '') or ''
            pats = S.extract_ip_patterns(raw)
            if not pats:
                return self._resp(False, msg='未识别到有效 IP')
            expire_at = self._ttl_to_ts(getattr(get, 'ttl_hours', 0))
            r = self.re.add_rules_bulk('ip_black', pats, source='paste', note='批量封禁',
                                       expire_at=expire_at)
            note = self._after_rule_change('ip_black') if r['added'] else ''
            msg = '已封禁 %d 条' % r['added']
            if expire_at:
                msg += '(至 %s 自动解封)' % time.strftime('%m-%d %H:%M', time.localtime(expire_at))
            if r['duplicated']:
                msg += ', 重复 %d 条' % r['duplicated']
            if r['invalid']:
                msg += ', 无效 %d 条' % r['invalid']
            Conf.audit('batch_black', msg)
            return self._resp(True, r, msg + note)
        except Exception as e:
            return self._resp(False, msg='批量封禁失败: %s' % e)

    def BatchDelRule(self, get):
        """批量删除规则(IP名单常用): ids 逗号分隔; all=1 清空该类型"""
        self._check_perm('rule', get)
        try:
            rt = str(getattr(get, 'rule_type', '') or '')
            if rt not in RULE_TYPES:
                return self._resp(False, msg='无效的规则类型')
            ids = [x.strip() for x in str(getattr(get, 'ids', '') or '').split(',') if x.strip()]
            all_flag = str(getattr(get, 'all', '0')) == '1'
            keyword = str(getattr(get, 'keyword', '') or '').strip()
            if not ids and not all_flag:
                return self._resp(False, msg='请先选择要删除的规则')
            n = self.re.del_rules(rt, ids, all_flag, keyword=keyword)
            note = self._after_rule_change(rt) if n else ''
            scope = '（按搜索条件 %s）' % keyword if (keyword and all_flag) else ''
            return self._resp(True, {'deleted': n}, '已删除 %d 条%s' % (n, scope) + note)
        except Exception as e:
            return self._resp(False, msg='批量删除失败: %s' % e)

    def DelRule(self, get):
        self._check_perm('rule', get)
        try:
            rt = str(getattr(get, 'rule_type', '') or '')
            if rt not in RULE_TYPES:
                return self._resp(False, msg='无效的规则类型')
            self.re.del_rule(rt, str(getattr(get, 'id', '') or ''))
            return self._resp(True, msg='规则已删除' + self._after_rule_change(rt))
        except Exception as e:
            return self._resp(False, msg=str(e))

    def UpdateRule(self, get):
        self._check_perm('rule', get)
        try:
            kv = {}
            for k in ('name', 'pattern', 'level', 'mode', 'on', 'note', 'rate', 'burst'):
                if hasattr(get, k):
                    kv[k] = getattr(get, k)
                    if k == 'on':
                        kv[k] = str(kv[k]) == '1'
            rt = str(getattr(get, 'rule_type', '') or '')
            if rt not in RULE_TYPES:
                return self._resp(False, msg='无效的规则类型')
            self.re.update_rule(rt, str(getattr(get, 'id', '') or ''), kv)
            return self._resp(True, msg='规则已更新' + self._after_rule_change(rt))
        except Exception as e:
            return self._resp(False, msg=str(e))

    # ================= 站点联动 =================
    def GetSites(self, get):
        self._check_perm('view', get)
        sites = WebServer.get_sites()
        for s in sites:
            s['waf'] = self.wd.get_site_conf(s['name'])
        return self._resp(True, sites)

    def SetSiteWaf(self, get):
        self._check_perm('site', get)
        try:
            site = str(getattr(get, 'site', '') or '')
            if not site:
                return self._resp(False, msg='缺少站点参数')
            on = str(getattr(get, 'on', '1')) == '1'
            mode = str(getattr(get, 'mode', '') or '') or None
            r = self.wd.deploy_site(site, on=on, mode=mode)
            msg = '站点[%s]WAF已%s' % (site, '开启' if on else '关闭')
            if r.get('errors'):
                msg += '（部分失败: %s）' % '; '.join(r['errors'][:2])
            return self._resp(True, r, msg)
        except Exception as e:
            return self._resp(False, msg=str(e))

    def SetSitesWaf(self, get):
        """批量开启/关闭站点防护: sites 逗号分隔, 全部写完后统一校验并 reload 一次"""
        self._check_perm('site', get)
        try:
            names = [x.strip() for x in str(getattr(get, 'sites', '') or '').split(',') if x.strip()]
            if not names:
                return self._resp(False, msg='请先选择站点')
            on = str(getattr(get, 'on', '1')) == '1'
            r = self.wd.deploy_sites(names, on=on)
            return self._resp(True, r, '%s %d 个站点%s' % (
                '已开启' if on else '已关闭', len(r.get('ok') or []),
                (', 失败: ' + '; '.join(x.get('site', '') for x in r.get('fail') or []))
                if r.get('fail') else ''))
        except Exception as e:
            return self._resp(False, msg=str(e))

    # ================= 日志与统计 =================
    def GetLogs(self, get):
        self._check_perm('logs', get)
        kw = lambda k, d=None: getattr(get, k, d)
        return self._resp(True, self.la.get_logs(
            page=int(kw('page', 1)), limit=int(kw('limit', 20)),
            rule_type=kw('rule_type'), ip=kw('ip'), level=kw('level'),
            start=kw('start'), end=kw('end'), keyword=kw('keyword')))

    def GetStats(self, get):
        self._check_perm('view', get)
        return self._resp(True, self.la.get_stats(days=int(getattr(get, 'days', 7))))

    def MarkFalsePositive(self, get):
        self._check_perm('logs', get)
        try:
            self.la.mark_fp(int(getattr(get, 'id', 0) or 0), 1)
        except Exception as e:
            return self._resp(False, msg='标记失败: %s' % e)
        return self._resp(True, msg='已标记误报, 将参与规则自学习')

    def UnmarkFalsePositive(self, get):
        """撤销误报标记(旧版本只能标记不能撤销)"""
        self._check_perm('logs', get)
        try:
            self.la.mark_fp(int(getattr(get, 'id', 0) or 0), 0)
        except Exception as e:
            return self._resp(False, msg='撤销失败: %s' % e)
        return self._resp(True, msg='已撤销误报标记')

    def ExportIpList(self, get):
        """批量导出 IP 黑/白名单: txt(已启用, 每行一条) / csv / json, 内容直接回传供浏览器下载"""
        self._check_perm('rule', get)
        try:
            rt = str(getattr(get, 'rule_type', 'ip_black') or 'ip_black')
            if rt not in ('ip_black', 'ip_white'):
                return self._resp(False, msg='仅支持导出 IP 黑名单 / 白名单')
            fmt = str(getattr(get, 'fmt', 'txt') or 'txt').lower()
            if fmt not in ('txt', 'csv', 'json'):
                fmt = 'txt'
            kw = str(getattr(get, 'keyword', '') or '').strip().lower()
            rows = []
            for r in self.re.get_rules(rt):
                if kw and kw not in (r.get('pattern', '') + ' ' + (r.get('name') or '')).lower():
                    continue
                rows.append(r)
            if not rows:
                return self._resp(False, msg='没有可导出的记录')
            content, mime = self._render_ip_export(rt, rows, fmt)
            fname = '%s_%s.%s' % (rt, time.strftime('%Y%m%d%H%M%S'), fmt)
            path = os.path.join(PLUGIN_ROOT, 'logs', fname)
            F.write_file(path, content)
            Conf.audit('export_ip_list', '%s %s %d条' % (rt, fmt, len(rows)))
            return self._resp(True, {'filename': fname, 'content': content, 'mime': mime,
                                     'count': len(rows), 'path': path},
                              '已导出 %d 条' % len(rows))
        except Exception as e:
            return self._resp(False, msg='导出失败: %s' % e)

    @staticmethod
    def _render_ip_export(rt, rows, fmt):
        """txt=已启用规则内容(可直接导入防火墙); csv/json=含状态、来源、命中数等字段"""
        if fmt == 'txt':
            pats = [r.get('pattern', '') for r in rows if r.get('on', True)]
            return '\n'.join(pats) + ('\n' if pats else ''), 'text/plain;charset=utf-8'
        if fmt == 'csv':
            head = ['pattern', 'name', 'level', 'mode', 'status', 'source', 'hits', 'fp', 'ctime']
            out = [','.join(head)]
            for r in rows:
                cells = [r.get('pattern', ''), r.get('name', ''), r.get('level', ''),
                         r.get('mode', ''), '1' if r.get('on', True) else '0',
                         r.get('source', ''), str(r.get('hits', 0)), str(r.get('fp', 0)),
                         time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(r.get('ctime') or 0))]
                out.append(','.join(['"%s"' % str(c).replace('"', '""') for c in cells]))
            return '\ufeff' + '\n'.join(out) + '\n', 'text/csv;charset=utf-8'
        return json.dumps({'type': rt, 'count': len(rows),
                           'exported_at': time.strftime('%Y-%m-%d %H:%M:%S'),
                           'rules': rows}, ensure_ascii=False, indent=2), 'application/json;charset=utf-8'

    def ExportLogs(self, get):
        self._check_perm('logs', get)
        try:
            fmt = str(getattr(get, 'fmt', '') or 'csv')
            path = self.la.export_logs(fmt,
                                       start=getattr(get, 'start', None) or None,
                                       end=getattr(get, 'end', None) or None,
                                       rule_type=getattr(get, 'rule_type', None) or None,
                                       keyword=getattr(get, 'keyword', None) or None,
                                       ip=getattr(get, 'ip', None) or None,
                                       level=getattr(get, 'level', None) or None)
            return self._resp(True, {'path': path, 'filename': os.path.basename(path),
                                     'content': F.read_text_smart(path),
                                     'mime': 'text/csv;charset=utf-8' if fmt == 'csv' else 'application/json;charset=utf-8'},
                              '导出成功')
        except Exception as e:
            return self._resp(False, msg=str(e))

    def ClearLogs(self, get):
        self._check_perm('logs', get)
        days = int(getattr(get, 'before_days', 0) or 0)
        self.la.clear_logs(days or None)
        Conf.audit('clear_logs', days)
        return self._resp(True, msg='日志已清理')

    # ================= 告警 =================
    def GetAlertConfig(self, get):
        role = self._check_perm('view', get)
        cfg = Conf.get('alert')
        if role != 'admin':
            # 非管理员不下发通道地址/密钥, 避免越权拿到 Webhook 与邮箱凭据
            cfg = json.loads(json.dumps(cfg, ensure_ascii=False))
            for ch in cfg.get('channels') or []:
                for k in ('url', 'secret', 'to', 'user', 'password', 'smtp', 'from'):
                    if k in ch:
                        ch[k] = '***'
        # 附上每个通道最近一次发送结果, 通道列表可直接显示"成功/失败"
        try:
            rows = DB.execute('SELECT channel,ok,ts FROM alerts ORDER BY id DESC LIMIT 80',
                              fetch='all') or []
            seen = {}
            for x in rows:
                seen.setdefault(x.get('channel'), x)
            for ch in cfg.get('channels') or []:
                ch.setdefault('enable', True)
                rec = seen.get(ch.get('type'))
                if rec:
                    ch['last_ts'] = rec.get('ts')
                    ch['last_ok'] = bool(rec.get('ok'))
        except Exception:
            pass
        return self._resp(True, cfg)

    def SaveAlertConfig(self, get):
        self._check_perm('alert', get)
        try:
            raw = getattr(get, 'cfg', '') or ''
            cfg = json.loads(raw)
            if not isinstance(cfg, dict):
                return self._resp(False, msg='配置格式错误: 需要 JSON 对象')
            cur = Conf.get('alert')
            cur.update(cfg)
            # 通道级过滤条件校验: 级别名称与事件类型必须是已知值
            for ch in cur.get('channels') or []:
                ch['enable'] = bool(ch.get('enable', True))
                ml = str(ch.get('min_level') or '')
                if ml and ml not in ('info', 'warn', 'high', 'critical'):
                    return self._resp(False, msg='通道最低级别无效: %s' % ml)
                evs = ch.get('events')
                if isinstance(evs, list):
                    ch['events'] = [x for x in evs
                                    if x in ('attack', 'malware', 'rollback', 'digest')]
            sil = cur.get('silence') or {}
            if sil:
                for k in ('start', 'end'):
                    v = str(sil.get(k, '') or '')
                    if not re.match(r'^([01]\d|2[0-3]):[0-5]\d$', v):
                        return self._resp(False, msg='静默时段时间格式应为 HH:MM，如 23:00')
                cur['silence'] = {'enable': bool(sil.get('enable')), 'start': sil.get('start'),
                                  'end': sil.get('end')}
            Conf.set({'alert': cur})
            Conf.audit('save_alert_config', raw[:200])
            return self._resp(True, msg='告警配置已保存')
        except Exception as e:
            return self._resp(False, msg='配置格式错误: %s' % e)

    def TestAlert(self, get):
        self._check_perm('alert', get)
        cfg = Conf.get('alert') or {}
        if not cfg.get('channels'):
            return self._resp(False, msg='尚未配置告警通道，请先添加 Webhook/钉钉/企微/邮件')
        only = getattr(get, 'index', None)
        only = int(only) if str(only or '').isdigit() else None
        r = self.am.send('warn', '司南防火墙测试告警',
                         '这是一条测试消息, 收到说明通道配置成功。', force=True, event='*',
                         only_index=only)
        if r is False or r is None:
            return self._resp(False, msg='未发送：请检查告警开关与最低级别')
        if not r:
            return self._resp(False, msg='该通道已停用，未发送测试消息')
        ok = [x for x in r if x.get('ok')]
        return self._resp(bool(ok), {'results': r},
                          '测试发送完成：成功 %d / 共 %d 个通道' % (len(ok), len(r)))

    def GetAlertHistory(self, get):
        self._check_perm('view', get)
        return self._resp(True, self.am.history(int(getattr(get, 'page', 1))))

    # ================= 状态/威慑推送(Webhook) =================
    def GetNotifyConfig(self, get):
        """返回推送配置 + 四种消息预览(Markdown/纯文本 × 状态/威慑)"""
        # 属于告警通道配置, 含 Webhook 地址与加签密钥, 按 alert 权限校验
        self._check_perm('alert', get)
        try:
            return self._resp(True, {'cfg': self.nf.cfg(), 'preview': self.nf.preview()})
        except Exception as e:
            return self._resp(False, msg='生成预览失败: %s' % e)

    def SaveNotifyConfig(self, get):
        self._check_perm('alert', get)
        try:
            raw = getattr(get, 'cfg', '') or ''
            if not raw.strip():
                return self._resp(False, msg='缺少推送配置')
            cfg = json.loads(raw)
            if not isinstance(cfg, dict):
                return self._resp(False, msg='配置格式错误: 需要 JSON 对象')
            cur = self.nf.save(cfg)
            return self._resp(True, cur, '推送配置已保存')
        except Exception as e:
            return self._resp(False, msg=str(e))

    def PushNotify(self, get):
        """立即推送: kind=status|deter"""
        self._check_perm('alert', get)
        try:
            kind = str(getattr(get, 'kind', 'status') or 'status')
            if kind not in ('status', 'deter'):
                return self._resp(False, msg='不支持的推送类型')
            r = self.nf.send(kind)
            return self._resp(bool(r.get('ok')), r, r.get('msg') or '已推送')
        except Exception as e:
            return self._resp(False, msg='推送失败: %s' % e)

    def TestNotify(self, get):
        self._check_perm('alert', get)
        try:
            if not self.nf.cfg().get('url'):
                return self._resp(False, msg='请先填写 Webhook 地址')
            r = self.nf.send('status')
            return self._resp(bool(r.get('ok')), r, r.get('msg') or '已发送')
        except Exception as e:
            return self._resp(False, msg='发送失败: %s' % e)

    # ================= 智能优化 =================
    def RunAnalysis(self, get):
        self._check_perm('ai', get)
        r = self.ao.run_cycle()
        if r.get('skip'):
            return self._resp(True, r, '未执行：%s' % r['skip'])
        return self._resp(True, r, '分析完成：生成规则 %s 条，优化 %s 条%s' % (
            r.get('generated', 0), (r.get('optimized') or {}).get('changed', 0),
            '，已自动回滚' if r.get('rollback') else ''))

    def GetAnalysis(self, get):
        self._check_perm('view', get)
        feats = self.ao.analyze_features()
        return self._resp(True, feats)

    def GetPendingRules(self, get):
        self._check_perm('view', get)
        return self._resp(True, self.ao.get_pending())

    def ApprovePending(self, get):
        self._check_perm('ai', get)
        try:
            pat = str(getattr(get, 'pattern', '') or '')
            if not pat:
                return self._resp(False, msg='缺少规则内容')
            n = self.ao.approve_pending(pat, str(getattr(get, 'approve', '1')) == '1')
            if n:
                r = self.wd.deploy_all_sites()
                return self._resp(True, n, '已处理 %d 条候选规则，并%s' %
                                  (n, self._deploy_msg('下发', r).strip()))
            return self._resp(True, n, '候选规则已忽略')
        except Exception as e:
            return self._resp(False, msg='处理失败: %s' % e)

    def GetRuleEvaluation(self, get):
        self._check_perm('view', get)
        return self._resp(True, self.ao.evaluate_rules())

    def GetLearnHistory(self, get):
        self._check_perm('view', get)
        return self._resp(True, self.ao.get_learn_history())

    def RollbackRules(self, get):
        self._check_perm('ai', get)
        try:
            v = str(getattr(get, 'version_id', '') or '')
            self.re.restore(version_id=int(v) if v.isdigit() else None)
            self._apply_ip_rules()
            r = self.wd.deploy_all_sites()
            return self._resp(True, r, '规则已回滚并重新下发(' + self._deploy_msg('', r).strip() + ')')
        except Exception as e:
            return self._resp(False, msg=str(e))

    def GetVersions(self, get):
        self._check_perm('view', get)
        return self._resp(True, self.re.list_backups())

    # ================= 导入导出与备份 =================
    def ExportRules(self, get):
        self._check_perm('rule', get)
        fname = 'rules_%s.json' % time.strftime('%Y%m%d%H%M%S')
        path = os.path.join(PLUGIN_ROOT, 'backup', fname)
        data = self.re.export_rules()
        F.write_json(path, data)
        Conf.audit('export_rules', path)
        return self._resp(True, {'path': path, 'filename': fname,
                                 'content': json.dumps(data, ensure_ascii=False, indent=2),
                                 'mime': 'application/json;charset=utf-8'},
                          '规则已导出')

    def ImportRules(self, get):
        self._check_perm('rule', get)
        try:
            raw = getattr(get, 'data', '') or ''
            if not raw.strip():
                return self._resp(False, msg='请粘贴规则 JSON')
            data = json.loads(raw)
            self.re.import_rules(data, str(getattr(get, 'mode', 'merge') or 'merge'))
            self._apply_ip_rules()
            r = self.wd.deploy_all_sites()
            return self._resp(True, r, '规则导入成功(' + self._deploy_msg('', r).strip() + ')')
        except Exception as e:
            return self._resp(False, msg='导入失败: %s' % e)

    def CreateBackup(self, get):
        self._check_perm('rule', get)
        path = self.re.create_backup(str(getattr(get, 'note', '')))
        return self._resp(True, {'path': path}, '备份已创建')

    def GetBackups(self, get):
        self._check_perm('view', get)
        return self._resp(True, self.re.list_backups())

    def RestoreBackup(self, get):
        self._check_perm('rule', get)
        try:
            f = str(getattr(get, 'file', '') or '')
            v = str(getattr(get, 'version_id', '') or '')
            if f:
                self.re.restore(file=f)
            elif v.isdigit():
                self.re.restore(version_id=int(v))
            else:
                return self._resp(False, msg='请提供备份文件名或版本 ID')
            self._apply_ip_rules()
            r = self.wd.deploy_all_sites()
            return self._resp(True, r, '恢复成功(' + self._deploy_msg('', r).strip() + ')')
        except Exception as e:
            return self._resp(False, msg=str(e))

    def DownloadBackup(self, get):
        """下载规则备份文件(仅允许 backup/ 目录内已存在的文件)"""
        self._check_perm('rule', get)
        name = os.path.basename(str(getattr(get, 'file', '') or ''))
        path = os.path.join(PLUGIN_ROOT, 'backup', name)
        if not name or not os.path.isfile(path):
            return self._resp(False, msg='备份文件不存在')
        try:
            content = F.read_text_smart(path)
            if not content:
                return self._resp(False, msg='备份文件为空或过大(>4MB)')
            return self._resp(True, {'filename': name, 'content': content,
                                     'mime': 'application/json;charset=utf-8'}, '已导出备份文件')
        except Exception as e:
            return self._resp(False, msg='读取失败: %s' % e)

    def DelBackup(self, get):
        """删除备份: version_id(数据库快照) 或 file(文件备份)"""
        self._check_perm('rule', get)
        f = os.path.basename(str(getattr(get, 'file', '') or ''))
        v = str(getattr(get, 'version_id', '') or '')
        try:
            if f:
                path = os.path.join(PLUGIN_ROOT, 'backup', f)
                if not os.path.isfile(path):
                    return self._resp(False, msg='备份文件不存在')
                os.remove(path)
                Conf.audit('del_backup_file', f)
                return self._resp(True, msg='备份文件已删除')
            if v.isdigit():
                DB.execute('DELETE FROM rule_version WHERE id=?', (int(v),))
                Conf.audit('del_backup_version', v)
                return self._resp(True, msg='快照已删除')
            return self._resp(False, msg='请提供版本 ID 或备份文件名')
        except Exception as e:
            return self._resp(False, msg=str(e))

    # ================= 全局设置 =================
    def GetSettings(self, get):
        role = self._check_perm('view', get)
        data = Conf.get()
        if role != 'admin':
            # 非管理员不下发敏感字段(Webhook 地址/签名/邮箱账号), 避免越权泄露
            data = json.loads(json.dumps(data, ensure_ascii=False))
            alert = data.get('alert') or {}
            for ch in alert.get('channels') or []:
                for k in ('url', 'secret', 'to', 'user', 'password', 'smtp', 'from'):
                    if k in ch:
                        ch[k] = '***'
            data['alert'] = alert
        return self._resp(True, data)

    def GetUserRoles(self, get):
        """当前用户-角色映射(仅 admin 可看完整映射)"""
        role = self._check_perm('view', get)
        if role != 'admin':
            return self._resp(False, msg='仅管理员可查看用户角色映射')
        return self._resp(True, {'mapping': Conf.get('user_roles', {}) or {},
                                 'roles': list((Conf.get('permissions') or {}).keys()),
                                 'current_user': str(os.environ.get('BT_USER', '') or '')})

    def SaveUserRoles(self, get):
        """保存 面板用户名 -> 角色 映射; 用于让子账号按角色受限"""
        self._check_perm('admin', get)
        try:
            raw = getattr(get, 'mapping', '') or ''
            data = json.loads(raw) if raw.strip() else {}
            if not isinstance(data, dict):
                return self._resp(False, msg='格式错误: 需要 {"用户名":"角色"} 对象')
            roles = (Conf.get('permissions') or {}).keys()
            clean = {}
            for user, role in data.items():
                user = str(user).strip()
                role = str(role).strip()
                if not user or len(user) > 64:
                    continue
                if role not in roles:
                    continue
                clean[user] = role
            Conf.set({'user_roles': clean})
            Conf.audit('save_user_roles', json.dumps(clean, ensure_ascii=False)[:300])
            return self._resp(True, {'mapping': clean}, '已保存 %d 条用户角色映射' % len(clean))
        except Exception as e:
            return self._resp(False, msg='保存失败: %s' % e)

    @staticmethod
    def _validate_settings(kv):
        """配置合法性校验: 非法值会写坏 Nginx 配置并触发全站回滚, 必须前置拦截"""
        if 'cc' in kv:
            cc = kv.get('cc') or {}
            for k, lo, hi, name in (('limit', 1, 100000, 'CC阈值'),
                                    ('time', 1, 3600, 'CC统计窗口'),
                                    ('deny', 1, 86400, '封禁时长')):
                if k in cc:
                    try:
                        cc[k] = max(lo, min(hi, int(cc[k])))
                    except (TypeError, ValueError):
                        raise ValueError('%s 必须是 %d~%d 的整数' % (name, lo, hi))
            kv['cc'] = cc
        if 'limit_req' in kv:
            lr = kv.get('limit_req') or {}
            rate = str(lr.get('rate', '20r/s')).strip()
            if not re.match(r'^[1-9]\d{0,5}r/s$', rate):
                raise ValueError('全局限速格式应为 "20r/s"')
            lr['rate'] = rate
            for k, lo, hi, name in (('burst', 0, 10000, '突发'), ('conn', 1, 10000, '并发')):
                if k in lr:
                    try:
                        lr[k] = max(lo, min(hi, int(lr[k])))
                    except (TypeError, ValueError):
                        raise ValueError('%s 必须是整数' % name)
            if 'skip_static' in lr:
                lr['skip_static'] = bool(lr['skip_static'])
            if 'skip_paths' in lr:
                raw = lr.get('skip_paths') or []
                if isinstance(raw, str):
                    raw = [x.strip() for x in raw.split('\n') if x.strip()]
                clean = []
                for pat in raw[:50]:
                    pat = str(pat).strip()
                    if not pat:
                        continue
                    if len(pat) > 200:
                        raise ValueError('限速豁免正则过长(<=200): %s' % pat[:40])
                    if '"' in pat or ';' in pat or '}' in pat:
                        raise ValueError('限速豁免正则不能包含 " ; } : %s' % pat[:40])
                    if not S.valid_regexp(pat):
                        raise ValueError('限速豁免正则非法: %s' % pat[:40])
                    clean.append(pat)
                lr['skip_paths'] = clean
            kv['limit_req'] = lr
        if 'block_return' in kv:
            try:
                code = int(kv['block_return'])
            except (TypeError, ValueError):
                raise ValueError('拦截状态码必须是数字')
            if code not in (403, 404, 429, 444, 503):
                raise ValueError('拦截状态码只支持 403/404/429/444/503')
            kv['block_return'] = code
        return kv

    def SaveSettings(self, get):
        self._check_perm('admin', get)
        try:
            raw = getattr(get, 'settings', '') or ''
            if not raw.strip():
                return self._resp(False, msg='缺少设置内容')
            kv = self._validate_settings(json.loads(raw))
            Conf.set(kv)
            Conf.audit('save_settings', raw[:300])
            if any(k in kv for k in ('cc', 'limit_req', 'mode', 'block_return', 'waf_on')):
                # 限速/CC/模式等参数需要重写全局与站点配置才真正生效
                g = self.wd.deploy_global()
                s = self.wd.deploy_all_sites()
                msg = '设置已保存并已下发(' + self._deploy_msg('', s).strip() + ')'
                if g.get('errors'):
                    msg += '；全局配置错误: ' + '; '.join(g['errors'][:2])
                return self._resp(True, {'global': g, 'sites': s}, msg)
            return self._resp(True, msg='设置已保存')
        except Exception as e:
            return self._resp(False, msg=str(e))

    # ================= 手动触发 =================
    def TriggerAnalyze(self, get):
        self._check_perm('logs', get)
        try:
            with FLock('analyze.lock'):
                r = self.la.analyze_all()
            self.la.cleanup_old()
            return self._resp(True, {'lines': r['lines'], 'attacks': r['attacks']},
                              '本次分析 %d 行日志, 检出 %d 次攻击' % (r['lines'], r['attacks']))
        except IOError:
            return self._resp(False, msg='另一个分析任务正在执行')

    def GetAuditLog(self, get):
        """操作审计: 在界面内查看审计日志(旧版本只显示了一个文件路径)"""
        self._check_perm('logs', get)
        path = os.path.join(PLUGIN_ROOT, 'logs', 'audit.log')
        kw = str(getattr(get, 'keyword', '') or '').strip().lower()
        try:
            page = max(1, int(getattr(get, 'page', 1) or 1))
            limit = min(200, max(10, int(getattr(get, 'limit', 50) or 50)))
        except (TypeError, ValueError):
            page, limit = 1, 50
        lines = []
        try:
            with open(path, 'rb') as fp:
                fp.seek(0, os.SEEK_END)
                size = fp.tell()
                fp.seek(max(0, size - 512 * 1024))     # 只读末尾 512KB, 避免大文件全量载入
                raw = fp.read()
            lines = raw.decode('utf-8', 'ignore').splitlines()
        except Exception:
            lines = []
        if kw:
            lines = [x for x in lines if kw in x.lower()]
        total = len(lines)
        lines.reverse()
        start = (page - 1) * limit
        return self._resp(True, {'total': total, 'rows': lines[start:start + limit],
                                 'page': page, 'limit': limit, 'path': path})

    # ================= 木马扫描杀毒 =================
    def ScanNow(self, get):
        """后台启动扫描(不阻塞面板请求), 前端轮询 GetScanProgress"""
        self._check_perm('scan', get)
        p = self.av.get_progress()
        if p.get('running'):
            return self._resp(False, msg='已有扫描任务正在运行')
        full = str(getattr(get, 'full', '0')) == '1'
        auto_fix = str(getattr(get, 'auto_fix', '0')) == '1'

        def _run():
            try:
                self.av.scan(full=full, auto_fix=auto_fix)
            except Exception as e:
                F.write_json(os.path.join(PLUGIN_ROOT, 'tmp', 'scan_state.json'),
                             {'running': False, 'error': str(e), 'done': 0, 'found': 0})

        t = threading.Thread(target=_run)
        t.daemon = True
        t.start()
        Conf.audit('scan_start', 'full=%s autofix=%s' % (full, auto_fix))
        return self._resp(True, {'full': full}, '扫描已在后台启动')

    def GetScanProgress(self, get):
        self._check_perm('view', get)
        return self._resp(True, self.av.get_progress())

    def StopScan(self, get):
        self._check_perm('scan', get)
        return self._resp(True, self.av.request_stop(), '已请求停止扫描')

    def GetScanResults(self, get):
        self._check_perm('view', get)
        return self._resp(True, self.av.get_results(
            page=int(getattr(get, 'page', 1)), limit=int(getattr(get, 'limit', 20)),
            level=getattr(get, 'level', None), site=getattr(get, 'site', None),
            keyword=getattr(get, 'keyword', None),
            include_fp=str(getattr(get, 'include_fp', '0')) == '1'))

    def GetScanStats(self, get):
        self._check_perm('view', get)
        return self._resp(True, self.av.get_stats())

    def GetScanConfig(self, get):
        self._check_perm('view', get)
        return self._resp(True, self.av.get_config())

    def SaveScanConfig(self, get):
        self._check_perm('admin', get)
        try:
            raw = getattr(get, 'cfg', '') or ''
            if not raw.strip():
                return self._resp(False, msg='缺少扫描配置')
            return self._resp(True, self.av.save_config(json.loads(raw)), '扫描配置已保存')
        except Exception as e:
            return self._resp(False, msg=str(e))

    def GetSignatures(self, get):
        self._check_perm('view', get)
        return self._resp(True, self.av.get_signatures())

    def SaveSignatures(self, get):
        self._check_perm('admin', get)
        try:
            raw = getattr(get, 'data', '') or ''
            if not raw.strip():
                return self._resp(False, msg='请粘贴特征 JSON 数组')
            n = self.av.update_signatures(json.loads(raw))
            return self._resp(True, n, '已保存%d条自定义特征' % n)
        except Exception as e:
            return self._resp(False, msg=str(e))

    def GetWhitelist(self, get):
        self._check_perm('view', get)
        return self._resp(True, self.av.get_whitelist())

    def AddWhitelist(self, get):
        self._check_perm('scan', get)
        md5 = getattr(get, 'md5', None)
        path = getattr(get, 'path', None)
        if not md5 and not path:
            return self._resp(False, msg='请提供文件MD5或目录路径')
        return self._resp(True, self.av.add_whitelist(md5=md5, path=path), '已加入白名单')

    def DelWhitelist(self, get):
        self._check_perm('scan', get)
        return self._resp(True, self.av.del_whitelist(
            md5=getattr(get, 'md5', None), path=getattr(get, 'path', None)), '已移除')

    def QuarantineFile(self, get):
        self._check_perm('scan', get)
        try:
            return self._resp(True, self.av.quarantine(self._req_id(get)), '文件已移入隔离区')
        except Exception as e:
            return self._resp(False, msg=str(e))

    def QuarantineAll(self, get):
        self._check_perm('scan', get)
        r = self.av.quarantine_all(getattr(get, 'min_score', None))
        return self._resp(True, r, '已隔离%d个高危文件' % r['isolated'])

    def RestoreFile(self, get):
        self._check_perm('scan', get)
        try:
            self.av.restore(self._req_id(get))
            return self._resp(True, msg='文件已恢复到原路径')
        except Exception as e:
            return self._resp(False, msg=str(e))

    def DeleteInfected(self, get):
        self._check_perm('admin', get)
        try:
            self.av.delete(self._req_id(get))
            return self._resp(True, msg='文件已永久删除')
        except Exception as e:
            return self._resp(False, msg=str(e))

    def MarkScanFp(self, get):
        self._check_perm('scan', get)
        try:
            self.av.mark_fp(self._req_id(get))
            return self._resp(True, msg='已标记误报并加入白名单')
        except Exception as e:
            return self._resp(False, msg=str(e))

    def UnmarkScanFp(self, get):
        """撤销误报: 移出白名单并恢复为待处理"""
        self._check_perm('scan', get)
        try:
            self.av.unmark_fp(self._req_id(get))
            return self._resp(True, msg='已撤销误报标记')
        except Exception as e:
            return self._resp(False, msg=str(e))

    def ExportScanReport(self, get):
        self._check_perm('view', get)
        try:
            fmt = str(getattr(get, 'fmt', '') or 'csv')
            path = self.av.export_report(fmt)
            return self._resp(True, {'path': path, 'filename': os.path.basename(path),
                                     'content': F.read_text_smart(path),
                                     'mime': 'text/csv;charset=utf-8' if fmt == 'csv' else 'application/json;charset=utf-8'},
                              '报告已导出')
        except Exception as e:
            return self._resp(False, msg=str(e))

    def ClearScanResults(self, get):
        self._check_perm('admin', get)
        self.av.clear_results()
        return self._resp(True, msg='扫描结果已清空')


    def getConfigHtml(self, get=None):
        """面板插件配置页: 返回根目录 index.html (静态资源由 /<插件名>/static/ 路由提供)"""
        import flask
        filename = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'index.html')
        if not os.path.exists(filename):
            return self._resp(False, msg='插件界面文件缺失: index.html')
        try:
            return flask.send_file(filename, mimetype='text/html', as_attachment=True,
                                   etag=True, conditional=True, max_age=0)
        except TypeError:
            return flask.send_file(filename, mimetype='text/html')

    UPDATE_MANIFEST_URLS = (
        # 主源 AtomGit(国内可达) + 备源 GitHub
        'https://atomgit.com/api/v5/repos/gtmaker/sinan-waf/raw/update.json?ref=main',
        'https://github.com/gtmaker520/sinan-waf/raw/main/update.json',
    )

    def UpdateCheck(self, get=None):
        """检查更新: 拉取远程版本清单并与本机 info.json 版本比较"""
        import urllib.request
        local_ver = '0.0.0'
        try:
            with open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   'info.json')) as f:
                local_ver = str(json.load(f).get('versions', local_ver))
        except Exception:
            pass
        remote, err = None, []
        for u in self.UPDATE_MANIFEST_URLS:
            try:
                req = urllib.request.Request(
                    u, headers={'User-Agent': 'SinanWAF-UpdateCheck'})
                remote = json.loads(urllib.request.urlopen(
                    req, timeout=5).read().decode('utf-8', 'ignore'))
                break
            except Exception as e:
                err.append(str(e)[:60])

        def _v(v):
            try:
                return tuple(int(x) for x in re.split(r'[.\-]', str(v)) if x.isdigit())
            except Exception:
                return (0,)

        if not isinstance(remote, dict):
            return self._resp(False, msg='检查更新失败: ' + ('; '.join(err[:2]) or '网络不可用'))
        r_ver = str(remote.get('version', '')).strip()
        has_update = _v(r_ver) > _v(local_ver)
        return self._resp(True, data={
            'has_update': has_update,
            'local_version': local_ver,
            'remote_version': r_ver,
            'date': remote.get('date', ''),
            'note': remote.get('note', ''),
            'urls': remote.get('urls', {}),
        })


def _api_guard(fn):
    """统一兜底: 权限异常/未捕获异常都转成 JSON 响应, 避免面板层直接 500"""
    def wrapper(self, get=None):
        try:
            return fn(self, {} if get is None else get)
        except Exception as e:
            if isinstance(e, RuntimeError):
                msg = str(e)
            else:
                msg = '%s: %s' % (type(e).__name__, e)
            return {'status': False, 'data': None, 'msg': msg}
    wrapper.__name__ = getattr(fn, '__name__', 'api')
    wrapper.__doc__ = getattr(fn, '__doc__', None)
    return wrapper


# 只包装插件对外暴露的接口(_ 开头的是内部方法)
for _n in list(vars(main).keys()):
    if _n.startswith('_'):
        continue
    _fn = getattr(main, _n)
    if callable(_fn):
        setattr(main, _n, _api_guard(_fn))

# 宝塔面板 PluginLoader 约定: 入口类名为 <插件名>_main
sinanwaf_main = main
