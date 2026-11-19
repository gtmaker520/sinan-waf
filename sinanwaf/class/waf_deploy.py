#!/usr/bin/env python
# -*- coding: utf-8 -*-
# WAF 部署器：Nginx/Apache 双向配置联动与部署
# 全局层: limit_req/limit_conn zone(CC/限速) + 全局IP黑名单 + Apache模块探测
# 站点层: 每个站点 vhost 注入 include, 拦截 URL/UA/Referer/注入/扫描/木马访问
# 端口层: port_proto 规则联动系统防火墙(iptables/firewalld), 可选显式开启
# 安全: 所有改动先备份、nginx -t / httpd -t 校验通过才 reload, 失败自动回滚
import os, re, json, time, sys
from public_base import F, Conf, DB, PLUGIN_ROOT, PLUGIN_DIR, WebServer, Lock, S
from rule_engine import RuleEngine

WAF_DIR = os.path.join(PLUGIN_ROOT, 'waf')
NG_DIR = os.path.join(WAF_DIR, 'vhost')
AP_DIR = os.path.join(WAF_DIR, 'apache')
GL_DIR = os.path.join(WAF_DIR, 'global')
CONF_BACKUP = os.path.join(PLUGIN_ROOT, 'backup', 'conf')
MARK_RE = re.compile(r'[ \t]*#BTFW-BEGIN.*?#BTFW-END[ \t]*\r?\n?', re.S)
SERVER_OPEN_RE = re.compile(r'(?m)^[ \t]*server\s*\{')
VHOST_OPEN_RE = re.compile(r'<VirtualHost[^>]*>', re.I)
# 这些端口绝不自动封禁, 避免把自己锁在服务器外面
PROTECTED_PORTS = {20, 21, 22, 25, 80, 443, 888, 8888, 39000}

# 规则类型 -> Nginx 变量: 决定规则作用于请求的哪一部分(与日志分析口径保持一致)
NGX_RULE_VARS = {
    'sqli': '$request_uri', 'xss': '$request_uri', 'path_scan': '$request_uri',
    'trojan': '$request_uri', 'upload': '$request_uri', 'url': '$request_uri',
    'ua': '$http_user_agent', 'bot': '$http_user_agent', 'referer': '$http_referer',
}
# 规则类型 -> Apache 变量(REQUEST_URI 不含查询串, 需要同时看 QUERY_STRING)
APACHE_RULE_VARS = {
    'sqli': ['%{REQUEST_URI}', '%{QUERY_STRING}'],
    'xss': ['%{REQUEST_URI}', '%{QUERY_STRING}'],
    'path_scan': ['%{REQUEST_URI}'], 'trojan': ['%{REQUEST_URI}'],
    'upload': ['%{REQUEST_URI}', '%{QUERY_STRING}'], 'url': ['%{REQUEST_URI}'],
    'ua': ['%{HTTP_USER_AGENT}'], 'bot': ['%{HTTP_USER_AGENT}'],
    'referer': ['%{HTTP_REFERER}'],
}
DEPLOY_RULE_LIMIT = 200      # 单站点 Nginx 最多下发规则条数(避免配置过大)
APACHE_COND_LIMIT = 80       # 单站点 Apache 最多 RewriteCond 条数


class WafDeploy(object):
    def __init__(self):
        self._mu = Lock.get('deploy')
        for d in (NG_DIR, AP_DIR, GL_DIR, CONF_BACKUP):
            try:
                if not os.path.isdir(d):
                    os.makedirs(d)
            except Exception:
                pass

    # ================= 规则库 -> 拦截指令 =================
    @staticmethod
    def collect_deploy_rules(limit=DEPLOY_RULE_LIMIT):
        """把规则库中"启用 + 动作为拦截"的规则整理为可下发列表。

        返回 (items, skipped):
          items   = [{'type','var','pattern','name'}]  已校验、去重、限量
          skipped = [{'type','pattern','reason'}]      未能下发的原因(供界面提示)
        历史上只有 url / 杀毒生成的 path_scan 规则会下发, 其余规则仅参与日志分析,
        导致"界面显示拦截、实际只记录"; 这里统一改为全量下发。
        """
        items, skipped, seen = [], [], set()
        try:
            rules = RuleEngine().get_rules()
        except Exception:
            rules = {}
        for rtype, var in NGX_RULE_VARS.items():
            for r in rules.get(rtype, []):
                if not r.get('on', True):
                    continue
                if r.get('mode') != 'block':
                    continue
                pat = str(r.get('pattern') or '')
                key = (var, pat)
                if not pat or key in seen:
                    continue
                if len(pat) > 400:
                    skipped.append({'type': rtype, 'pattern': pat[:60], 'reason': '正则过长(>400)'})
                    continue
                try:
                    re.compile(pat)
                except Exception:
                    skipped.append({'type': rtype, 'pattern': pat[:60], 'reason': '正则非法'})
                    continue
                if len(items) >= limit:
                    skipped.append({'type': rtype, 'pattern': pat[:60],
                                    'reason': '超出单站点下发上限(%d条)' % limit})
                    continue
                seen.add(key)
                items.append({'type': rtype, 'var': var, 'pattern': pat,
                              'name': r.get('name') or r.get('id') or ''})
        return items, skipped

    @classmethod
    def deploy_preview(cls):
        """界面用: 哪些规则会真正下发, 哪些被跳过及原因"""
        items, skipped = cls.collect_deploy_rules()
        by_type = {}
        for it in items:
            by_type[it['type']] = by_type.get(it['type'], 0) + 1
        return {'total': len(items), 'by_type': by_type, 'skipped': skipped[:30],
                'skipped_count': len(skipped), 'limit': DEPLOY_RULE_LIMIT}

    # ================= 基础设施: 备份/校验/回滚 =================
    @staticmethod
    def _backup_conf(path, text):
        name = '%s_%s' % (os.path.basename(path), time.strftime('%Y%m%d%H%M%S'))
        F.write_file(os.path.join(CONF_BACKUP, name), text)
        # 仅保留每个文件最近 10 份备份
        try:
            base = os.path.basename(path)
            fs = sorted([f for f in os.listdir(CONF_BACKUP) if f.startswith(base + '_')], reverse=True)
            for f in fs[10:]:
                os.remove(os.path.join(CONF_BACKUP, f))
        except Exception:
            pass

    @staticmethod
    def _strip_marks(text):
        return MARK_RE.sub('', text)

    def _safe_write(self, path, text, web, verify=True):
        """写配置 -> 语法校验 -> 失败自动回滚原文件

        verify=False 用于批量下发: 逐站点校验会执行 N 次 nginx -t, 站点多时非常慢,
        批量场景改为全部写完后再统一校验一次。
        """
        orig = F.read_file(path)
        self._backup_conf(path, orig)
        F.write_file(path, text)
        if not verify:
            return True
        ok = WebServer.test_config(web)
        if ok is False:
            F.write_file(path, orig)
            raise RuntimeError('%s 配置校验失败, 已自动回滚: %s' % (web, path))
        return True

    def _marker(self, content):
        return '\n#BTFW-BEGIN (司南防火墙管理, 请勿手工编辑)\n%s#BTFW-END\n' % content

    # ================= 全局层 =================
    def deploy_global(self):
        with self._mu:
            result = {'nginx': False, 'apache': False, 'errors': []}
            # 先确保被 include 的文件一定存在, 否则 nginx -t 直接失败
            self.sync_blacklist_map()
            self._write_nginx_global()
            self._write_apache_global()
            # Nginx: include 注入 http{} 之后
            nc = WebServer.nginx_conf()
            if nc:
                try:
                    text = self._strip_marks(F.read_file(nc))
                    inc = self._marker('include %s;\n' % os.path.join(GL_DIR, 'sinanwaf_global.conf'))
                    m = re.search(r'\bhttp\s*\{', text)
                    if m:
                        text = text[:m.end()] + '\n' + inc + text[m.end():]
                        self._safe_write(nc, text, 'nginx')
                        result['nginx'] = True
                except Exception as e:
                    result['errors'].append('nginx: %s' % e)
            # Apache: IncludeOptional 追加到主配置末尾
            ac = WebServer.apache_conf()
            if ac:
                try:
                    text = self._strip_marks(F.read_file(ac))
                    inc = self._marker('IncludeOptional %s\n' %
                                       os.path.join(GL_DIR, 'sinanwaf_apache.conf'))
                    self._safe_write(ac, text.rstrip() + '\n' + inc, 'apache')
                    result['apache'] = True
                except Exception as e:
                    result['errors'].append('apache: %s' % e)
            if result['nginx']:
                WebServer.reload('nginx')
            if result['apache']:
                WebServer.reload('apache')
            Conf.audit('deploy_global', json.dumps(result, ensure_ascii=False)[:300])
            self._record({'time': int(time.time()), 'result': result})
            return result

    @staticmethod
    def freq_plan():
        """频率规则 -> 每个规则独立 zone + map(仅命中 URI 计数), 不生成 location, 不影响站点路由"""
        out = []
        for r in RuleEngine().get_rules('freq'):
            if not r.get('on', True) or r.get('mode') != 'block':
                continue
            pat = str(r.get('pattern') or '')
            rate = str(r.get('rate') or '').strip().lower()
            if not pat or '"' in pat or ';' in pat or '{' in pat or '}' in pat or '\n' in pat:
                continue
            if not S.valid_regexp(pat) or not re.match(r'^\d{1,6}r/[sm]$', rate):
                continue
            n = len(out) + 1
            out.append({'id': r.get('id'), 'name': r.get('name') or '', 'pattern': pat,
                        'rate': rate, 'burst': int(r.get('burst') or 0),
                        'zone': 'btfw_freq_%d' % n, 'key': '$btfw_freq_key_%d' % n})
        return out

    def _write_nginx_global(self):
        s = Conf.get()
        lr = s.get('limit_req', {})
        bad_ua = (F.read_json(os.path.join(PLUGIN_DIR, 'rules', 'nginx_patterns.json'), {}) or {}) \
            .get('bad_ua', '(sqlmap|nikto|masscan|zgrab|nessus)')
        # 限速键: 静态资源与自定义例外使用空 key (nginx 对空 key 不计数) -> 避免误伤图片/CSS 并发
        skip_static = bool(lr.get('skip_static', True))
        skips = [x for x in (lr.get('skip_paths') or []) if isinstance(x, str) and x.strip()]
        map_lines = []
        if skip_static or skips:
            if skip_static:
                static_re = (r'~*\.(js|css|png|jpe?g|gif|webp|svg|ico|bmp|woff2?|ttf|eot|map|'
                             r'mp4|webm|mp3|zip|gz|txt)$')
                map_lines.append('    %s "";' % static_re)
            for pat in skips[:50]:
                # map 正则里不能出现裸 " 与 ;, 非法则跳过(设置接口已校验)
                if '"' in pat or ';' in pat or len(pat) > 200:
                    continue
                map_lines.append('    ~*%s "";' % pat)
        if map_lines:
            key_block = ('# ---- 限速豁免: 静态资源/指定URL 空 key 不计数 ----\n'
                         'map $uri $btfw_limit_key {\n'
                         '    default $binary_remote_addr;\n'
                         '%s\n}\n' % '\n'.join(map_lines))
            key_var = '$btfw_limit_key'
        else:
            key_block = ''
            key_var = '$binary_remote_addr'
        # 频率规则: 先定义 map(变量), 再定义 zone; 顺序不能反, 否则 nginx 报 unknown variable
        freq_block = ''
        plan = self.freq_plan()
        if plan:
            freq_block = '# ---- 频率规则: 按 URI 独立限速(仅命中请求计数) ----\n'
            for z in plan:
                freq_block += 'map $uri %s {\n    default "";\n    ~*%s $binary_remote_addr;\n}\n' % (
                    z['key'], z['pattern'])
            for z in plan:
                freq_block += 'limit_req_zone %s zone=%s:10m rate=%s;\n' % (
                    z['key'], z['zone'], z['rate'])
        conf = '''#BTFW-BEGIN (由司南防火墙管理, 请勿手工编辑)
%s# ---- 全局限速与CC防护 zone (供各站点 limit_req / limit_conn 引用) ----
limit_req_zone %s zone=btfw_req:20m rate=%s;
limit_conn_zone %s zone=btfw_conn:20m;
%s# ---- 全局恶意爬虫UA地图 ----
map $http_user_agent $btfw_badbot {
    default 0;
    %s 1;
}
# ---- 全局IP黑名单 (deny/allow, http上下文合法) ----
include %s;
#BTFW-END
''' % (key_block, key_var, lr.get('rate', '20r/s'), key_var, freq_block,
       json.dumps('~*' + bad_ua), os.path.join(GL_DIR, 'blacklist.map'))
        F.write_file(os.path.join(GL_DIR, 'sinanwaf_global.conf'), conf)

    def _write_apache_global(self):
        """Apache 全局层: 隐藏版本信息; 若装有 mod_evasive 则启用CC防护"""
        evasive = self._apache_module('evasive20_module') or self._apache_module('evasive_module')
        block = '#BTFW-BEGIN (由司南防火墙管理, 请勿手工编辑)\nServerTokens Prod\nServerSignature Off\n'
        if evasive:
            cc = Conf.get('cc', {})
            block += '''<IfModule mod_evasive20.c>
    DOSHashTableSize 3097
    DOSPageCount %d
    DOSSiteCount %d
    DOSPageInterval %d
    DOSSiteInterval 1
    DOSBlockingPeriod %d
    DOSLogDir "%s/logs"
</IfModule>
''' % (max(2, cc.get('limit', 120) // 20), max(10, cc.get('limit', 120) // 2),
       cc.get('time', 60), cc.get('deny', 600), PLUGIN_ROOT)
        else:
            block += '# 未检测到 mod_evasive, CC防护由 Nginx limit_req 或系统防火墙承担\n'
        block += '#BTFW-END\n'
        F.write_file(os.path.join(GL_DIR, 'sinanwaf_apache.conf'), block)

    def _apache_module(self, name):
        b = WebServer.apache_bin()
        if not b:
            return False
        r = WebServer.cmd([b, '-M'], timeout=8)
        return name in r.get('out', '') + r.get('err', '')

    # ================= 站点层 =================
    def _sites_conf(self):
        return F.read_json(os.path.join(NG_DIR, '.sites.json'), {}) or {}

    def get_site_conf(self, site):
        """站点防护配置。默认关闭: 未显式开启过的站点不会被隐式注入 WAF。

        旧版本默认 True, 导致"切换模式/保存限速"会给全部站点开启防护。
        """
        data = self._sites_conf()
        return data.get(site, {'on': False, 'mode': None})

    def save_site_conf(self, site, kv):
        path = os.path.join(NG_DIR, '.sites.json')
        data = self._sites_conf()
        cur = data.get(site, {'on': False, 'mode': None})
        cur.update(kv)
        data[site] = cur
        F.write_json(path, data)

    def _site_injected(self, site):
        """是否已有生成的站点配置文件(用于兼容旧版本已下发的站点)"""
        return os.path.exists(os.path.join(NG_DIR, site + '.conf')) or \
            os.path.exists(os.path.join(AP_DIR, site + '.conf'))

    def _site_has_include(self, site):
        """vhost 中是否仍残留 include 标记(生成的配置被手工删除时, 需清理避免 nginx -t 失败)"""
        for d in (WebServer.nginx_vhost_dir(), WebServer.apache_vhost_dir()):
            if not d:
                continue
            p = os.path.join(d, site + '.conf')
            if os.path.exists(p) and '#BTFW-BEGIN' in F.read_file(p):
                return True
        return False

    def deploy_site(self, site, on=True, mode=None, reload=True, verify=True):
        """为站点生成/移除 WAF include 配置 (Nginx + Apache 双联动)"""
        with self._mu:
            self.save_site_conf(site, {'on': on, 'mode': mode or Conf.get('mode')})
            active = on and Conf.get('waf_on', True)
            done, errors = [], []
            # ---- Nginx ----
            nd = WebServer.nginx_vhost_dir()
            if nd:
                cf = os.path.join(nd, site + '.conf')
                if os.path.exists(cf):
                    try:
                        conf = self._gen_nginx_site(site, mode or Conf.get('mode')) if active \
                            else self._empty_site(site, 'nginx')
                        F.write_file(os.path.join(NG_DIR, site + '.conf'), conf)
                        text = self._strip_marks(F.read_file(cf))
                        if active:
                            inc = self._marker('include %s;\n' % os.path.join(NG_DIR, site + '.conf'))
                            # 在每个 server{ 之后插入 (兼容多 server 块 / 泛域名 / 无空格写法)
                            hits = len(SERVER_OPEN_RE.findall(text))
                            if not hits:
                                raise RuntimeError('未找到 server{} 块, 无法注入 WAF')
                            text = SERVER_OPEN_RE.sub(lambda m: m.group(0) + '\n' + inc, text)
                        self._safe_write(cf, text, 'nginx', verify=verify)
                        done.append('nginx')
                    except Exception as e:
                        errors.append('nginx: %s' % e)
            # ---- Apache ----
            ad = WebServer.apache_vhost_dir()
            if ad:
                cf = os.path.join(ad, site + '.conf')
                if os.path.exists(cf):
                    try:
                        conf = self._gen_apache_site(site, mode or Conf.get('mode')) if active \
                            else self._empty_site(site, 'apache')
                        F.write_file(os.path.join(AP_DIR, site + '.conf'), conf)
                        text = self._strip_marks(F.read_file(cf))
                        if active:
                            inc = self._marker('IncludeOptional %s\n' %
                                               os.path.join(AP_DIR, site + '.conf'))
                            if not VHOST_OPEN_RE.search(text):
                                raise RuntimeError('未找到 <VirtualHost> 块, 无法注入 WAF')
                            text = VHOST_OPEN_RE.sub(lambda m: m.group(0) + '\n' + inc, text, count=1)
                        self._safe_write(cf, text, 'apache', verify=verify)
                        done.append('apache')
                    except Exception as e:
                        errors.append('apache: %s' % e)
            if not done:
                self._record_site(site, {'ok': False, 'web': done,
                                         'errors': errors or ['未找到 Nginx/Apache 站点配置']})
                raise RuntimeError('站点[%s]配置下发失败: %s' %
                                   (site, '; '.join(errors) or '未找到 Nginx/Apache 站点配置'))
            if reload:
                WebServer.reload('nginx') if 'nginx' in done else None
                WebServer.reload('apache') if 'apache' in done else None
            self._record_site(site, {'ok': not errors, 'web': done, 'errors': errors})
            Conf.audit('deploy_site', '%s on=%s web=%s err=%s' %
                       (site, on, ','.join(done), '; '.join(errors)))
            return {'site': site, 'web': done, 'errors': errors}

    def _empty_site(self, site, web):
        return '#BTFW-BEGIN (防火墙已停用, 站点 %s / %s)\n#BTFW-END\n' % (site, web)

    def _gen_nginx_site(self, site, mode):
        s = Conf.get()
        cc, lr = s.get('cc', {}), s.get('limit_req', {})
        p = F.read_json(os.path.join(PLUGIN_DIR, 'rules', 'nginx_patterns.json'), {}) or {}
        ret = s.get('block_return', 403)
        q = lambda k, d: json.dumps(p.get(k, d))    # 保留引号并转义, 供 nginx 正则字面量使用
        lines = [
            '#BTFW-BEGIN 司南防火墙 (site=%s mode=%s)' % (site, mode),
            '# ---- CC防护与频率限制 ----',
        ]
        limit_lines = []
        if cc.get('enable', True) and mode != 'loose':
            limit_lines += ['limit_req zone=btfw_req burst=%d nodelay;' % int(lr.get('burst', 40)),
                            'limit_conn btfw_conn %d;' % int(lr.get('conn', 30)),
                            '# CC阈值: %d req / %ds, 超限返回429' % (cc.get('limit', 120), cc.get('time', 60))]
        if mode != 'loose':
            for z in self.freq_plan():
                limit_lines.append('limit_req zone=%s burst=%d nodelay;' % (z['zone'], z['burst']))
                limit_lines.append('# 频率规则: %s -> %s 突发 %d' %
                                   (z['name'] or z['pattern'], z['rate'], z['burst']))
        if limit_lines:
            limit_lines.append('limit_req_status 429;')
        lines += limit_lines
        lines += [
            '# ---- 恶意UA / 爬虫 ----',
            'if ($btfw_badbot) { return %d; }' % ret,
            'if ($http_user_agent ~* %s) { return %d; }' % (q('bad_ua', '(nikto|sqlmap|masscan)'), ret),
            '# ---- SQL注入 / 目录扫描 / 敏感路径 / 木马文件访问 ----',
            'if ($request_uri ~* %s) { return %d; }' % (
                q('sqli_scan', '(union.*select|\\.\\./|/etc/passwd|\\.env|\\.git)'), ret),
            '# ---- 垃圾Referer / XSS ----',
            'if ($http_referer ~* %s) { return %d; }' % (q('bad_referer', '(gambling|casino)'), ret),
            'if ($request_uri ~* %s) { return %d; }' % (q('xss', '(<script|onerror\\s*=|javascript:)'), ret),
        ]
        # 规则库全量下发: 所有"启用 + 拦截"规则(含用户新增/杀毒自动生成), 与日志分析口径一致
        items, skipped = self.collect_deploy_rules()
        if items:
            lines.append('# ---- 规则库下发: %d 条 (规则库页启停即生效)' % len(items))
            for it in items:
                lines.append('if (%s ~* %s) { return %d; }' %
                             (it['var'], json.dumps(it['pattern']), ret))
        if skipped:
            lines.append('# ---- 以下 %d 条规则未下发(正则非法/超长/超上限), 详见系统诊断 ----' % len(skipped))
        if mode == 'strict':
            lines += ['# ---- 严格模式 ----',
                      'if ($http_user_agent = "") { return %d; }' % ret]
        lines.append('#BTFW-END')
        return '\n'.join(lines) + '\n'

    @staticmethod
    def _ip_rewrite_regex(p):
        """IP / CIDR -> Apache RewriteCond 的 REMOTE_ADDR 正则

        Apache 的 RewriteCond 只能做正则匹配(没有 nginx 的 CIDR 语义), 因此:
          - /8 /16 /24 /32 直接用前缀
          - 其余网段把"跨界的那一段"枚举成 (a|b|...) 备选, 最多 16 个值
          - 更细的网段(如 /25 ~ /27)无法用短正则表达, 返回 None 并提示仅 Nginx 生效
        """
        p = (p or '').strip()
        oct_re = r'^\d{1,3}(\.\d{1,3}){3}$'
        if '/' not in p:
            return '^%s$' % re.escape(p) if re.match(oct_re, p) else None
        ip, bits = p.split('/', 1)
        if not re.match(oct_re, ip) or not bits.isdigit():
            return None
        bits = int(bits)
        if not 0 <= bits <= 32:
            return None
        octets = [int(x) for x in ip.split('.')]
        if bits == 32:
            return '^%s$' % re.escape('.'.join(str(x) for x in octets))
        if bits % 8 == 0:
            head = '.'.join(str(x) for x in octets[:bits // 8])
            return '^%s\\.' % re.escape(head) if head else '^'
        idx = bits // 8                  # 需要枚举的字节下标
        rem = 8 - (bits % 8)             # 该字节内可变的位数
        if rem > 4:                      # 超过 16 个备选, 正则过长
            return None
        base = octets[idx] & ((0xff << rem) & 0xff)
        vals = '|'.join(str(base + i) for i in range(1 << rem))
        head = '.'.join(str(x) for x in octets[:idx])
        prefix = (re.escape(head) + '\\.') if head else ''
        return '^%s(%s)\\.' % (prefix, vals)

    @classmethod
    def _apache_ip_conds(cls, rule_type, limit=200):
        """IP 名单 -> Apache 条件正则列表(Apache 站点配置体积有限, 最多 limit 条)"""
        out = []
        for r in RuleEngine().get_rules(rule_type):
            if not r.get('on', True):
                continue
            c = cls._ip_rewrite_regex(r.get('pattern', ''))
            if c:
                out.append(c)
            if len(out) >= limit:
                break
        return out

    def _gen_apache_site(self, site, mode):
        """Apache 站点级: mod_rewrite 拦截 + mod_authz_core IP封禁 + 木马文件禁止访问"""
        s = Conf.get()
        p = F.read_json(os.path.join(PLUGIN_DIR, 'rules', 'nginx_patterns.json'), {}) or {}
        conds = [
            ('%{REQUEST_URI}', p.get('sqli_scan', '(union.*select|\\.\\./|\\.env|\\.git)')),
            ('%{QUERY_STRING}', p.get('sqli_scan', '(union.*select|\\.\\./|\\.env|\\.git)')),
            ('%{HTTP_USER_AGENT}', p.get('bad_ua', '(nikto|sqlmap|masscan)')),
            ('%{HTTP_REFERER}', p.get('bad_referer', '(gambling|casino)')),
            ('%{QUERY_STRING}', p.get('xss', '(<script|onerror\\s*=|javascript:)')),
        ]
        # 规则库全量下发(与 Nginx 侧一致), 数量受 APACHE_COND_LIMIT 约束
        seen = set((v, pat) for v, pat in conds)
        items, _skipped = self.collect_deploy_rules()
        for it in items:
            for var in APACHE_RULE_VARS.get(it['type'], []):
                if (var, it['pattern']) in seen:
                    continue
                if len(conds) >= APACHE_COND_LIMIT:
                    break
                seen.add((var, it['pattern']))
                conds.append((var, it['pattern']))
        white = self._apache_ip_conds('ip_white')
        black = self._apache_ip_conds('ip_black')
        lines = ['#BTFW-BEGIN 司南防火墙 (site=%s mode=%s)' % (site, mode),
                 '<IfModule mod_rewrite.c>', '    RewriteEngine On']
        if white:
            lines.append('    # IP白名单: 命中则直接放行, 跳过后续拦截')
            for i, c in enumerate(white):
                lines.append('    RewriteCond %%{REMOTE_ADDR} %s%s' %
                             (c, ' [OR]' if i < len(white) - 1 else ''))
            lines.append('    RewriteRule ^ - [L]')
        cond_lines = ['    # 攻击特征拦截']
        for var, pat in conds:
            cond_lines.append('    RewriteCond %s %s [NC,OR]' % (var, json.dumps(pat)))
        if black:
            cond_lines.append('    # IP黑名单: 直接拒绝(403)')
            for c in black:
                cond_lines.append('    RewriteCond %%{REMOTE_ADDR} %s [OR]' % c)
            if len(black) >= 200:
                cond_lines.append('    # 注意: Apache 侧最多下发 200 条IP规则, 其余仅在 Nginx 生效')
        # 最后一条 RewriteCond 不能带 [OR], 否则整组恒为真会把所有请求都拦掉
        for i in range(len(cond_lines) - 1, -1, -1):
            if cond_lines[i].startswith('    RewriteCond'):
                cond_lines[i] = cond_lines[i].replace(' [NC,OR]', ' [NC]').replace(' [OR]', '')
                break
        lines += cond_lines + ['    RewriteRule ^ - [F,L]', '</IfModule>',
                               '<FilesMatch "\\.(?:env|git|svn|bak|sql|old|save)$">',
                               '    <IfModule mod_authz_core.c>', '        Require all denied',
                               '    </IfModule>', '</FilesMatch>']
        if mode == 'strict':
            lines += ['<IfModule mod_rewrite.c>',
                      '    RewriteEngine On',
                      '    RewriteCond %{HTTP_USER_AGENT} ^$',
                      '    RewriteRule ^ - [F,L]', '</IfModule>']
        lines.append('#BTFW-END')
        return '\n'.join(lines) + '\n'

    # ================= 预览 / 下发报告 =================
    @staticmethod
    def _record_site(site, data):
        path = os.path.join(PLUGIN_ROOT, 'tmp', 'deploy_sites.json')
        d = F.read_json(path, {}) or {}
        data = dict(data)
        data['time'] = int(time.time())
        d[site] = data
        if len(d) > 100:
            items = sorted(d.items(), key=lambda kv: kv[1].get('time', 0), reverse=True)[:100]
            d = dict(items)
        try:
            F.write_json(path, d)
        except Exception:
            pass

    def site_preview(self, site):
        """站点将要写入的配置内容 + vhost 注入状态(不改动任何文件)"""
        c = self.get_site_conf(site)
        mode = c.get('mode') or Conf.get('mode')
        active = bool(c.get('on', False)) and Conf.get('waf_on', True)
        nd, ad = WebServer.nginx_vhost_dir(), WebServer.apache_vhost_dir()
        npath = os.path.join(nd, site + '.conf') if nd else ''
        apath = os.path.join(ad, site + '.conf') if ad else ''
        ntext = F.read_file(npath) if npath else ''
        atext = F.read_file(apath) if apath else ''
        return {
            'site': site, 'mode': mode, 'active': active,
            'site_on': bool(c.get('on', False)), 'waf_on': Conf.get('waf_on', True),
            'freq_rules': len(self.freq_plan()),
            'nginx': {
                'path': npath, 'exists': bool(npath and os.path.exists(npath)),
                'injected': '#BTFW-BEGIN' in ntext,
                'conf': self._gen_nginx_site(site, mode) if active else self._empty_site(site, 'nginx'),
            },
            'apache': {
                'path': apath, 'exists': bool(apath and os.path.exists(apath)),
                'injected': '#BTFW-BEGIN' in atext,
                'conf': self._gen_apache_site(site, mode) if active else self._empty_site(site, 'apache'),
            },
        }

    def deploy_report(self):
        """最近一次下发结果 + 各站点最近一次下发状态"""
        nc = WebServer.nginx_conf()
        sites = F.read_json(os.path.join(PLUGIN_ROOT, 'tmp', 'deploy_sites.json'), {}) or {}
        rows = []
        for name, v in sites.items():
            rows.append({'site': name, 'ok': bool(v.get('ok')), 'web': v.get('web') or [],
                         'errors': v.get('errors') or [], 'time': v.get('time', 0)})
        rows.sort(key=lambda x: -x['time'])
        return {
            'last_deploy': F.read_json(os.path.join(PLUGIN_ROOT, 'tmp', 'last_deploy.json'), {}) or {},
            'sites': rows[:50],
            'global_injected': '#BTFW-BEGIN' in F.read_file(nc or ''),
            'nginx_test': WebServer.test_config('nginx') if nc else None,
            'freq_rules': len(self.freq_plan()),
        }

    def deploy_all_sites(self):
        """重新下发全部"已配置防护"的站点。

        只处理显式配置过的站点(.sites.json 有记录)或历史已注入的站点,
        绝不给从未开启防护的站点隐式注入配置(旧版本会给全部站点开启, 属变更事故)。
        """
        confs = self._sites_conf()
        # 频率规则/限速豁免变化会影响全局 zone 定义, 批量下发前刷新全局文件(只写文件, 不改主配置)
        try:
            self._write_nginx_global()
        except Exception:
            pass
        ok, fail, skipped = [], [], []
        changed = set()
        for s in WebServer.get_sites():
            name = s['name']
            if name not in confs and not self._site_injected(name) and not self._site_has_include(name):
                skipped.append(name)
                continue
            c = confs.get(name, {'on': False, 'mode': None})
            try:
                # verify=False: 批量场景下逐站点执行 nginx -t 太慢, 全部写完后统一校验一次
                r = self.deploy_site(name, bool(c.get('on', False)), c.get('mode'),
                                     reload=False, verify=False)
                changed.update(r.get('web') or [])
                ok.append(name)
            except Exception as e:
                fail.append({'site': name, 'error': str(e)})
        # 全部站点写完后统一校验 + reload, 避免每站点重复 reload
        for web in ('nginx', 'apache'):
            if web in changed:
                if WebServer.test_config(web) is False:
                    fail.append({'site': '*', 'error': '%s 配置校验失败, 未执行 reload(原配置仍在生效, '
                                                       '备份见 backup/conf)' % web})
                    continue
                WebServer.reload(web)
        return {'ok': ok, 'fail': fail, 'skipped': skipped}

    def deploy_sites(self, sites, on=True, mode=None):
        """批量下发指定站点(站点防护页多选): 逐站点写配置, 最后统一校验 + reload 一次"""
        try:
            self._write_nginx_global()
        except Exception:
            pass
        ok, fail = [], []
        changed = set()
        for name in sites or []:
            try:
                r = self.deploy_site(name, on=on, mode=mode, reload=False, verify=False)
                changed.update(r.get('web') or [])
                ok.append(name)
            except Exception as e:
                fail.append({'site': name, 'error': str(e)})
        for web in ('nginx', 'apache'):
            if web in changed:
                if WebServer.test_config(web) is False:
                    fail.append({'site': '*', 'error': '%s 配置校验失败, 未执行 reload(原配置仍在生效)' % web})
                    continue
                WebServer.reload(web)
        Conf.audit('deploy_sites', 'on=%s n=%d' % (on, len(ok)))
        return {'ok': ok, 'fail': fail}

    def enable_all(self, on):
        """真正的一键启停: 只重写已 include 的站点 conf(不动用户 vhost), 失败自动回滚"""
        with self._mu:
            Conf.set({'waf_on': on})
            self.sync_blacklist_map()
            try:
                self._write_nginx_global()
            except Exception:
                pass
            changed = []
            for f in os.listdir(NG_DIR):
                if f.endswith('.conf'):
                    site = f[:-5]
                    c = self.get_site_conf(site)
                    active = on and c.get('on', False)
                    F.write_file(os.path.join(NG_DIR, f),
                                 self._gen_nginx_site(site, c.get('mode') or Conf.get('mode'))
                                 if active else self._empty_site(site, 'nginx'))
                    changed.append(site)
            for f in os.listdir(AP_DIR):
                if f.endswith('.conf'):
                    site = f[:-5]
                    c = self.get_site_conf(site)
                    active = on and c.get('on', False)
                    F.write_file(os.path.join(AP_DIR, f),
                                 self._gen_apache_site(site, c.get('mode') or Conf.get('mode'))
                                 if active else self._empty_site(site, 'apache'))
            # 校验并 reload
            for web in ('nginx', 'apache'):
                present = bool(WebServer.nginx_conf()) if web == 'nginx' else bool(WebServer.apache_conf())
                if present:
                    ok = WebServer.test_config(web)
                    if ok is False:
                        # 回滚本次生成(Nginx 与 Apache 都要回滚, 旧版本只回滚了 Nginx)
                        for site in changed:
                            self.enable_all_rollback(not on, site)
                        Conf.set({'waf_on': not on})
                        self.sync_blacklist_map()
                        raise RuntimeError('%s 配置校验失败, 一键启停已自动回滚' % web)
                    WebServer.reload(web)
            Conf.audit('enable_all', on)
            self._record({'time': int(time.time()), 'enable': on, 'sites': len(changed)})
            return {'on': on, 'sites': changed}

    def enable_all_rollback(self, on, site):
        """回滚单个站点: 同时回滚 Nginx 与 Apache 两侧"""
        with self._mu:
            c = self.get_site_conf(site)
            mode = c.get('mode') or Conf.get('mode')
            if os.path.exists(os.path.join(NG_DIR, site + '.conf')):
                F.write_file(os.path.join(NG_DIR, site + '.conf'),
                             self._gen_nginx_site(site, mode) if on
                             else self._empty_site(site, 'nginx'))
            if os.path.exists(os.path.join(AP_DIR, site + '.conf')):
                F.write_file(os.path.join(AP_DIR, site + '.conf'),
                             self._gen_apache_site(site, mode) if on
                             else self._empty_site(site, 'apache'))

    # ================= 黑白名单地图 =================
    def sync_blacklist_map(self):
        """IP 白/黑名单 -> nginx allow/deny 文件（白名单在前，先匹配先生效）"""
        lines = ['#BTFW-BEGIN 全局IP黑白名单(自动生成)', '# 格式: allow/deny IP;  (http上下文, 先匹配先生效)']
        written, skipped = 0, []
        if Conf.get('waf_on', True):
            for rtype, act in (('ip_white', 'allow'), ('ip_black', 'deny')):
                for r in RuleEngine().get_rules(rtype):
                    p = r.get('pattern', '')
                    if not p or not r.get('on', True):
                        continue
                    if re.match(r'^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$', p) or \
                            (':' in p and re.match(r'^[0-9a-fA-F:]+(/\d{1,3})?$', p)):
                        lines.append('%s %s;' % (act, p))
                        written += 1
                    else:
                        # 非常规写法: 不写入 nginx 名单, 但在诊断中回报
                        skipped.append(p)
        lines += ['allow all;', '#BTFW-END']
        F.write_file(os.path.join(GL_DIR, 'blacklist.map'), '\n'.join(lines) + '\n')
        return {'written': written, 'skipped': skipped[:50], 'skipped_count': len(skipped)}

    # ================= 端口与协议规则 -> 系统防火墙 =================
    def sync_port_rules(self, dry_run=False):
        """port_proto 规则联动 iptables(幂等, 带 BTFW 注释便于清理; 支持预演与持久化)"""
        if not Conf.get('port_enforce', False):
            return {'skip': True, 'msg': '端口强制封禁未开启(port_enforce=false), 需先开启总开关'}
        want, ignored = [], []
        for r in RuleEngine().get_rules('port_proto'):
            if not r.get('on', True) or r.get('mode') != 'block':
                continue
            m = re.match(r'^(\d{1,5})/(TCP|UDP|ALL)$', r['pattern'], re.I)
            if not m:
                ignored.append({'pattern': r.get('pattern', ''), 'reason': '格式应为 3306/TCP'})
                continue
            port, proto = int(m.group(1)), m.group(2).lower()
            if port > 65535:
                ignored.append({'pattern': r.get('pattern', ''), 'reason': '端口超出范围'})
                continue
            if port in PROTECTED_PORTS:
                ignored.append({'pattern': r.get('pattern', ''),
                                'reason': '受保护端口, 禁止封禁(避免锁死 SSH/面板/网站)'})
                continue
            want.append((port, proto))
        if dry_run:
            return {'dry_run': True, 'plan': ['%d/%s' % (p, t) for p, t in want],
                    'ignored': ignored, 'protected': sorted(PROTECTED_PORTS)}
        # 清理旧的 BTFW 规则
        listing = WebServer.cmd(['iptables', '-S', 'INPUT'], timeout=8)
        for line in listing.get('out', '').splitlines():
            if 'BTFW' in line and line.startswith('-A '):
                WebServer.cmd(['iptables', '-D', 'INPUT'] + line.split()[2:], timeout=8)
        applied, failed = [], []
        for port, proto in want:
            plist = ['tcp'] if proto == 'tcp' else ['udp'] if proto == 'udp' else ['tcp', 'udp']
            part_ok = True
            for pp in plist:
                rule = ['-p', pp, '--dport', str(port), '-j', 'DROP',
                        '-m', 'comment', '--comment', 'BTFW']
                exists = WebServer.cmd(['iptables', '-C', 'INPUT'] + rule, timeout=8)
                if not exists.get('ok'):
                    ins = WebServer.cmd(['iptables', '-I', 'INPUT', '1'] + rule, timeout=8)
                    if not ins.get('ok'):
                        part_ok = False
            (applied if part_ok else failed).append('%d/%s' % (port, proto))
        # 持久化: 否则服务器重启后规则丢失, 用户以为还在封禁状态
        persisted = self._persist_iptables() if applied else False
        Conf.audit('sync_port_rules', 'applied=%s failed=%s persisted=%s' %
                   (','.join(applied), ','.join(failed), persisted))
        return {'applied': applied, 'failed': failed, 'ignored': ignored,
                'persisted': persisted, 'protected': sorted(PROTECTED_PORTS)}

    @staticmethod
    def _persist_iptables():
        """把当前 iptables 规则写入发行版持久化文件"""
        r = WebServer.cmd(['iptables-save'], timeout=10)
        if not r.get('ok') or not r.get('out'):
            return False
        for p in ('/etc/sysconfig/iptables', '/etc/iptables/rules.v4'):
            try:
                if os.path.isdir(os.path.dirname(p)):
                    F.write_file(p, r['out'])
                    return True
            except Exception:
                continue
        return False

    @classmethod
    def apache_unsupported_ips(cls, limit=20):
        """Apache 侧无法精确表达的 IP 规则(仅 Nginx/日志层生效), 供界面提示"""
        out = []
        for rt in ('ip_white', 'ip_black'):
            for r in RuleEngine().get_rules(rt):
                if not r.get('on', True):
                    continue
                p = r.get('pattern', '')
                if p and cls._ip_rewrite_regex(p) is None:
                    out.append({'type': rt, 'pattern': p})
                    if len(out) >= limit:
                        return out
        return out

    # ================= 状态 =================
    def status(self):
        nc, ac = WebServer.nginx_conf(), WebServer.apache_conf()
        n_sites = len([f for f in os.listdir(NG_DIR) if f.endswith('.conf')]) if os.path.exists(NG_DIR) else 0
        a_sites = len([f for f in os.listdir(AP_DIR) if f.endswith('.conf')]) if os.path.exists(AP_DIR) else 0
        try:
            preview = self.deploy_preview()
            unsupported = self.apache_unsupported_ips()
        except Exception:
            preview, unsupported = {'total': 0, 'by_type': {}, 'skipped': [], 'skipped_count': 0}, []
        try:
            freq_n = len(self.freq_plan())
        except Exception:
            freq_n = 0
        try:
            site_err = [x for x in (self.deploy_report().get('sites') or []) if not x.get('ok')]
        except Exception:
            site_err = []
        return {
            'nginx': bool(nc), 'apache': bool(ac),
            'nginx_test': WebServer.test_config('nginx') if nc else None,
            'apache_test': WebServer.test_config('apache') if ac else None,
            'global_injected': '#BTFW-BEGIN' in F.read_file(nc or ''),
            'nginx_sites': n_sites, 'apache_sites': a_sites,
            'port_enforce': Conf.get('port_enforce', False),
            'waf_on': Conf.get('waf_on', True),
            'rules': preview,
            'freq_rules': freq_n,
            'site_errors': site_err[:10],
            'apache_unsupported': unsupported,
            'last_deploy': F.read_json(os.path.join(PLUGIN_ROOT, 'tmp', 'last_deploy.json'), {}) or {},
            'waf_dir': WAF_DIR,
            # 运行环境(便于在 7.x ~ 13.x 各版本面板上核对解释器)
            'python': sys.version.split()[0],
            'platform': sys.platform
        }

    def _record(self, data):
        F.write_json(os.path.join(PLUGIN_ROOT, 'tmp', 'last_deploy.json'), data)
