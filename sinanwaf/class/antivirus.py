#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 木马扫描杀毒引擎（WebShell / 后门 / 图片马 / 免杀混淆）
# 检测层次: MD5黑名单 -> 正则特征库 -> 启发式(危险函数组合/混淆熵/图片马/文件名/路径/时间)
# 处置: 报告 -> 隔离(可恢复) -> 删除 / 白名单 / 误报反馈 -> 自动生成WAF拦截规则 + 告警
# 资源控制: 增量索引(mtime+size)、文件大小/数量上限、排除目录、限速sleep、超时、可中断
import os, re, json, time, math, hashlib, shutil, traceback
from public_base import F, Conf, DB, PLUGIN_ROOT, PLUGIN_DIR, WebServer, Lock, FLock
from rule_engine import RuleEngine

SIG_PATH = os.path.join(PLUGIN_DIR, 'rules', 'virus_signatures.json')
CUSTOM_SIG = os.path.join(PLUGIN_ROOT, 'rules', 'virus_signatures_custom.json')
WHITE_PATH = os.path.join(PLUGIN_ROOT, 'rules', 'scan_whitelist.json')
INDEX_PATH = os.path.join(PLUGIN_ROOT, 'tmp', 'scan_index.json')
STATE_PATH = os.path.join(PLUGIN_ROOT, 'tmp', 'scan_state.json')
STOP_PATH = os.path.join(PLUGIN_ROOT, 'tmp', 'scan_stop')
QUAR_DIR = os.path.join(PLUGIN_ROOT, 'quarantine')

DEFAULT_SCAN = {
    'enable': True,
    'targets': [],                      # 空 = 自动扫描全部宝塔站点 + /www/wwwroot
    'max_file_size': 2097152,           # 2MB
    'max_files': 60000,
    'timeout': 900,                     # 秒
    'auto_quarantine': False,           # 默认仅报告, 避免误杀业务文件
    'quarantine_score': 60,
    'auto_waf_rule': True,              # 发现木马自动生成URL拦截规则
    'alert_on_found': True,
    'quick_hours': 24,                  # 增量扫描只检查最近N小时变动过的文件
    'exclude_dirs': []
}


class Antivirus(object):
    def __init__(self):
        self._mu = Lock.get('antivirus')
        for d in (QUAR_DIR, os.path.join(PLUGIN_ROOT, 'tmp')):
            try:
                if not os.path.isdir(d):
                    os.makedirs(d)
            except Exception:
                pass

    # ================= 配置 / 特征库 / 白名单 =================
    def get_config(self):
        cfg = dict(DEFAULT_SCAN)
        cfg.update(Conf.get('scan', {}) or {})
        return cfg

    def save_config(self, kv):
        cur = self.get_config()
        for k, v in kv.items():
            if k in DEFAULT_SCAN:
                cur[k] = v
        Conf.set({'scan': cur})
        Conf.audit('save_scan_config', json.dumps(kv, ensure_ascii=False)[:300])
        return cur

    def get_signatures(self):
        base = F.read_json(SIG_PATH, {}) or {}
        custom = F.read_json(CUSTOM_SIG, []) or []
        sigs = list(base.get('signatures', []))
        for s in custom:
            if isinstance(s, dict) and s.get('pattern'):
                s.setdefault('score', 40)
                s.setdefault('group', 'custom')
                s.setdefault('name', '自定义特征')
                sigs.append(s)
        out, bad = [], []
        for s in sigs:
            try:
                re.compile(s['pattern'], re.I)
                out.append(s)
            except Exception:
                bad.append(s.get('id', '?'))
        base['signatures'] = out
        base['invalid'] = bad
        return base

    def _load_compiled(self):
        sigs = self.get_signatures()
        out = []
        for s in sigs['signatures']:
            try:
                out.append(dict(s, _re=re.compile(s['pattern'], re.I)))
            except Exception:
                continue
        sigs['signatures'] = out
        return sigs

    def update_signatures(self, data):
        """导入/覆盖用户自定义特征（与内置特征库分离，升级插件不丢失）"""
        if not isinstance(data, list):
            raise ValueError('需要特征数组')
        good = []
        for s in data:
            if not isinstance(s, dict) or not s.get('pattern') or len(s['pattern']) > 512:
                continue
            try:
                re.compile(s['pattern'])
            except Exception:
                continue
            good.append({'id': s.get('id', 'CUS%d' % len(good)),
                         'name': s.get('name', '自定义特征'),
                         'group': 'custom', 'pattern': s['pattern'],
                         'score': min(100, int(s.get('score', 40))),
                         'desc': s.get('desc', '')})
        F.write_json(CUSTOM_SIG, good)
        Conf.audit('update_signatures', '%d条' % len(good))
        return len(good)

    def get_whitelist(self):
        return F.read_json(WHITE_PATH, {'md5': [], 'paths': []}) or {'md5': [], 'paths': []}

    def add_whitelist(self, md5=None, path=None):
        w = self.get_whitelist()
        if md5 and md5 not in w['md5']:
            w['md5'].append(md5)
        if path and path not in w['paths']:
            w['paths'].append(path)
        F.write_json(WHITE_PATH, w)
        Conf.audit('add_scan_whitelist', str(md5 or path))
        return w

    def del_whitelist(self, md5=None, path=None):
        w = self.get_whitelist()
        w['md5'] = [x for x in w['md5'] if x != md5] if md5 else w['md5']
        w['paths'] = [x for x in w['paths'] if x != path] if path else w['paths']
        F.write_json(WHITE_PATH, w)
        return w

    # ================= 扫描目标 =================
    def _targets(self):
        cfg = self.get_config()
        if cfg['targets']:
            return [p for p in cfg['targets'] if os.path.isdir(p)]
        roots = ['/www/wwwroot']
        for s in WebServer.get_sites():
            if s.get('path') and os.path.isdir(s['path']):
                roots.append(s['path'])
        out = []
        for p in roots:
            if p not in out and os.path.isdir(p):
                out.append(p)
        return out

    def _site_of(self, path):
        m = re.match(r'^/www/wwwroot/([^/]+)', path)
        return m.group(1) if m else (path.split('/')[2] if len(path.split('/')) > 2 else 'other')

    def _allowed_file(self, fn, sigs):
        ext = fn.rsplit('.', 1)[-1].lower() if '.' in fn else ''
        allow = set(sigs.get('script_exts', [])) | set(sigs.get('image_exts', [])) | {'ini', 'htaccess'}
        if fn.startswith('.'):
            ext = fn.lstrip('.').split('.')[-1].lower() if '.' in fn.lstrip('.') else fn.lstrip('.')
        return ext in allow

    def _iter_files(self, sigs, full):
        cfg = self.get_config()
        exclude = set(sigs.get('exclude_dirs', [])) | set(cfg.get('exclude_dirs', []))
        idx = {} if full else (F.read_json(INDEX_PATH, {}) or {})
        since = int(time.time()) - cfg['quick_hours'] * 3600
        n = 0
        for base in self._targets():
            for root, dirs, files in os.walk(base):
                dirs[:] = [d for d in dirs if d not in exclude and not d.startswith('.btfw')]
                for fn in files:
                    if n >= cfg['max_files']:
                        return
                    if not self._allowed_file(fn, sigs):
                        continue
                    p = os.path.join(root, fn)
                    try:
                        st = os.stat(p)
                        if st.st_size > cfg['max_file_size'] or st.st_size == 0:
                            continue
                        key = [int(st.st_mtime), st.st_size]
                        # 增量: 未变化的文件跳过; 快速模式只关注近期变动文件
                        if not full and idx.get(p) == key:
                            continue
                        if not full and cfg['quick_hours'] and st.st_mtime < since:
                            continue
                        idx[p] = key
                    except OSError:
                        continue
                    n += 1
                    yield p, st
        F.write_json(INDEX_PATH, idx)

    # ================= 单文件检测 =================
    def inspect(self, path, sigs, white):
        cfg = self.get_config()
        if any(path.startswith(x) for x in white.get('paths', [])):
            return None, None
        try:
            with open(path, 'rb') as fp:
                raw = fp.read(cfg['max_file_size'])
        except (IOError, OSError):
            return None, None
        md5 = hashlib.md5(raw).hexdigest()
        if md5 in white.get('md5', []):
            return None, None
        text = raw.decode('utf-8', 'ignore')
        ext = path.rsplit('.', 1)[-1].lower() if '.' in path else ''
        is_img = ext in sigs.get('image_exts', [])
        is_conf = os.path.basename(path) in ('.user.ini', '.htaccess') or ext == 'ini'
        score, reasons = 0, []

        # 1) MD5 黑名单
        for h in sigs.get('hash_blacklist', []):
            if h.get('enabled') and h.get('md5') == md5:
                score += 100
                reasons.append('MD5黑名单:%s' % h.get('name', ''))

        # 2) 特征库正则（按分组适配文件类型）
        client_side = ext in ('js', 'json', 'css', 'map', 'html', 'htm')  # 纯前端文件不做服务端特征匹配
        for s in sigs['signatures']:
            g = s.get('group')
            if g == 'image_trojan' and not is_img:
                continue
            if g == 'hidden' and not is_conf:
                continue
            if is_img and g not in ('image_trojan', 'webshell', 'obfuscation'):
                continue
            if client_side and g != 'hidden':
                continue
            try:
                matches = list(s['_re'].finditer(text))
                if s.get('id') in ('VS008', 'VS012') and matches:
                    # JS 模板误报过滤: `function xxx_$_GET['k'] (` 是前端函数声明而非后门
                    matches = [mm for mm in matches
                               if not re.search(r'function\s+[\w$]+$', text[
                                   text.rfind('\n', 0, mm.start()) + 1:mm.start()])]
                    # 命中点嵌入更长标识符（如 succeedhandle_$_GET[...]）的同样跳过
                    matches = [mm for mm in matches
                               if mm.start() == 0 or not (text[mm.start() - 1].isalnum()
                                                          or text[mm.start() - 1] == '_')]
                    if not matches:
                        continue
                else:
                    if not matches:
                        continue
                score += int(s.get('score', 30))
                reasons.append('%s[%s]' % (s.get('name', ''), s.get('id', '')))
            except Exception:
                continue

        # 3) 启发式: 代码执行类函数 + 用户输入 组合（要求同一行内紧邻，降低框架正常代码误报）
        code_exec = r'(?i)\b(eval|assert|system|passthru|shell_exec|exec|proc_open|popen)\s*\([^;\n]{0,100}\$_(POST|GET|REQUEST|COOKIE)'
        if not client_side and re.search(code_exec, text):
            score += 25
            reasons.append('用户输入直连危险函数')
        # 多层编码混淆: 要求嵌套解码(base64_decode 的参数内还有另一层解码), 框架的正常单独调用不误报
        if not client_side and \
                re.search(r'(?i)base64_decode\s*\([^;\n]{0,150}(gzinflate|str_rot13|convert_uudecode|gzuncompress)\s*\(', text):
            score += 15
            reasons.append('多层编码混淆')

        # 4) 单行超长 / 高熵载荷（纯前端文件常有压缩单行，跳过）
        longest = max([len(x) for x in text.split('\n')] + [0])
        if not client_side and longest > 5000 and text.count('\n') < 5:
            score += 10
            reasons.append('超长单行(压缩/免杀)')
        if not client_side:
            tokens = re.findall(r'[A-Za-z0-9+/]{200,}={0,2}', text)
            for t in tokens[:1]:
                if self._entropy(t) > 4.6:
                    score += 12
                    reasons.append('高熵编码载荷')

        # 5) 图片马: PHP 标签后邻近范围内必须有执行函数/用户输入, 官方图片中的偶然字节序列不算
        img_php = re.search(rb'<\?php[\s\S]{0,300}(\b(eval|assert|system|shell_exec|passthru|base64_decode)\s*\(|\$_(POST|GET|REQUEST))', raw) if is_img else None
        if img_php:
            score += 30
            reasons.append('图片内嵌PHP标签')
        if is_img and re.search(rb'\b(eval|assert|system)\s*\(', raw):
            score += 25
            reasons.append('图片内嵌执行函数')

        # 6) 文件名 / 路径 / 时间异常
        base = os.path.basename(path)
        if re.search(r'\.(jpg|jpeg|png|gif|txt|pdf)\.(php|phtml|asp|jsp)', base, re.I):
            score += 30
            reasons.append('双扩展名绕过')
        if re.match(r'^[a-f0-9]{16,}\.php$', base, re.I) or re.match(r'^\d{6,}\.php$', base):
            score += 10
            reasons.append('随机/数字文件名')
        if base.startswith('.') and ext in ('php', 'phtml'):
            score += 12
            reasons.append('隐藏脚本文件')
        parts = path.lower().split('/')
        # 缓存/模板/临时等自动生成目录不属于攻击者可控的落地路径, 不叠加上下文加分
        auto_gen = any(d in parts for d in sigs.get('exclude_dirs', []))
        if not is_img and not auto_gen and any(d in parts for d in sigs.get('upload_dirs', [])):
            score += 10
            reasons.append('上传目录内可执行脚本')
        try:
            if not auto_gen and time.time() - os.path.getmtime(path) < 86400 and not is_img:
                score += 5
                reasons.append('24小时内新增/修改')
        except OSError:
            pass

        if score < 30:
            return None, {'md5': md5, 'size': len(raw)}
        level = 'critical' if score >= 80 else 'high' if score >= 55 else \
            'medium' if score >= 30 else 'low'
        return {'path': path, 'site': self._site_of(path), 'size': len(raw),
                'mtime': int(os.path.getmtime(path)), 'md5': md5,
                'level': level, 'score': min(score, 999), 'reasons': reasons}, None

    @staticmethod
    def _entropy(s):
        if not s:
            return 0
        from collections import Counter
        c = Counter(s)
        return -sum((n / float(len(s))) * math.log(n / float(len(s)), 2) for n in c.values())

    # ================= 扫描主流程 =================
    def scan(self, full=False, auto_fix=False, targets=None):
        """full=True 全量(忽略增量索引); auto_fix=True 达阈值自动隔离"""
        try:
            with FLock('scan.lock'):
                with self._mu:
                    if os.path.exists(STOP_PATH):
                        os.remove(STOP_PATH)
                    start = int(time.time())
                    cfg = self.get_config()
                    sigs = self._load_compiled()
                    white = self.get_whitelist()
                    state = {'running': True, 'type': 'full' if full else 'quick',
                             'start': start, 'done': 0, 'found': 0, 'current': '',
                             'total': 0, 'stop': False}
                    F.write_json(STATE_PATH, state)
                    batch, found, n = [], [], 0
                    for path, st in self._iter_files(sigs, full):
                        if os.path.exists(STOP_PATH):
                            state['stop'] = True
                            break
                        if int(time.time()) - start > cfg['timeout']:
                            state['stop'] = True
                            break
                        n += 1
                        state['done'] = n
                        state['current'] = path
                        res, _ = self.inspect(path, sigs, white)
                        if res:
                            found.append(res)
                            batch.append((int(time.time()), res['path'], res['site'],
                                          res['size'], res['mtime'], res['md5'],
                                          res['level'], res['score'],
                                          '; '.join(res['reasons'])[:1000], 'report'))
                            state['found'] = len(found)
                        if len(batch) >= 100:
                            self._flush(batch)
                            batch = []
                        if n % 200 == 0:
                            F.write_json(STATE_PATH, state)
                            time.sleep(0.02)     # 让出CPU, 避免影响线上业务
                    self._flush(batch)
                    state['running'] = False
                    state['total'] = n
                    state['duration'] = int(time.time()) - start
                    F.write_json(STATE_PATH, state)
                    # 自动隔离 + 规则联动 + 告警
                    acted = []
                    if auto_fix or cfg['auto_quarantine']:
                        for r in found:
                            if r['score'] >= cfg['quarantine_score']:
                                try:
                                    self._quarantine_path(r['path'], r['md5'], r['reasons'])
                                    acted.append(r['path'])
                                except Exception:
                                    pass
                    self._post_actions(found, acted, state, sigs)
                    DB.execute('INSERT INTO scan_task(ts,type,files,threats,duration,status,detail) '
                               'VALUES(?,?,?,?,?,?,?)',
                               (start, state['type'], n, len(found), state.get('duration', 0),
                                'stopped' if state.get('stop') else 'done',
                                json.dumps({'acted': len(acted), 'sigs': len(sigs['signatures'])}, ensure_ascii=False)))
                    Conf.audit('scan', '%s files=%d threats=%d acted=%d' %
                               (state['type'], n, len(found), len(acted)))
                    return {'type': state['type'], 'files': n, 'threats': len(found),
                            'acted': len(acted), 'duration': state.get('duration', 0),
                            'stopped': state.get('stop', False),
                            'levels': self._level_count(found),
                            'top': sorted(found, key=lambda x: -x['score'])[:10]}
        except IOError:
            return {'skip': True, 'msg': '已有扫描任务正在运行'}

    @staticmethod
    def _level_count(found):
        d = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for r in found:
            d[r['level']] = d.get(r['level'], 0) + 1
        return d

    def _flush(self, batch):
        if not batch:
            return
        c = DB.conn()
        c.executemany('INSERT INTO scan_file(ts,path,site,size,mtime,md5,level,score,reasons,action)'
                      ' VALUES(?,?,?,?,?,?,?,?,?,?)', batch)
        c.commit()

    def _post_actions(self, found, acted, state, sigs):
        cfg = self.get_config()
        # 与规则引擎联动: 把木马URL加入拦截规则
        if cfg['auto_waf_rule'] and found:
            re_ = RuleEngine()
            for r in sorted(found, key=lambda x: -x['score'])[:20]:
                if r['level'] in ('critical', 'high'):
                    m = re.search(r'/www/wwwroot/[^/]+/(.+)$', r['path'])
                    if m:
                        rel = m.group(1)[:200]
                        candidates = ['/' + re.escape(rel),
                                      '/' + re.escape(os.path.basename(rel))]
                        pat = None
                        for cand in candidates:
                            try:
                                # 截断后的正则可能残缺, 非法会写坏整站配置(Nginx -t 失败 -> 回滚)
                                re.compile(cand)
                                pat = cand
                                break
                            except Exception:
                                continue
                        if not pat:
                            continue
                        try:
                            re_.add_rule('path_scan', '木马文件拦截:%s' % os.path.basename(r['path']),
                                         pat, level='high', mode='block',
                                         note='杀毒模块自动生成', source='antivirus')
                        except Exception:
                            pass
            try:
                from waf_deploy import WafDeploy
                # 只重写已注入站点的 WAF 文件, 不给未开启防护的站点隐式注入
                WafDeploy().enable_all(Conf.get('waf_on', True))
            except Exception:
                pass
        # 告警
        if cfg['alert_on_found'] and (acted or any(r['level'] == 'critical' for r in found)):
            try:
                from alert_manager import AlertManager
                AlertManager().send('critical', '检测到木马文件',
                                    '%s扫描: 检查%d个文件, 发现%d个可疑文件, 已隔离%d个\n%s' % (
                                        state['type'], state['total'], len(found), len(acted),
                                        '\n'.join('%s (%s/%d)' % (x['path'], x['level'], x['score'])
                                                  for x in sorted(found, key=lambda y: -y['score'])[:5])),
                                    force=True, event='malware')
            except Exception:
                pass

    # ================= 隔离 / 恢复 / 删除 / 误报 =================
    def _quarantine_path(self, path, md5, reasons):
        if not os.path.exists(path):
            raise IOError('文件已不存在')
        dst_dir = os.path.join(QUAR_DIR, '%s_%s' % (time.strftime('%Y%m%d%H%M%S'), md5[:10]))
        try:
            if not os.path.isdir(dst_dir):
                os.makedirs(dst_dir)
        except OSError:
            pass
        dst = os.path.join(dst_dir, os.path.basename(path))
        shutil.move(path, dst)
        DB.execute('UPDATE scan_file SET action=?, quarantined=1, qpath=? WHERE path=? AND quarantined=0',
                   ('quarantine', dst, path))
        return dst

    def quarantine(self, file_id):
        row = self._row(file_id)
        q = self._quarantine_path(row['path'], row['md5'], row['reasons'])
        Conf.audit('quarantine', row['path'])
        return {'path': q}

    def quarantine_all(self, min_score=None):
        cfg = self.get_config()
        th = int(min_score or cfg['quarantine_score'])
        rows = DB.execute('SELECT * FROM scan_file WHERE score>=? AND quarantined=0 AND fp=0',
                          (th,), fetch='all')
        n = 0
        for r in rows:
            try:
                self._quarantine_path(r['path'], r['md5'], r['reasons'])
                n += 1
            except Exception:
                continue
        Conf.audit('quarantine_all', '%d files' % n)
        return {'isolated': n}

    def restore(self, file_id):
        row = self._row(file_id)
        if not row['quarantined'] or not row['qpath'] or not os.path.exists(row['qpath']):
            raise IOError('隔离文件不存在')
        shutil.move(row['qpath'], row['path'])
        DB.execute('UPDATE scan_file SET action=?, quarantined=0, qpath=? WHERE id=?',
                   ('restored', '', file_id))
        Conf.audit('restore_file', row['path'])
        return True

    def delete(self, file_id):
        """永久删除（仅允许已隔离文件, 需二次确认）"""
        row = self._row(file_id)
        if not row['quarantined']:
            raise IOError('仅允许删除已隔离文件')
        if os.path.exists(row['qpath']):
            os.remove(row['qpath'])
        DB.execute('UPDATE scan_file SET action=? WHERE id=?', ('deleted', file_id))
        Conf.audit('delete_infected', row['path'])
        return True

    def mark_fp(self, file_id, add_white=True):
        row = self._row(file_id)
        DB.execute('UPDATE scan_file SET fp=1 WHERE id=?', (file_id,))
        if add_white:
            self.add_whitelist(md5=row['md5'])
        Conf.audit('scan_mark_fp', row['path'])
        return True

    def unmark_fp(self, file_id, remove_white=True):
        """撤销误报: 移出白名单, 让该文件重新参与检测"""
        row = self._row(file_id)
        DB.execute('UPDATE scan_file SET fp=0 WHERE id=?', (file_id,))
        if remove_white and row.get('md5'):
            try:
                w = self.get_whitelist()
                w['md5'] = [x for x in w.get('md5', []) if x != row['md5']]
                F.write_json(WHITE_PATH, w)
            except Exception:
                pass
        Conf.audit('scan_unmark_fp', row['path'])
        return True

    def _row(self, file_id):
        row = DB.execute('SELECT * FROM scan_file WHERE id=?', (file_id,), fetch='one')
        if not row:
            raise ValueError('记录不存在')
        return row

    # ================= 查询 / 进度 / 控制 =================
    def get_results(self, page=1, limit=20, level=None, site=None, keyword=None,
                    include_fp=False):
        where, params = ['1=1'], []
        if not include_fp:
            where.append('fp=0')
        if level:
            where.append('level=?'); params.append(level)
        if site:
            where.append('site=?'); params.append(site)
        if keyword:
            where.append('(path LIKE ? OR reasons LIKE ?)')
            params += ['%%%s%%' % keyword, '%%%s%%' % keyword]
        cond = ' AND '.join(where)
        total = DB.execute('SELECT COUNT(*) c FROM scan_file WHERE %s' % cond, params, fetch='one')['c']
        rows = DB.execute('SELECT * FROM scan_file WHERE %s ORDER BY score DESC, id DESC '
                          'LIMIT ? OFFSET ?' % cond,
                          params + [limit, (page - 1) * limit], fetch='all')
        for r in rows:
            r['time_str'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(r['ts']))
        return {'total': total, 'rows': rows, 'page': page, 'limit': limit}

    def get_stats(self):
        levels = DB.execute('SELECT level, COUNT(*) c FROM scan_file WHERE fp=0 GROUP BY level', fetch='all')
        sites = DB.execute('SELECT site, COUNT(*) c FROM scan_file WHERE fp=0 '
                           'GROUP BY site ORDER BY c DESC LIMIT 10', fetch='all')
        tasks = DB.execute('SELECT * FROM scan_task ORDER BY id DESC LIMIT 10', fetch='all')
        for t in tasks:
            t['time_str'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(t['ts']))
        return {'levels': levels, 'sites': sites, 'tasks': tasks,
                'quarantined': DB.execute('SELECT COUNT(*) c FROM scan_file WHERE quarantined=1',
                                         fetch='one')['c'],
                'whitelist': self.get_whitelist(),
                'signature_count': len(self.get_signatures().get('signatures', []))}

    def get_progress(self):
        return F.read_json(STATE_PATH, {'running': False, 'done': 0, 'found': 0}) or {}

    def request_stop(self):
        F.write_file(STOP_PATH, '1')
        return True

    def export_report(self, fmt='csv'):
        rows = self.get_results(1, 100000)['rows']
        path = os.path.join(PLUGIN_ROOT, 'logs', 'scan_report_%s.%s' %
                            (time.strftime('%Y%m%d%H%M%S'), fmt))
        if fmt == 'csv':
            import csv
            with open(path, 'w') as fp:
                w = csv.writer(fp, lineterminator='\n')
                w.writerow(['time', 'site', 'path', 'level', 'score', 'md5', 'reasons', 'action'])
                for r in rows:
                    w.writerow([r['time_str'], r['site'], r['path'], r['level'], r['score'],
                                r['md5'], r['reasons'][:500], r['action']])
        else:
            F.write_json(path, rows)
        Conf.audit('export_scan_report', fmt)
        return path

    def clear_results(self):
        DB.execute('DELETE FROM scan_file')
        F.write_json(STATE_PATH, {'running': False, 'done': 0, 'found': 0})
        return True
