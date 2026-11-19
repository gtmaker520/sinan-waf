#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 计划任务入口：日志滚动分析 -> 规则自学习 -> 自动调优/回滚 -> 告警收敛
import sys, os, time, traceback

PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PLUGIN_DIR)
sys.path.insert(0, os.path.join(PLUGIN_DIR, 'class'))

def _scheduled_scan():
    """每天一次全量扫描 + 每小时一次增量扫描（由同一个10分钟cron按状态判断）"""
    from antivirus import Antivirus
    from public_base import F, PLUGIN_ROOT
    av = Antivirus()
    cfg = av.get_config()
    if not cfg.get('enable', True):
        return {'skip': 'disabled'}
    state_file = os.path.join(PLUGIN_ROOT, 'tmp', 'scan_cron.json')
    st = F.read_json(state_file, {}) or {}
    now = int(time.time())
    today = time.strftime('%Y%m%d')
    full = st.get('last_full') != today
    if not full and now - st.get('last_quick', 0) < 3600:
        return {'skip': 'not_due'}
    r = av.scan(full=full)
    # 只有真正执行过才记录状态: 旧实现即使因互斥/手动扫描而 skip 也会写 last_full,
    # 导致当天的全量查杀被永久跳过
    if r.get('skip'):
        return r
    if full:
        st['last_full'] = today
    st['last_quick'] = now
    F.write_json(state_file, st)
    return r


def _expire_rules():
    """清理到期的临时封禁(带 TTL 的 IP 规则), 有变更才重新下发"""
    from rule_engine import RuleEngine
    from waf_deploy import WafDeploy
    try:
        removed = RuleEngine().purge_expired()
        if not removed:
            return {'removed': 0}
        wd = WafDeploy()
        wd.sync_blacklist_map()
        wd.deploy_all_sites()
        return {'removed': len(removed), 'patterns': [x['pattern'] for x in removed[:20]]}
    except Exception as e:
        return {'error': str(e)}


def run():
    from log_analyzer import LogAnalyzer
    from ai_optimizer import AiOptimizer
    from alert_manager import AlertManager
    from public_base import FLock

    la = LogAnalyzer()
    try:
        with FLock('analyze.lock'):    # 与界面"立即分析"共用锁, 避免并发重复入库
            stats = la.analyze_all()
        la.cleanup_old()               # 日志保留期清理(log_keep_days)
    except IOError:
        stats = {'skip': 'another analyze running'}
    expired = _expire_rules()         # 到期临时封禁自动解封
    ao = AiOptimizer()
    result = ao.run_cycle()           # 递归自学习：分析 -> 生成/优化规则 -> 评估 -> 回滚
    am = AlertManager()
    am.flush_digest()                 # 告警摘要发送（带频率控制）
    scan = _scheduled_scan()          # 木马定时查杀（全量/增量）
    try:
        from notify import Notify
        push = Notify().maybe_push()  # 状态/威慑 Webhook 推送（按间隔与阈值）
    except Exception as e:
        push = {'error': str(e)}
    return {'analyze': stats, 'optimize': result, 'scan': scan,
            'expired': expired, 'push': push, 'time': int(time.time())}

if __name__ == '__main__':
    try:
        r = run()
        print('[sinanwaf cron] ok: attacks=%s, new_rules=%s, rollback=%s, scan_threats=%s, expired=%s, push=%s' % (
            r.get('analyze', {}).get('attacks', 0),
            r.get('optimize', {}).get('generated', 0),
            r.get('optimize', {}).get('rollback', False),
            r.get('scan', {}).get('threats', '-'),
            r.get('expired', {}).get('removed', 0),
            r.get('push')))
    except Exception:
        print('[sinanwaf cron] error:\n%s' % traceback.format_exc())
