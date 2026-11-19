#!/bin/bash
# ============================================================
# 司南防火墙 sinanwaf 安装脚本（宝塔面板插件）
# 用法: 将 sinanwaf 目录放入 /www/server/panel/plugin/ 后
#       在面板-软件商店中点击安装，或直接执行本脚本
# ============================================================
PLUGIN_NAME=sinanwaf
PLUGIN_ROOT=/www/server/sinanwaf
PANEL_PLUGIN_DIR=/www/server/panel/plugin/${PLUGIN_NAME}

# 兼容各版本宝塔面板内置 Python（7.x 用系统 python，9.x 起用 pyenv）
# 13.x 部分环境 pyenv 下只有 python3，因此优先探测 python3
if [ -x /www/server/panel/pyenv/bin/python3 ]; then
    PY=/www/server/panel/pyenv/bin/python3
elif [ -x /www/server/panel/pyenv/bin/python ]; then
    PY=/www/server/panel/pyenv/bin/python
else
    PY=$(command -v python3 || command -v python)
fi

echo "===== [1/6] 创建运行目录 ====="
mkdir -p ${PLUGIN_ROOT}/{rules,waf/vhost,waf/apache,waf/global,logs,db,backup/conf,versions,tmp,quarantine}

echo "===== [2/6] 检查插件文件 ====="
if [ ! -f "${PANEL_PLUGIN_DIR}/sinanwaf_main.py" ]; then
    echo "错误: 未找到 sinanwaf_main.py, 请确认插件目录已解压至 ${PANEL_PLUGIN_DIR}"
    exit 1
fi
if [ -z "${PY}" ]; then
    echo "错误: 未找到可用的 Python 解释器"
    exit 1
fi
echo "解释器: ${PY} 版本: $(${PY} -V 2>&1)"

# 生成插件根目录 index.html (面板 getConfigHtml 约定从插件根目录读取模板,
# 静态资源由 /<插件名>/static/ 路由提供)
sed 's|<script src="index.js"></script>|<script src="/sinanwaf/static/index.js"></script>|' \
    ${PANEL_PLUGIN_DIR}/static/index.html > ${PANEL_PLUGIN_DIR}/index.html
echo "插件模板 index.html 已生成"

echo "===== [3/6] 初始化数据库与默认规则 ====="
cd ${PANEL_PLUGIN_DIR} 2>/dev/null || cd ${PLUGIN_ROOT}
${PY} - <<'PYEOF'
import os, sys, json
sys.path.insert(0, '/www/server/panel/plugin/sinanwaf')
sys.path.insert(0, '/www/server/panel/plugin/sinanwaf/class')
try:
    from rule_engine import RuleEngine
    RuleEngine().init_default_rules()
    from public_base import DB
    DB.init_db()
    print('默认规则与数据库初始化完成')
except Exception as e:
    print('初始化警告: %s' % e)
PYEOF

echo "===== [4/6] 写入 Nginx/Apache 全局 WAF 配置 ====="
${PY} - <<'PYEOF'
import sys
sys.path.insert(0, '/www/server/panel/plugin/sinanwaf')
sys.path.insert(0, '/www/server/panel/plugin/sinanwaf/class')
try:
    from waf_deploy import WafDeploy
    w = WafDeploy()
    w.deploy_global()
    print('全局 WAF 配置部署完成')
except Exception as e:
    print('WAF 部署警告: %s (可在插件界面一键部署)' % e)
PYEOF

echo "===== [5/6] 注册计划任务（日志分析 + 规则自学习 + 定时木马查杀） ====="
CRON_LINE="*/10 * * * * ${PY} ${PANEL_PLUGIN_DIR}/cron_task.py >> ${PLUGIN_ROOT}/logs/cron.log 2>&1"
crontab -l 2>/dev/null | grep -v 'sinanwaf/cron_task.py' | { cat; echo "${CRON_LINE}"; } | crontab -
echo "已注册计划任务: 每10分钟执行日志分析/规则自学习, 每天全量+每小时增量木马扫描"

echo "===== [6/6] 重载 Web 服务 ====="
if [ -f /etc/init.d/nginx ]; then /etc/init.d/nginx reload >/dev/null 2>&1; fi
if [ -f /etc/init.d/httpd ]; then /etc/init.d/httpd graceful >/dev/null 2>&1; fi

echo "=========================================="
echo "安装完成！请在宝塔面板 -> 软件商店 -> 司南防火墙 中使用"
echo "=========================================="
exit 0
