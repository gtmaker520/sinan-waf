#!/bin/bash
# 司南防火墙卸载脚本：移除计划任务与全局 WAF 配置（保留日志备份于 /www/server/sinanwaf.bak）
PLUGIN_NAME=sinanwaf
PLUGIN_ROOT=/www/server/sinanwaf

echo "===== [1/3] 移除计划任务 ====="
crontab -l 2>/dev/null | grep -v 'sinanwaf/cron_task.py' | crontab -

echo "===== [2/3] 移除 Nginx/Apache 中 WAF include（全局+全部站点） ====="
for f in /www/server/nginx/conf/nginx.conf \
         /www/server/panel/vhost/nginx/*.conf \
         /www/server/panel/vhost/apache/*.conf \
         /www/server/apache/conf/httpd.conf \
         /www/server/apache/conf/extra/*.conf \
         /etc/httpd/conf/httpd.conf \
         /etc/httpd/conf/extra/*.conf; do
    [ -f "$f" ] && sed -i '/#BTFW-BEGIN/,/#BTFW-END/d' "$f" 2>/dev/null
done
# 端口规则联动产生的 iptables 条目也一并清除
if command -v iptables >/dev/null 2>&1; then
    iptables -S INPUT | grep 'BTFW' | while read -r line; do
        iptables -D INPUT $(echo "${line#-A INPUT }" | sed 's/"//g') >/dev/null 2>&1
    done
fi
[ -f /etc/init.d/nginx ] && /etc/init.d/nginx reload >/dev/null 2>&1
[ -f /etc/init.d/httpd ] && /etc/init.d/httpd graceful >/dev/null 2>&1

echo "===== [3/3] 备份并移除数据目录 ====="
rm -rf ${PLUGIN_ROOT}.bak
mv ${PLUGIN_ROOT} ${PLUGIN_ROOT}.bak 2>/dev/null
echo "卸载完成（原数据已备份至 ${PLUGIN_ROOT}.bak）"
exit 0
