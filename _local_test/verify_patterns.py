#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""规则盲点修复验证脚本"""
import json
import re

# 1. 同步部署目录的规则到源码仓库
src = '/www/server/panel/plugin/sinanwaf/rules/nginx_patterns.json'
dst = '/root/projects/sinanwaf/sinanwaf/rules/nginx_patterns.json'
with open(src) as f:
    d = json.load(f)
p = d['sqli_scan']
re.compile(p, re.I)
print('正则编译 OK')

# 2. 验证编码形态匹配
tests = {
    '/?file=..%2f..%2fetc/passwd': True,      # 混合编码穿越
    '/?file=%2e%2e%2fetc/passwd': True,       # 全编码穿越
    '/?x=%252e%252e%252f': True,              # 双重编码
    "/?id=1%27%20OR%20%271%27=%271": True,    # 编码 SQLi 引号
    '/index.html?a=1': False,                 # 正常请求误报检查
    '/docs/page-2?kw=hello': False,           # 正常请求误报检查
}
ok = True
for t, expect in tests.items():
    got = bool(re.search(p, t, re.I))
    mark = 'OK ' if got == expect else 'FAIL'
    if got != expect:
        ok = False
    print('%s %s -> %s (期望 %s)' % (mark, t[:40], got, expect))
print('全部通过' if ok else '存在失败')
