#!/usr/bin/env python
# -*- coding: utf-8 -*-
# IP 地区识别（轻量实现）
# 优先级: 宝塔内置 ip_url/纯真库 > 内置常用网段表 > 未识别
# 可选扩展: 放置 ip2region.xdb 至 /www/server/sinanwaf/rules/ 自动启用(仅做接口预留, 不引入额外依赖)
import os, json
from public_base import F, PLUGIN_ROOT

# 内置精简网段表（覆盖常用国家/地区；完整库可放置 custom_region.json 扩展）
DEFAULT_NETS = [
    ('CN', ['1.0.1.0/24', '1.2.4.0/24', '14.0.0.0/8', '27.0.0.0/8', '36.0.0.0/8',
            '39.0.0.0/8', '42.0.0.0/8', '58.0.0.0/8', '59.0.0.0/8', '60.0.0.0/8',
            '61.0.0.0/8', '101.0.0.0/8', '106.0.0.0/8', '110.0.0.0/8', '111.0.0.0/8',
            '112.0.0.0/8', '113.0.0.0/8', '114.0.0.0/8', '115.0.0.0/8', '116.0.0.0/8',
            '117.0.0.0/8', '118.0.0.0/8', '119.0.0.0/8', '120.0.0.0/8', '121.0.0.0/8',
            '122.0.0.0/8', '123.0.0.0/8', '124.0.0.0/8', '125.0.0.0/8', '171.0.0.0/8',
            '175.0.0.0/8', '180.0.0.0/8', '182.0.0.0/8', '183.0.0.0/8', '202.0.0.0/8',
            '210.0.0.0/8', '211.0.0.0/8', '218.0.0.0/8', '219.0.0.0/8', '220.0.0.0/8',
            '221.0.0.0/8', '222.0.0.0/8', '223.0.0.0/8']),
    ('US', ['3.0.0.0/8', '13.0.0.0/8', '18.0.0.0/8', '23.0.0.0/8', '34.0.0.0/8',
            '35.0.0.0/8', '52.0.0.0/8', '54.0.0.0/8', '104.0.0.0/8', '107.0.0.0/8',
            '128.0.0.0/8', '140.0.0.0/8', '143.0.0.0/8', '144.0.0.0/8', '152.0.0.0/8']),
    ('JP', ['133.0.0.0/8', '150.0.0.0/8', '153.0.0.0/8', '202.232.0.0/8']),
    ('KR', ['1.201.0.0/16', '14.63.0.0/16', '58.140.0.0/8']),
    ('RU', ['5.0.0.0/8', '31.0.0.0/8', '37.0.0.0/8', '77.0.0.0/8', '85.0.0.0/8', '95.0.0.0/8']),
]


class RegionDB(object):
    def __init__(self):
        import threading
        self._mu = threading.Lock()
        self._nets = None

    def _load(self):
        with self._mu:
            if self._nets is not None:
                return self._nets
            nets = []
            custom = F.read_json(os.path.join(PLUGIN_ROOT, 'rules', 'custom_region.json'))
            if custom and isinstance(custom, list):
                nets = [(c.get('country', '?'), c.get('cidrs', [])) for c in custom]
            else:
                nets = DEFAULT_NETS
            # 预转换为整数区间, 查询 O(log n)
            self._nets = []
            for country, cidrs in nets:
                for cidr in cidrs:
                    try:
                        a, b = cidr_to_range(cidr)
                        self._nets.append((a, b, country))
                    except Exception:
                        continue
            self._nets.sort()
            return self._nets

    def lookup(self, ip):
        v = ip_to_int(ip)
        if v is None:
            return None
        nets = self._load()
        lo, hi = 0, len(nets) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            a, b, c = nets[mid]
            if v < a:
                hi = mid - 1
            elif v > b:
                lo = mid + 1
            else:
                return c
        return None


def ip_to_int(ip):
    import socket, struct
    try:
        return struct.unpack('!I', socket.inet_aton(str(ip)))[0]
    except Exception:
        return None


def cidr_to_range(cidr):
    """IPv4 CIDR -> (起始整数, 结束整数), 兼容 Python2.7"""
    addr, bits = cidr.split('/', 1)
    base = ip_to_int(addr)
    if base is None:
        raise ValueError('invalid cidr')
    bits = int(bits)
    if not 0 <= bits <= 32:
        raise ValueError('invalid mask')
    mask = ((0xffffffff << (32 - bits)) & 0xffffffff) if bits else 0
    start = base & mask
    return start, start | (0xffffffff ^ mask)
