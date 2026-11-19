/* 司南防火墙 前端逻辑 (依赖宝塔面板内嵌jQuery) */
var BFW = (function () {
  var NAME = 'sinanwaf';
  var PAGE = { page: 1, total: 0 };

  function api(method, data, cb) {
    data = data || {};
    var url = '/plugin?action=a&name=' + NAME + '&s=' + method;
    $.post(url, data, function (r) {
      if (typeof r === 'string') { try { r = JSON.parse(r); } catch (e) { } }
      if (r && r.status === false && r.msg) toast(r.msg);
      if (cb) cb(r);
    }).fail(function () { toast('请求失败，请检查面板服务'); });
  }
  function toast(msg, isErr) {
    var t = $('#toast'); t.text(msg);
    if (isErr) t.addClass('err'); else t.removeClass('err');
    t.show();
    clearTimeout(t._t);
    t._t = setTimeout(function () { t.hide(); }, isErr ? 5000 : 2800);
  }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[<>&"]/g, function (c) {
      return { '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;' }[c];
    });
  }
  /* 用于拼接进 onclick="..." 的字符串字面量: 转义单引号与反斜杠, 防止规则/站点名注入 */
  function jsq(s) {
    return String(s == null ? '' : s).replace(/\\/g, '\\\\').replace(/'/g, "\\'")
      .replace(/</g, '&lt;').replace(/"/g, '&quot;');
  }
  /* 统一切换 class: 兼容不同 jQuery 版本(部分子集无 toggleClass) */
  function setOn($el, name, on) {
    if (on) $el.addClass(name); else $el.removeClass(name);
    return $el;
  }
  function fmtTime(ts) {
    if (!ts) return '-';
    var d = new Date(ts * 1000), p = function (n) { return (n < 10 ? '0' : '') + n; };
    return (d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' + p(d.getHours()) + ':' +
      p(d.getMinutes()) + ':' + p(d.getSeconds());
  }
  function num(n) { return (n == null ? 0 : n); }
  function downloadText(filename, text, mime) {
    try {
      var blob = new Blob([text], { type: mime || 'text/plain;charset=utf-8' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = filename || 'export.txt';
      document.body.appendChild(a);
      a.click();
      setTimeout(function () {
        if (a.parentNode) a.parentNode.removeChild(a);
        URL.revokeObjectURL(url);
      }, 120);
      return true;
    } catch (e) { return false; }
  }
  function openModal(html) { $('#modal-box').html(html); $('#modal').addClass('on'); }
  function closeModal() { $('#modal').removeClass('on'); }
  $(document).on('click', '#modal', function (e) { if (e.target === this) closeModal(); });
  function openDrawer(title, html, width) {
    $('#drawer-hd').html('<b>' + title + '</b><span class="x" onclick="BFW.closeDrawer()">×</span>');
    $('#drawer-bd').html(html);
    $('#drawer').css('width', width || '');
    $('#drawer').addClass('on');
  }
  function closeDrawer() { $('#drawer').removeClass('on'); }
  $(document).on('click', '#drawer', function (e) { if (e.target === this) closeDrawer(); });
  $(document).on('keydown', function (e) { if (e.keyCode === 27) { closeModal(); closeDrawer(); } });

  /* ---------- 左侧导航(分组) ---------- */
  var PAGE_LOAD = {
    'p-overview': function () { loadOverview(); },
    'p-sites': function () { loadSites(); },
    'p-protect': function () { loadRules($('#pr-type').val(), '#pr-table'); loadDeployHint(); },
    'p-limit': function () { loadLimits(); },
    'p-traffic': function () { loadIps(); },
    'p-region': function () { loadRegion(); },
    'p-port': function () { loadRules('port_proto', '#pp-table'); loadPortStatus(); },
    'p-logs': function () { loadLogs(1); },
    'p-stats': function () { loadStats(); },
    'p-alert': function () { loadAlertCfg(); switchAlertTab('al-ch'); },
    'p-av': function () { loadAv(); },
    'p-avcfg': function () { loadAvCfg(); },
    'p-ai': function () { loadAi(); },
    'p-version': function () { loadBackups(); },
    'p-waf': function () { loadWafStatus(); },
    'p-data': function () { },
    'p-perm': function () { loadPerm(); loadAudit(1); }
  };
  function go(id) {
    if (!id || !PAGE_LOAD[id]) return;
    $('.nav-item').removeClass('on');
    $('.nav-item[data-p="' + id + '"]').addClass('on');
    $('.panel').removeClass('on');
    $('#' + id).addClass('on');
    try { PAGE_LOAD[id](); } catch (e) { toast('页面加载失败: ' + e.message, true); }
    window.scrollTo(0, 0);
  }
  $(document).on('click', '.nav-item', function () { go($(this).data('p')); });
  function reloadAll() {
    loadStatusBar(); loadOverview();
    var cur = $('.nav-item.on').data('p');
    if (cur && cur !== 'p-overview' && PAGE_LOAD[cur]) PAGE_LOAD[cur]();
    toast('已刷新');
  }

  /* ---------- 总览 ---------- */
  var MODE_NAME = { loose: '宽松', standard: '标准', strict: '严格' };
  var OV = { waf_on: false, mode: 'standard' };
  var SITE_SERVER = {};

  function loadStatusBar() {
    api('GetOverview', {}, function (r) {
      if (r.status) renderStatus(r.data);
    });
  }

  /* 顶部状态条 + 待办 + 导航徽标: 复用同一次 GetOverview 结果 */
  function renderStatus(d) {
    OV.waf_on = d.waf_on; OV.mode = d.mode;
    setOn($('#st-switch'), 'on', !!d.waf_on);
    $('#st-waf-txt').text(d.waf_on ? '运行中' : '已关闭').css('color', d.waf_on ? '#20a53a' : '#e54545');
    $('#st-mode').text(MODE_NAME[d.mode] || d.mode);
    $('#st-today').text(d.today_attacks || 0);
    $('#st-analyze').text(d.last_analyze ? fmtTime(d.last_analyze) : '尚未分析');
    var server = d.server_status || {};
    $('#st-sites').text((server.nginx_sites || 0) + (server.apache_sites ? '/' + server.apache_sites : ''));
    // 导航徽标: 待确认规则 / 木马
    var pend = d.pending_rules || 0;
    setOn($('#badge-ai'), 'hide', !pend).text(pend);
    var lv = {};
    (d.scan_threats || []).forEach(function (x) { lv[x.level] = x.c; });
    var th = (lv.critical || 0) + (lv.high || 0);
    setOn($('#badge-av'), 'hide', !th).text(th);
    SITE_SERVER = server;
    highlightMode(d.mode);
    renderTodo(d);
  }

  function highlightMode(mode) {
    $('[data-mode]').removeClass('primary');
    $('[data-mode="' + (mode || 'standard') + '"]').addClass('primary');
  }

  function renderTodo(d) {
    var items = [];
    if (d.pending_rules) {
      items.push('<div style="margin:6px 0">待确认的自学习规则 <b style="color:#ff9900">' + d.pending_rules +
        '</b> 条 <a style="color:#20a53a" onclick="BFW.go(\'p-ai\')">去处理 →</a></div>');
    }
    var lv = {};
    (d.scan_threats || []).forEach(function (x) { lv[x.level] = x.c; });
    if ((lv.critical || 0) + (lv.high || 0) > 0) {
      items.push('<div style="margin:6px 0">未处理木马 <b style="color:#e54545">' + ((lv.critical || 0) + (lv.high || 0)) +
        '</b> 个 <a style="color:#20a53a" onclick="BFW.go(\'p-av\')">去查杀 →</a></div>');
    }
    if (d.fp_rate > 0.15) {
      items.push('<div style="margin:6px 0">误报率 <b style="color:#ff9900">' + (d.fp_rate * 100).toFixed(1) +
        '%</b> 超过 15%，建议检查规则或标记误报 <a style="color:#20a53a" onclick="BFW.go(\'p-protect\')">查看规则 →</a></div>');
    }
    var server = d.server_status || {};
    if (server.nginx_test === false) {
      items.push('<div style="margin:6px 0"><b style="color:#e54545">Nginx 配置校验失败</b>，请到' +
        '<a style="color:#20a53a" onclick="BFW.go(\'p-waf\')">部署诊断</a>查看</div>');
    }
    if (!items.length) items.push('<div class="muted">暂无待处理事项，防护运行正常。</div>');
    $('#ov-todo').html(items.join(''));
  }

  function loadOverview() {
    api('GetOverview', {}, function (r) {
      if (!r.status) return;
      var d = r.data, server = d.server_status || {};
      renderStatus(d);
      var ruleInfo = server.rules || {};
      $('#ov-cards').html(
        card('今日拦截', '<span class="v ' + (d.today_attacks > 0 ? 'err' : '') + '">' + (d.today_attacks || 0) + '</span>', '次（自然日）') +
        card('防护模式', '<span class="v">' + (MODE_NAME[d.mode] || d.mode || '-') + '</span>', '可在下方切换') +
        card('规则总数', '<span class="v">' + (d.total_rules || 0) + '</span>', '其中已下发 ' + (ruleInfo.total || 0) + ' 条') +
        card('误报率', '<span class="v ' + (d.fp_rate > 0.15 ? 'warn' : 'ok') + '">' + ((d.fp_rate || 0) * 100).toFixed(1) + '%</span>', '近' + (d.fp_window || 7) + '天') +
        card('联动站点', '<span class="v">' + (d.sites || 0) + '</span>', 'Nginx ' + (server.nginx_sites || 0) + ' 个') +
        card('自学习', '<span class="v ' + (d.auto_learn ? 'ok' : 'warn') + '">' + (d.auto_learn ? '开启' : '关闭') + '</span>', '每10分钟') +
        card('引擎', '<span class="v" style="font-size:15px;line-height:1.9">' + (server.nginx ? 'Nginx ' : '') +
          (server.apache ? 'Apache' : '') + (!server.nginx && !server.apache ? '未探测到' : '') + '</span>',
          (server.nginx ? '校验' + (server.nginx_test === false ? '失败' : server.nginx_test ? '通过' : '不可用') : '')));
      $('#mode-cur').text('当前：' + (MODE_NAME[d.mode] || d.mode) + '模式');
      highlightMode(d.mode);
      loadRecent();
    });
  }

  function loadRecent() {
    api('GetLogs', { page: 1, limit: 8 }, function (r) {
      if (!r.status) { $('#ov-recent').html('<div class="empty">暂无攻击日志</div>'); return; }
      var rows = r.data.rows || [];
      if (!rows.length) { $('#ov-recent').html('<div class="empty">暂无攻击日志</div>'); return; }
      var h = '<table><tr><th>时间</th><th>IP</th><th>类型</th><th>URI</th><th>级别</th></tr>';
      rows.forEach(function (x) {
        h += '<tr style="cursor:pointer" onclick="BFW.showLogDetail(' + x.id + ')"><td>' + fmtTime(x.ts) +
          '</td><td>' + esc(x.ip) + '</td><td><span class="tag info">' + (RULE_NAMES[x.rule_type] || x.rule_type) +
          '</span></td><td><code>' + esc(x.uri) + '</code></td><td><span class="tag ' + esc(x.level) + '">' +
          esc(x.level) + '</span></td></tr>';
      });
      $('#ov-recent').html(h + '</table>');
    });
  }

  function card(k, v, unit) {
    return '<div class="card"><div class="k">' + k + '</div><div>' + v +
      ' <span class="sub">' + (unit || '') + '</span></div></div>';
  }
  function toggleWaf() {
    var next = !OV.waf_on;
    if (!confirm((next ? '开启' : '关闭') + '防火墙？将重写所有已注入站点的 WAF 配置并 reload（失败会自动回滚）。')) return;
    api('SetWafStatus', { on: next ? '1' : '0' }, function (r) {
      toast(r.msg || '已更新', !r.status);
      loadOverview();
    });
  }
  $(document).on('click', '[data-mode]', function () {
    var m = $(this).data('mode');
    if (!confirm('切换为「' + MODE_NAME[m] + '模式」并重新下发已开启防护的站点？')) return;
    api('SetMode', { mode: m }, function (r) {
      toast(r.msg || '已切换', !r.status);
      if (r.status) { highlightMode(m); loadOverview(); }
    });
  });

  /* ---------- 站点防护 ---------- */
  var SITE_SEL = {}, SITE_ROWS = [], DEPLOY_REPORT = null;
  function loadSites() {
    api('GetSites', {}, function (r) {
      if (!r.status) return;
      var kw = $.trim($('#site-kw').val() || '').toLowerCase();
      var all = r.data || [];
      var rows = all.filter(function (s) {
        return !kw || (s.name || '').toLowerCase().indexOf(kw) >= 0;
      });
      if (!all.length) {
        $('#site-table').html('<div class="empty">当前没有站点。请先在宝塔面板「网站」中添加站点，' +
          '刷新后这里会自动列出并支持一键开启防护。</div>');
        $('#sites-hint').text('未检测到任何站点，暂无需要下发的 WAF 配置。');
        loadDeployReport();
        return;
      }
      if (!rows.length) { $('#site-table').html('<div class="empty">没有匹配的站点</div>'); return; }
      SITE_ROWS = rows;
      var valid = {};
      rows.forEach(function (s) { if (SITE_SEL[s.name]) valid[s.name] = 1; });
      SITE_SEL = valid;
      var h = '<table><tr><th style="width:34px"><input type="checkbox" id="site-all" onclick="BFW.pickSitePage(this.checked)"></th>' +
        '<th>站点</th><th>路径</th><th>WAF</th><th>模式</th><th>操作</th></tr>';
      rows.forEach(function (s) {
        var conf = s.waf || {};
        var on = !!conf.on;
        h += '<tr><td><input type="checkbox" class="siteck"' + (SITE_SEL[s.name] ? ' checked' : '') +
          ' onclick="BFW.pickSite(\'' + jsq(s.name) + '\',this.checked)"></td>' +
          '<td><b>' + esc(s.name) + '</b>' + (s.ps ? '<div class="muted">' + esc(s.ps) + '</div>' : '') + '</td>' +
          '<td class="muted">' + esc(s.path || '-') + '</td>' +
          '<td><span class="switch ' + (on ? 'on' : '') + '" onclick="BFW.toggleSite(\'' + jsq(s.name) + '\',' + (!on) + ')"><i></i></span>' +
          ' <span class="muted">' + (on ? '已开启' : '未开启') + '</span></td>' +
          '<td><select onchange="BFW.setSiteMode(\'' + jsq(s.name) + '\',this.value,' + (on ? 1 : 0) + ')" style="padding:2px 6px">' +
          '<option value="">跟随全局</option>' +
          ['loose', 'standard', 'strict'].map(function (m) {
            return '<option value="' + m + '"' + (conf.mode === m ? ' selected' : '') + '>' + MODE_NAME[m] + '</option>';
          }).join('') + '</select></td>' +
          '<td><button class="btn sm" onclick="BFW.toggleSite(\'' + jsq(s.name) + '\',' + (!on) + ')">' +
          (on ? '关闭' : '开启') + '</button>' +
          '<button class="btn sm plain" onclick="BFW.showSitePreview(\'' + jsq(s.name) + '\')">预览配置</button></td></tr>';
      });
      var picked = Object.keys(SITE_SEL || {}).length;
      var bar = picked ? ('<div class="toolbar"><span class="muted">已选 ' + picked + ' 个站点</span>' +
        '<button class="btn sm" onclick="BFW.batchSite(1)">开启</button>' +
        '<button class="btn sm" onclick="BFW.batchSite(0)">关闭</button>' +
        '<button class="btn sm plain" onclick="BFW.clearSiteSel()">取消选择</button></div>') : '';
      $('#site-table').html(bar + h + '</table>');
      var srv = SITE_SERVER || {};
      $('#sites-hint').html('当前已下发：Nginx <b>' + (srv.nginx_sites || 0) + '</b> 个站点 / Apache <b>' +
        (srv.apache_sites || 0) + '</b> 个站点。未开启防护的站点不会被注入任何配置。');
      loadDeployReport();
    });
  }

  var PREVIEW = { site: '', tab: 'nginx' };
  function showSitePreview(site) {
    api('GetSitePreview', { site: site }, function (r) {
      if (!r.status) return toast(r.msg || '预览失败', true);
      var d = r.data;
      PREVIEW = { site: site, tab: 'nginx', data: d };
      var state = d.active ? '<span class="tag ok">会写入并生效</span>'
        : '<span class="tag gray">当前不生效（站点或总开关关闭）</span>';
      var html = '<div class="toolbar" style="margin-bottom:6px">' +
        '<span class="tag info">' + esc(site) + '</span>' + state +
        '<span class="muted">模式 ' + (MODE_NAME[d.mode] || d.mode) + '；频率规则 ' + (d.freq_rules || 0) + ' 条</span></div>' +
        '<div class="table-wrap"><table><tr><th>引擎</th><th>vhost 文件</th><th>注入状态</th></tr>' +
        '<tr><td>Nginx</td><td><code>' + esc(d.nginx.path || '-') + '</code></td><td>' +
        (d.nginx.exists ? (d.nginx.injected ? '<span class="tag ok">已注入 include</span>' : '<span class="tag warn">未注入</span>')
          : '<span class="tag gray">文件不存在</span>') + '</td></tr>' +
        '<tr><td>Apache</td><td><code>' + esc(d.apache.path || '-') + '</code></td><td>' +
        (d.apache.exists ? (d.apache.injected ? '<span class="tag ok">已注入 include</span>' : '<span class="tag warn">未注入</span>')
          : '<span class="tag gray">文件不存在</span>') + '</td></tr>' +
        '</table></div>' +
        '<div class="toolbar" style="margin:10px 0 6px">' +
        '<button class="btn sm" id="pv-nginx" onclick="BFW.previewTab(\'nginx\')">Nginx 配置</button>' +
        '<button class="btn sm plain" id="pv-apache" onclick="BFW.previewTab(\'apache\')">Apache 配置</button>' +
        '<span class="muted">这是重新生成后的内容，实际写入位置：sinanwaf/waf/vhost|apache/&lt;site&gt;.conf</span></div>' +
        '<pre id="pv-conf" style="max-height:52vh">' + esc(d.nginx.conf || '') + '</pre>';
      openDrawer('站点配置预览 · ' + site, html, '760px');
    });
  }
  function previewTab(which) {
    var d = PREVIEW.data;
    if (!d) return;
    PREVIEW.tab = which;
    $('#pv-conf').text(d[which].conf || '');
    if (which === 'nginx') { $('#pv-nginx').removeClass('plain'); $('#pv-apache').addClass('plain'); }
    else { $('#pv-apache').removeClass('plain'); $('#pv-nginx').addClass('plain'); }
  }
  function loadDeployReport() {
    api('GetDeployReport', {}, function (r) {
      if (!r.status) { $('#deploy-report').html('<div class="empty">无法读取下发记录</div>'); return; }
      var d = r.data || {};
      DEPLOY_REPORT = d;
      var last = d.last_deploy || {};
      var lg = last.result || {};
      var bad = (d.sites || []).filter(function (x) { return !x.ok; });
      var h = '<div class="toolbar" style="margin-bottom:6px">' +
        '<span class="muted">全局配置：' + (d.global_injected ? '<span class="tag ok">已注入</span>' : '<span class="tag warn">未注入</span>') +
        '　Nginx 校验：' + (d.nginx_test === true ? '<span class="tag ok">通过</span>' :
          d.nginx_test === false ? '<span class="tag high">失败</span>' : '<span class="tag gray">不可用</span>') +
        '　频率规则 zone：' + (d.freq_rules || 0) + ' 个</span></div>';
      if (last.time) {
        h += '<div class="muted" style="margin-bottom:6px">最近一次全局下发：' + fmtTime(last.time) +
          (lg.errors && lg.errors.length ? '（错误：' + esc(lg.errors.join('; ').slice(0, 160)) + '）' : '') + '</div>';
      }
      if (!bad.length) {
        h += '<div class="hint ok">最近一次站点下发没有失败记录。</div>';
      } else {
        h += '<div class="hint warn">' + bad.length + ' 个站点最近一次下发失败：</div>' +
          '<div class="table-wrap"><table><tr><th>站点</th><th>时间</th><th>错误</th></tr>';
        bad.slice(0, 10).forEach(function (x) {
          h += '<tr><td>' + esc(x.site) + '</td><td class="muted">' + fmtTime(x.time) + '</td>' +
            '<td class="muted">' + esc((x.errors || []).join('; ').slice(0, 200)) + '</td></tr>';
        });
        h += '</table></div>' +
          '<div class="toolbar" style="margin-top:6px">' +
          '<button class="btn sm primary" onclick="BFW.retryFailedSites()">重试这些站点</button>' +
          '<span class="muted">重试只重新下发失败站点，成功站点不受影响</span></div>';
      }
      var good = (d.sites || []).filter(function (x) { return x.ok; });
      if (good.length) {
        h += '<div class="muted" style="margin-top:6px">最近成功下发：' +
          good.slice(0, 6).map(function (x) { return esc(x.site) + '(' + fmtTime(x.time) + ')'; }).join('、') + '</div>';
      }
      $('#deploy-report').html(h);
    });
  }

  function setSiteMode(site, mode, on) {
    api('SetSiteWaf', { site: site, on: on ? '1' : '0', mode: mode || '' }, function (r) {
      toast(r.msg || '已更新', !r.status); loadSites(); loadStatusBar();
    });
  }

  function pickSite(name, on) {
    if (on) SITE_SEL[name] = 1; else delete SITE_SEL[name];
  }
  function pickSitePage(on) {
    SITE_ROWS.forEach(function (s) {
      if (on) SITE_SEL[s.name] = 1; else delete SITE_SEL[s.name];
    });
    loadSites();
  }
  function batchSite(on) {
    var names = [];
    for (var k in SITE_SEL) { if (SITE_SEL[k]) names.push(k); }
    if (!names.length) return toast('请先勾选站点', true);
    if (!confirm('确认' + (on ? '开启' : '关闭') + '选中的 ' + names.length + ' 个站点的 WAF？')) return;
    api('SetSitesWaf', { sites: names.join(','), on: on ? '1' : '0' }, function (r) {
      toast(r.msg || (r.status ? '已批量更新' : '操作失败'), !r.status);
      if (r.status) { SITE_SEL = {}; loadSites(); loadStatusBar(); }
    });
  }
  function clearSiteSel() {
    SITE_SEL = {};
    loadSites();
  }
  function batchAllSites(on) {
    api('GetSites', {}, function (r) {
      var names = ((r.data || [])).map(function (s) { return s.name; });
      if (!names.length) return toast('没有可操作的站点', true);
      if (!confirm('确认' + (on ? '开启' : '关闭') + '全部 ' + names.length + ' 个站点的 WAF？\n' +
        (on ? '将给所有站点注入防护配置。' : '将移除所有站点的防护配置。'))) return;
      api('SetSitesWaf', { sites: names.join(','), on: on ? '1' : '0' }, function (rr) {
        toast(rr.msg || (rr.status ? '已更新全部站点' : '操作失败'), !rr.status);
        if (rr.status) { loadSites(); loadStatusBar(); }
      });
    });
  }
  function retryFailedSites() {
    var bad = ((DEPLOY_REPORT || {}).sites || []).filter(function (x) { return !x.ok; });
    if (!bad.length) return toast('没有失败站点', true);
    var names = bad.map(function (x) { return x.site; });
    api('SetSitesWaf', { sites: names.join(','), on: '1' }, function (r) {
      toast(r.msg || (r.status ? '已重试' : '重试失败'), !r.status);
      loadSites();
    });
  }

  /* ---------- 规则通用 ---------- */
  var RULE_NAMES = {
    sqli: 'SQL注入', xss: 'XSS', upload: '文件上传', trojan: '木马', bot: '恶意爬虫',
    path_scan: '敏感路径', url: 'URL', ua: 'UA', referer: 'Referer', freq: '频率',
    port_proto: '端口', ip_black: 'IP黑名单', ip_white: 'IP白名单', ip_region: '地区', freq: '频率'
  };
  window.BFW_RULE_NAMES = RULE_NAMES;
  function ruleTable(rules, type) {
    if (!rules || !rules.length) return '<div class="empty">暂无规则</div>';
    var deployable = ['sqli', 'xss', 'upload', 'trojan', 'bot', 'path_scan', 'url', 'ua',
      'referer', 'freq'].indexOf(type) >= 0;
    var h = '<table><tr><th>名称</th><th>内容</th><th>级别</th><th>动作</th><th>是否下发</th><th>命中/误报</th><th>来源</th><th>状态</th><th>操作</th></tr>';
    rules.forEach(function (r) {
      var dispatch = '—';
      if (deployable) {
        dispatch = (r.on && r.mode === 'block') ? '<span class="tag ok">拦截生效</span>'
          : (r.on ? '<span class="tag gray">仅记录</span>' : '<span class="tag gray">未启用</span>');
      }
      h += '<tr><td>' + esc(r.name) + '<div class="muted">' + esc(r.note || '') + '</div></td>' +
        '<td style="max-width:280px"><code>' + esc(r.pattern) + '</code>' +
        (type === 'freq' ? '<div class="muted">限速 ' + esc(r.rate || '-') +
          '，突发 ' + (r.burst || 0) + '</div>' : '') + '</td>' +
        '<td><span class="tag ' + esc(r.level) + '">' + esc(r.level) + '</span></td>' +
        '<td>' + (r.mode === 'block' ? '拦截' : r.mode === 'log' ? '仅记录' : '放行') + '</td>' +
        '<td>' + dispatch + '</td>' +
        '<td>' + (r.hits || 0) + ' / ' + (r.fp || 0) + '</td>' +
        '<td>' + esc(r.source || 'manual') + '</td>' +
        '<td><span class="switch ' + (r.on ? 'on' : '') + '" onclick="BFW.toggleRule(\'' + type + '\',\'' + jsq(r.id) + '\',' + (!r.on) + ')"><i></i></span></td>' +
        '<td><button class="btn sm err" onclick="BFW.delRule(\'' + type + '\',\'' + jsq(r.id) + '\')">删除</button></td></tr>';
    });
    return h + '</table>';
  }
  function loadRules(type, sel) {
    api('GetRules', { rule_type: type }, function (r) {
      if (!r.status) { $(sel).html('<div class="empty">加载失败: ' + esc(r.msg || '') + '</div>'); return; }
      $(sel).html(ruleTable(r.data, type));
    });
  }
  $('#pr-type').change(function () {
    var isFreq = $(this).val() === 'freq';
    if (isFreq) $('#pr-freq-box').show(); else $('#pr-freq-box').hide();
    loadRules($(this).val(), '#pr-table');
  });
  $(document).on('keydown', '#pr-pat', function (e) {
    if (e.keyCode === 13) { e.preventDefault(); addRule('protect'); }
  });

  function loadDeployHint() {
    api('GetDeployPreview', {}, function (r) {
      if (!r.status) return;
      var d = r.data;
      var byType = d.by_type || {};
      var parts = Object.keys(byType).map(function (k) {
        return (RULE_NAMES[k] || k) + ' ' + byType[k];
      });
      var h = '当前会被下发到 Nginx/Apache 的规则共 <b>' + d.total + '</b> 条' +
        (parts.length ? '（' + parts.join('、') + '）' : '') + '。';
      if (d.skipped_count) {
        h += '<div class="hint warn" style="margin:6px 0 0">有 ' + d.skipped_count +
          ' 条规则未下发：' + d.skipped.slice(0, 5).map(function (x) {
            return esc(x.pattern) + '(' + esc(x.reason) + ')';
          }).join('、') + '。请修正规则内容。</div>';
      }
      $('#deploy-hint').html(h);
    });
  }

  function addRule(kind, dest) {
    if (kind === 'protect') {
      var t = $('#pr-type').val(), n = $('#pr-name').val(), p = $.trim($('#pr-pat').val() || '');
      if (!p) return toast('请输入规则内容', true);
      var lv = $('#pr-level').val(), md = $('#pr-mode').val();
      var payload = { rule_type: t, name: n, pattern: p, level: lv, mode: md };
      if (t === 'freq') {
        payload.rate = $.trim($('#pr-rate').val() || '');
        payload.burst = $.trim($('#pr-burst').val() || '0');
        if (!payload.rate) return toast('频率规则请填写速率，如 10r/s', true);
      }
      api('AddRule', payload, function (r) {
        toast(r.msg || (r.status ? '规则已添加' : '添加失败'), !r.status);
        if (r.status) { $('#pr-pat').val(''); loadRules(t, '#pr-table'); loadDeployHint(); }
      });
    } else if (kind === 'port_proto') {
      var p2 = $.trim($('#pp-pat').val() || '');
      if (!p2) return toast('请输入端口规则，如 3306/TCP', true);
      api('AddRule', { rule_type: 'port_proto', name: '端口' + p2, pattern: p2, level: 'medium', mode: 'block' }, function (r) {
        toast(r.msg || (r.status ? '已添加' : '添加失败'), !r.status);
        if (r.status) { $('#pp-pat').val(''); loadRules('port_proto', '#pp-table'); loadPortStatus(); }
      });
    }
  }

  function showRuleTest() {
    openModal('<h4>规则测试</h4>' +
      '<p class="muted">输入一个真实 URL / UA，检查当前规则库是否会命中（仅做本地匹配，不会下发）。</p>' +
      '<label>URI</label><input id="rt-uri" placeholder="/product/list?page=1">' +
      '<label>User-Agent</label><input id="rt-ua" placeholder="Mozilla/5.0 ...">' +
      '<label>Referer</label><input id="rt-ref" placeholder="https://example.com">' +
      '<div class="hint" id="rt-out" style="margin-top:10px">填写后点击测试</div>' +
      '<p><button class="btn primary" onclick="BFW.runRuleTest()">开始测试</button> ' +
      '<button class="btn" onclick="BFW.closeModal()">关闭</button></p>');
  }
  function runRuleTest() {
    var uri = $('#rt-uri').val() || '/', ua = $('#rt-ua').val() || '', ref = $('#rt-ref').val() || '';
    api('TestRule', { uri: uri, ua: ua, referer: ref }, function (r) {
      if (!r.status) { $('#rt-out').text(r.msg || '测试失败'); return; }
      var hits = r.data.hits || [];
      if (r.data.whitelisted) {
        $('#rt-out').html('<span style="color:#ff9900">测试 IP ' + esc(r.data.ip) +
          ' 在 IP 白名单中，命中规则也会被放行。</span>');
        return;
      }
      if (!hits.length) {
        $('#rt-out').html('<b style="color:#20a53a">未命中任何规则</b>，该请求会被放行。' +
          '<div class="muted">测试 IP: ' + esc(r.data.ip) + '</div>');
        return;
      }
      var h = '<b>命中 ' + hits.length + ' 条规则：</b><div class="table-wrap" style="margin-top:6px">' +
        '<table><tr><th>类型</th><th>规则</th><th>级别</th><th>动作</th></tr>';
      hits.forEach(function (x) {
        h += '<tr><td>' + (RULE_NAMES[x.rule_type] || x.rule_type) + '</td><td>' + esc(x.rule) +
          '</td><td><span class="tag ' + esc(x.level) + '">' + esc(x.level) + '</span></td><td>' +
          (x.mode === 'block' ? '拦截' : '仅记录') + '</td></tr>';
      });
      $('#rt-out').html(h + '</table></div>');
    });
  }

  function refreshRules(t) {
    if (t === 'ip_black' || t === 'ip_white') loadIps();
    else if (t === 'ip_region') loadRegion();
    else loadRules(t, t === 'port_proto' ? '#pp-table' : '#pr-table');
  }

  var _siteOps = {
    toggleRule: function (t, id, on) {
      api('UpdateRule', { rule_type: t, id: id, on: on ? '1' : '0' }, function (r) {
        toast(r.msg || (r.status ? '已更新' : '更新失败'), !r.status);
        if (r.status) { refreshRules(t); if (t !== 'port_proto') loadDeployHint(); }
      });
    },
    delRule: function (t, id) {
      if (!confirm('确认删除该规则？删除后会立即重新下发配置。')) return;
      api('DelRule', { rule_type: t, id: id }, function (r) {
        toast(r.msg || (r.status ? '已删除' : '删除失败'), !r.status);
        if (r.status) { refreshRules(t); if (t !== 'port_proto') loadDeployHint(); }
      });
    },
    toggleSite: function (site, on) {
      api('SetSiteWaf', { site: site, on: on ? '1' : '0' }, function (r) {
        toast(r.msg || (r.status ? '已更新' : '操作失败'), !r.status);
        if (r.status) { loadSites(); loadStatusBar(); }
      });
    },
    reloadWaf: function () {
      api('ReloadWaf', {}, function (r) {
        toast(r.msg || '已下发', !r.status); loadStatusBar();
        var cur = $('.nav-item.on').data('p');
        if (cur === 'p-sites') loadSites();
        if (cur === 'p-waf') loadWafStatus();
      });
    }
  };

  /* ---------- IP名单 ---------- */
  var IPS = { page: 1, limit: 20, total: 0, kw: '', rows: [], sel: {}, timer: null, all: false };

  function ipType() { return $('#ip-type').val(); }
  function ipSelectable(t) { return t === 'ip_black' || t === 'ip_white'; }

  function expireText(r) {
    var ea = parseInt(r.expire_at || 0, 10);
    if (!ea) return '<span class="muted">永久</span>';
    var left = ea - Math.floor(Date.now() / 1000);
    if (left <= 0) return '<span class="tag warn">已到期</span>';
    if (left < 3600) return '<span class="tag warn">' + Math.ceil(left / 60) + ' 分钟后</span>';
    return '<span class="muted">' + fmtTime(ea) + '</span>';
  }

  function loadIps(page) {
    if (page) IPS.page = page;
    IPS.kw = $.trim($('#ip-search').val() || '');
    api('GetRulePage', { rule_type: ipType(), page: IPS.page, limit: IPS.limit, keyword: IPS.kw },
      function (r) {
        if (!r.status) {
          $('#ip-table').html('<div class="empty">加载失败: ' + esc(r.msg || '') + '</div>');
          return;
        }
        var d = r.data || {};
        IPS.rows = d.rows || [];
        IPS.total = d.total || 0;
        var maxPage = Math.max(1, Math.ceil(IPS.total / IPS.limit));
        if (IPS.page > maxPage) { IPS.page = maxPage; return loadIps(); }
        if (IPS.page < 1) IPS.page = 1;
        // 只保留当前页仍存在的勾选
        var valid = {};
        IPS.rows.forEach(function (x) { if (IPS.sel[x.id]) valid[x.id] = 1; });
        IPS.sel = valid;
        $('#ip-table').html(ipTable(ipType()));
      });
  }

  function ipTable(t) {
    var sel = ipSelectable(t);
    if (!IPS.rows.length) {
      $('#ip-tip').text(IPS.kw ? ('搜索「' + IPS.kw + '」无结果') : '');
      return '<div class="empty">' + (IPS.kw ? '没有匹配的记录' : '暂无规则') + '</div>';
    }
    var h = '<table><tr>';
    if (sel) h += '<th style="width:34px"><input type="checkbox" id="ip-all" onclick="BFW.pickIpPage(this.checked)"></th>';
    h += '<th>名称</th><th>内容</th><th>级别</th><th>动作</th><th>到期</th><th>命中/误报</th><th>来源</th><th>状态</th><th>操作</th></tr>';
    IPS.rows.forEach(function (r) {
      h += '<tr>';
      if (sel) {
        h += '<td><input type="checkbox" class="ipck"' + (IPS.sel[r.id] ? ' checked' : '') +
          ' onclick="BFW.pickIp(\'' + jsq(r.id) + '\',this.checked)"></td>';
      }
      h += '<td>' + esc(r.name) + '<div class="muted">' + esc(r.note || '') + '</div></td>' +
        '<td style="max-width:240px"><code>' + esc(r.pattern) + '</code></td>' +
        '<td><span class="tag ' + esc(r.level) + '">' + esc(r.level) + '</span></td>' +
        '<td>' + (r.mode === 'block' ? '拦截' : r.mode === 'log' ? '仅记录' : '放行') + '</td>' +
        '<td>' + expireText(r) + '</td>' +
        '<td>' + (r.hits || 0) + ' / ' + (r.fp || 0) + '</td>' +
        '<td>' + esc(r.source || 'manual') + '</td>' +
        '<td><span class="switch ' + (r.on ? 'on' : '') + '" onclick="BFW.toggleRule(\'' + t + '\',\'' + jsq(r.id) + '\',' + (!r.on) + ')"><i></i></span></td>' +
        '<td><button class="btn sm err" onclick="BFW.delRule(\'' + t + '\',\'' + jsq(r.id) + '\')">删除</button></td></tr>';
    });
    var maxPage = Math.max(1, Math.ceil(IPS.total / IPS.limit));
    h += '</table><div class="pager">共 ' + IPS.total + ' 条';
    var picked = ipPicked();
    if (sel && IPS.all) {
      h += '，<b style="color:#e54545">已全选当前筛选的 ' + IPS.total + ' 条</b>';
    } else if (sel && picked.length) {
      h += '，已选 ' + picked.length + ' 条';
    }
    h += ' <button onclick="BFW.ipPage(-1)">上一页</button> 第 ' + IPS.page + ' / ' + maxPage +
      ' 页 <button onclick="BFW.ipPage(1)">下一页</button>';
    if (sel) {
      h += ' <label class="inline" style="margin-left:10px"><input type="checkbox" id="ip-all-filter"' +
        (IPS.all ? ' checked' : '') + ' onclick="BFW.pickIpAll(this.checked)"> 跨页全选筛选结果（' +
        IPS.total + ' 条）</label>';
    }
    h += '</div>';
    $('#ip-tip').text(sel ? '勾选后可批量删除；搜索与导出按当前条件' + (IPS.kw ? '（已搜索）' : '') +
      '；带到期时间的规则由计划任务自动解封' : '');
    return h;
  }

  function ipPicked() {
    var out = [];
    for (var k in IPS.sel) { if (IPS.sel[k]) out.push(k); }
    return out;
  }
  function pickIp(id, on) {
    if (on) IPS.sel[id] = 1; else delete IPS.sel[id];
    if (on) IPS.all = false;
    $('#ip-table').html(ipTable(ipType()));
  }
  function pickIpAll(on) {
    IPS.all = !!on;
    IPS.sel = {};
    $('#ip-table').html(ipTable(ipType()));
  }
  function pickIpPage(on) {
    IPS.rows.forEach(function (r) {
      if (on) IPS.sel[r.id] = 1; else delete IPS.sel[r.id];
    });
    $('#ip-table').html(ipTable(ipType()));
  }
  function ipPage(d) {
    var maxPage = Math.max(1, Math.ceil(IPS.total / IPS.limit));
    var p = IPS.page + d;
    if (p < 1 || p > maxPage) return;
    loadIps(p);
  }

  $('#ip-type').change(function () {
    IPS.sel = {};
    IPS.all = false;
    IPS.page = 1;
    loadIps();
  });
  $('#ip-search').on('input', function () {
    IPS.all = false;
    clearTimeout(IPS.timer);
    IPS.timer = setTimeout(function () { loadIps(1); }, 200);
  });

  function addIp() {
    var t = ipType(), p = $.trim($('#ip-pat').val() || ''), note = $.trim($('#ip-note').val() || '');
    if (!p) return toast('请输入 IP / 网段', true);
    api('AddRule', {
      rule_type: t, name: note || p, pattern: p, note: note, level: 'high', mode: 'block',
      ttl_hours: $('#ip-ttl').val() || 0
    }, function (r) {
      toast(r.msg || (r.status ? '已添加' : '添加失败'), !r.status);
      if (r.status) { $('#ip-pat').val(''); $('#ip-note').val(''); loadIps(1); }
    });
  }
  function purgeExpired() {
    api('PurgeExpiredRules', {}, function (r) {
      toast(r.msg || '已清理', !r.status);
      if (r.status) { loadIps(1); loadStatusBar(); }
    });
  }
  function exportIps() {
    var t = ipType();
    if (!ipSelectable(t)) return toast('地区封禁请使用规则导出');
    api('ExportIpList', { rule_type: t, fmt: $('#ip-efmt').val(), keyword: IPS.kw }, function (r) {
      if (!r.status) return;
      var d = r.data || {};
      if (d.content && downloadText(d.filename, d.content, d.mime)) toast('已导出 ' + d.count + ' 条');
      else toast('文件已生成: ' + (d.path || ''));
    });
  }
  function delSelectedIps() {
    var t = ipType();
    var ids = ipPicked();
    if (IPS.all) {
      if (!confirm('确认删除当前筛选条件下的全部 ' + IPS.total + ' 条规则？' +
        (IPS.kw ? '（筛选关键词：' + IPS.kw + '）' : '（无筛选，将清空该类型全部规则）') +
        '\n删除后会立即重新下发名单，此操作不可撤销。')) return;
      api('BatchDelRule', { rule_type: t, all: '1', keyword: IPS.kw }, function (r) {
        toast(r.msg || (r.status ? '已删除' : '删除失败'), !r.status);
        if (!r.status) return;
        IPS.sel = {};
        IPS.all = false;
        loadIps(1);
      });
      return;
    }
    if (!ids.length) return toast('请先勾选要删除的规则', true);
    if (!confirm('确认删除选中的 ' + ids.length + ' 条规则？删除后会立即重新下发名单。')) return;
    api('BatchDelRule', { rule_type: t, ids: ids.join(',') }, function (r) {
      toast(r.msg || (r.status ? '已删除' : '删除失败'), !r.status);
      if (!r.status) return;
      IPS.sel = {};
      loadIps(1);
    });
  }

  /* ---------- 地区封禁 ---------- */
  function loadRegion() {
    api('GetRules', { rule_type: 'ip_region' }, function (r) {
      var rows = (r && r.data) || [];
      $('#rg-stat').text('已配置 ' + rows.length + ' 条地区规则');
      if (!rows.length) { $('#rg-table').html('<div class="empty">暂无地区规则</div>'); return; }
      var h = '<table><tr><th>地区代码</th><th>动作</th><th>状态</th><th>操作</th></tr>';
      rows.forEach(function (x) {
        h += '<tr><td><b>' + esc(x.pattern) + '</b></td><td>' + (x.mode === 'block' ? '拦截（当前仅记录）' : '仅记录') +
          '</td><td><span class="switch ' + (x.on ? 'on' : '') + '" onclick="BFW.toggleRule(\'ip_region\',\'' +
          jsq(x.id) + '\',' + (!x.on) + ')"><i></i></span></td>' +
          '<td><button class="btn sm err" onclick="BFW.delRule(\'ip_region\',\'' + jsq(x.id) + '\')">删除</button></td></tr>';
      });
      $('#rg-table').html(h + '</table>');
    });
  }
  function addRegion() {
    var code = $.trim($('#rg-code').val() || '').toUpperCase();
    if (!/^[A-Z]{2}$/.test(code)) return toast('请输入两位国家代码，如 CN', true);
    api('AddRule', { rule_type: 'ip_region', name: '地区:' + code, pattern: code, level: 'medium', mode: $('#rg-mode').val() || 'log' },
      function (r) {
        toast(r.msg || (r.status ? '已添加' : '添加失败'), !r.status);
        if (r.status) { $('#rg-code').val(''); loadRegion(); }
      });
  }

  /* ---------- 端口与协议 ---------- */
  function loadPortStatus() {
    api('GetWafStatus', {}, function (r) {
      if (!r.status) return;
      setOn($('#port-switch'), 'on', !!r.data.port_enforce);
      $('#port-result').html('端口规则下发开关：<b>' + (r.data.port_enforce ? '已开启' : '已关闭') +
        '</b>。关闭时点击下发只会提示，不会改动系统防火墙。');
    });
  }
  function togglePortEnforce() {
    var next = !$('#port-switch').hasClass('on');
    if (next && !confirm('开启后，"立即下发"会把端口规则写入 iptables 并持久化。受保护端口不会被封禁。确认开启？')) return;
    api('SetPortEnforce', { on: next ? '1' : '0' }, function (r) {
      toast(r.msg || '已更新', !r.status);
      if (r.status) loadPortStatus();
    });
  }
  function syncPortRules(dry) {
    api('SyncPortRules', { dry_run: dry ? '1' : '0' }, function (r) {
      if (!r.status) { $('#port-result').html('<span style="color:#e54545">' + esc(r.msg || '下发失败') + '</span>'); toast(r.msg || '下发失败', true); return; }
      var d = r.data || {};
      var list = dry ? (d.plan || []) : (d.applied || []);
      var h = (dry ? '预演结果：' : '已下发：') + (list.length ? list.join('、') : '无') +
        (d.ignored && d.ignored.length ? '<div class="muted">跳过：' + d.ignored.map(function (x) {
          return esc(x.pattern) + '(' + esc(x.reason) + ')';
        }).join('、') + '</div>' : '') +
        (!dry && 'persisted' in d ? '<div class="muted">持久化：' + (d.persisted ? '成功' : '未成功（重启后失效）') + '</div>' : '');
      $('#port-result').html(h);
      toast(r.msg || '完成', !r.status);
    });
  }

  /* ---------- IP批量提取 / 快速封禁 ---------- */
  var IPX = { subnet: true, list: [], timer: null, src: '' };

  function ipValid(ip) {
    var p = String(ip).split('.');
    if (p.length !== 4) return false;
    for (var i = 0; i < 4; i++) {
      if (!/^\d{1,3}$/.test(p[i]) || +p[i] > 255) return false;
    }
    return true;
  }
  function ipFormat(ip) {
    if (!IPX.subnet) return ip;
    var p = ip.split('.'), net = p[0] + '.' + p[1] + '.' + p[2];
    return net + '.0-' + net + '.255';
  }
  function ipxExtract() {
    var text = $('#ipx-src').val() || '';
    var re = /(?:\d{1,3}\.){3}\d{1,3}/g, m, seen = {}, list = [];
    while ((m = re.exec(text)) !== null) {
      if (!ipValid(m[0])) continue;
      var line = ipFormat(m[0]);
      if (seen[line]) continue;
      seen[line] = 1;
      list.push(line);
      if (list.length >= 2000) break;
    }
    IPX.list = list;
    $('#ipx-out').val(list.join('\n'));
    $('#ipx-stat').text(list.length ?
      ('已提取 ' + list.length + ' 条' + (IPX.subnet ? '（按 /24 网段）' : '（单个 IP）')) : '');
  }
  $(document).on('input', '#ipx-src', function () {
    IPX.src = $(this).val();
    clearTimeout(IPX.timer);
    IPX.timer = setTimeout(ipxExtract, 180);
  });
  function showIpBanTool() {
    var subnet = IPX.subnet !== false;
    openModal('<h4>粘贴批量封禁</h4>' +
      '<p class="muted" style="margin:4px 0 8px">粘贴攻击日志/表格/聊天记录，自动提取去重（支持 1.2.3.4、带端口、CIDR、区间）。</p>' +
      '<div class="ipx">' +
      '<textarea id="ipx-src" rows="7" placeholder="1.2.3.4&#10;5.6.7.8:8080&#10;9.10.11.0-9.10.11.255">' +
      esc(IPX.src || '') + '</textarea>' +
      '<textarea id="ipx-out" rows="7" readonly>' + esc((IPX.list || []).join('\n')) + '</textarea>' +
      '</div>' +
      '<div class="toolbar" style="margin-top:9px">' +
      '<span class="switch ' + (subnet ? 'on' : '') + '" id="ipx-mode" onclick="BFW.toggleIpMode()"><i></i></span>' +
      '<span id="ipx-mode-txt">' + (subnet ? '封禁整个网段 x.x.x.0-x.x.x.255' : '仅封禁单个 IP') + '</span>' +
      '<span class="muted" id="ipx-stat"></span><span class="fill"></span>' +
      '<select id="ipx-ttl"><option value="0">永久封禁</option><option value="1">1 小时</option>' +
      '<option value="24">24 小时</option><option value="168">7 天</option></select>' +
      '<button class="btn" onclick="BFW.copyIps()">一键复制</button>' +
      '<button class="btn primary" onclick="BFW.banIps()">批量封禁</button>' +
      '</div>');
    if (IPX.list && IPX.list.length) {
      $('#ipx-stat').text('已提取 ' + IPX.list.length + ' 条' +
        (subnet ? '（按 /24 网段）' : '（单个 IP）'));
    }
  }
  function toggleIpMode() {
    IPX.subnet = !IPX.subnet;
    if (IPX.subnet) $('#ipx-mode').addClass('on'); else $('#ipx-mode').removeClass('on');
    $('#ipx-mode-txt').text(IPX.subnet ? '封禁整个网段 x.x.x.0-x.x.x.255' : '仅封禁单个 IP');
    ipxExtract();
  }
  function copyIps() {
    if (!IPX.list.length) return toast('请先粘贴含 IP 的内容');
    var out = document.getElementById('ipx-out');
    out.focus(); out.select();
    var ok = false;
    try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
    if (ok) return toast('已复制 ' + IPX.list.length + ' 条');
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(IPX.list.join('\n')).then(function () {
        toast('已复制 ' + IPX.list.length + ' 条');
      }, function () { toast('复制失败，请手动选择后复制'); });
    } else toast('复制失败，请手动选择后复制');
  }
  function banIps() {
    if (!IPX.list.length) return toast('请先粘贴含 IP 的内容', true);
    var ttl = $('#ipx-ttl').val() || 0;
    var ttlTxt = ttl === '0' ? '永久' : (ttl === '168' ? '7 天' : ttl + ' 小时');
    if (!confirm('确认将 ' + IPX.list.length + ' 条 IP（段）加入黑名单？封禁时长：' + ttlTxt)) return;
    api('BatchAddIpBlack', { patterns: IPX.list.join('\n'), ttl_hours: ttl }, function (r) {
      if (!r.status) { toast(r.msg || '封禁失败', true); return; }
      toast(r.msg || '已封禁');
      closeModal();
      loadIps(1);
    });
  }

  /* ---------- 限速 ---------- */
  function loadLimits() {
    api('GetSettings', {}, function (r) {
      if (!r.status) return;
      var s = r.data;
      $('#limit-box').html(
        '<div class="grid2"><div>' +
        '<div class="sec" style="margin-top:0">CC 防护</div>' +
        '<div class="kv"><div class="k">阈值</div><div><input id="cc-limit" value="' + s.cc.limit + '" style="width:80px"> 次 / ' +
        '<input id="cc-time" value="' + s.cc.time + '" style="width:70px"> 秒</div>' +
        '<div class="k">超限处理</div><div>返回 429，封禁 <input id="cc-deny" value="' + s.cc.deny +
        '" style="width:80px"> 秒 <span class="muted">（Nginx limit_req，作用于单 IP）</span></div></div>' +
        '</div><div>' +
        '<div class="sec" style="margin-top:0">全局限速</div>' +
        '<div class="kv"><div class="k">速率</div><div><input id="lr-rate" value="' + s.limit_req.rate + '" style="width:90px"> ' +
        '<span class="muted">格式 20r/s</span></div>' +
        '<div class="k">突发</div><div><input id="lr-burst" value="' + s.limit_req.burst + '" style="width:80px"></div>' +
        '<div class="k">单 IP 并发</div><div><input id="lr-conn" value="' + s.limit_req.conn + '" style="width:80px"></div></div>' +
        '</div></div>' +
        '<div class="sec">限速豁免（避免误伤正常流量）</div>' +
        '<label class="inline"><input type="checkbox" id="lr-skip-static" style="width:auto"' +
        ((s.limit_req.skip_static === false) ? '' : ' checked') + '> 静态资源不计入限速（js/css/图片/字体/音视频/压缩包）</label>' +
        '<div class="muted" style="margin:8px 0 4px">自定义豁免 URL 正则（每行一条，命中则不计入限速与并发；例如 ^/api/health）</div>' +
        '<textarea id="lr-skip-paths" rows="3" style="width:100%;font:12.5px/1.6 Consolas,Monaco,monospace" placeholder="^/api/health$">' +
        esc(((s.limit_req.skip_paths) || []).join('\n')) + '</textarea>' +
        '<div class="hint" style="margin-top:8px">实现方式：Nginx map 将命中项映射为空 key，' +
        '空 key 的请求不参与 limit_req / limit_conn 计数（不影响拦截规则）。</div>' +
        '<div class="toolbar" style="margin-top:8px"><button class="btn primary" onclick="BFW.saveLimits()">保存并下发</button>' +
        '<span class="muted" id="limit-msg"></span></div>');
    });
  }
  function saveLimits() {
    var skipPaths = ($('#lr-skip-paths').val() || '').split('\n').map(function (x) {
      return $.trim(x);
    }).filter(function (x) { return x; });
    api('SaveSettings', { settings: JSON.stringify({
      cc: { enable: true, limit: +$('#cc-limit').val(), time: +$('#cc-time').val(), deny: +$('#cc-deny').val() },
      limit_req: {
        rate: $.trim($('#lr-rate').val()), burst: +$('#lr-burst').val(), conn: +$('#lr-conn').val(),
        skip_static: $('#lr-skip-static').prop('checked'), skip_paths: skipPaths
      }
    }) }, function (r) {
      toast(r.msg || (r.status ? '已保存并下发' : '保存失败'), !r.status);
      if (r.status) $('#limit-msg').text('已下发 ' + new Date().toLocaleTimeString());
    });
  }

  /* ---------- 日志 ---------- */
  function logFilter() {
    var f = {
      rule_type: $('#lg-type').val() || '',
      level: $('#lg-level').val() || '',
      keyword: $.trim($('#lg-kw').val() || ''),
      ip: $.trim($('#lg-ip').val() || '')
    };
    var s = $('#lg-start').val(), e = $('#lg-end').val();
    if (s) f.start = Math.floor(new Date(s).getTime() / 1000);
    if (e) f.end = Math.floor(new Date(e).getTime() / 1000);
    return f;
  }
  function loadLogs(page) {
    PAGE.page = page || 1;
    PAGE.limit = +($('#lg-size').val() || 20);
    var f = logFilter();
    f.page = PAGE.page; f.limit = PAGE.limit;
    api('GetLogs', f, function (r) {
      if (!r.status) { $('#lg-table').html('<div class="empty">加载失败: ' + esc(r.msg || '') + '</div>'); return; }
      PAGE.total = r.data.total;
      PAGE.rows = r.data.rows || [];
      $('#lg-updated').text('共 ' + PAGE.total + ' 条 · 数据更新于 ' + new Date().toLocaleTimeString());
      if (!PAGE.rows.length) { $('#lg-table').html('<div class="empty">没有匹配的攻击日志</div>'); return; }
      var h = '<table><tr><th>时间</th><th>IP</th><th>类型</th><th>规则</th><th>URI</th><th>级别</th><th>动作</th><th>操作</th></tr>';
      PAGE.rows.forEach(function (x) {
        h += '<tr><td style="white-space:nowrap">' + (x.time_str || fmtTime(x.ts)) + '</td><td>' + esc(x.ip) + '</td>' +
          '<td><span class="tag info">' + (RULE_NAMES[x.rule_type] || x.rule_type) + '</span></td>' +
          '<td>' + esc(x.rule) + (x.fp ? ' <span class="tag warn">误报</span>' : '') + '</td>' +
          '<td style="max-width:300px"><code>' + esc(x.uri) + '</code></td>' +
          '<td><span class="tag ' + esc(x.level) + '">' + esc(x.level) + '</span></td>' +
          '<td>' + (x.action === 'log' ? '<span class="tag gray">仅记录</span>' : '<span class="tag high">拦截</span>') + '</td>' +
          '<td style="white-space:nowrap"><button class="btn sm" onclick="BFW.showLogDetail(' + x.id + ')">详情</button>' +
          (x.fp
            ? '<button class="btn sm plain" onclick="BFW.undoMarkFp(' + x.id + ')">撤销误报</button>'
            : '<button class="btn sm warn" onclick="BFW.markFp(' + x.id + ')">标记误报</button>') +
          '<button class="btn sm err" onclick="BFW.blockIp(\'' + jsq(x.ip) + '\')">封IP</button></td></tr>';
      });
      h += '</table><div class="pager">' + pagerHtml(PAGE.page, Math.ceil(PAGE.total / PAGE.limit), 'BFW.logPage') + '</div>';
      $('#lg-table').html(h);
    });
  }
  function pagerHtml(page, maxPage, fn, total) {
    maxPage = Math.max(1, maxPage);
    var out = '<span class="muted">第 ' + page + ' / ' + maxPage + ' 页，共 ' +
      (total == null ? (PAGE.total || 0) : total) + ' 条</span> ';
    out += '<button ' + (page <= 1 ? 'disabled' : '') + ' onclick="' + fn + '(' + (page - 1) + ')">上一页</button>';
    var from = Math.max(1, page - 2), to = Math.min(maxPage, from + 4);
    from = Math.max(1, to - 4);
    for (var i = from; i <= to; i++) {
      out += '<button class="' + (i === page ? 'on' : '') + '" onclick="' + fn + '(' + i + ')">' + i + '</button>';
    }
    out += '<button ' + (page >= maxPage ? 'disabled' : '') + ' onclick="' + fn + '(' + (page + 1) + ')">下一页</button>';
    return out;
  }
  function resetLogFilter() {
    $('#lg-type').val(''); $('#lg-level').val(''); $('#lg-kw').val(''); $('#lg-ip').val('');
    $('#lg-start').val(''); $('#lg-end').val('');
    loadLogs(1);
  }
  function showLogDetail(id) {
    var x = null;
    (PAGE.rows || []).forEach(function (r) { if (r.id === id) x = r; });
    if (!x) return toast('记录已失效，请刷新列表', true);
    var kv = function (k, v) { return '<div class="k">' + k + '</div><div>' + v + '</div>'; };
    var html = '<div class="kv">' +
      kv('时间', esc(x.time_str || fmtTime(x.ts))) +
      kv('来源 IP', '<b>' + esc(x.ip) + '</b>') +
      kv('类型', (RULE_NAMES[x.rule_type] || x.rule_type)) +
      kv('命中规则', esc(x.rule)) +
      kv('级别', '<span class="tag ' + esc(x.level) + '">' + esc(x.level) + '</span>') +
      kv('动作', x.action === 'log' ? '仅记录' : '拦截') +
      kv('误报', x.fp ? '<span class="tag warn">已标记误报</span>' : '未标记') +
      kv('站点', esc(x.site || '-')) +
      kv('方法', esc(x.method || '-')) +
      '</div><div class="sec">URI</div><pre class="code">' + esc(x.uri) + '</pre>' +
      '<div class="sec">User-Agent</div><pre class="code">' + esc(x.ua || '(空)') + '</pre>' +
      '<div class="sec">Referer</div><pre class="code">' + esc(x.referer || '(空)') + '</pre>' +
      '<div class="sec">命中内容</div><pre class="code">' + esc((x.payload || '').slice(0, 2000)) + '</pre>';
    openDrawer('攻击详情 #' + id, html);
  }
  function markFp(id) {
    api('MarkFalsePositive', { id: id }, function (r) {
      toast(r.msg || (r.status ? '已标记误报' : '操作失败'), !r.status);
      if (r.status) { loadLogs(PAGE.page); loadRecent(); }
    });
  }
  function undoMarkFp(id) {
    api('UnmarkFalsePositive', { id: id }, function (r) {
      toast(r.msg || (r.status ? '已撤销' : '操作失败'), !r.status);
      if (r.status) loadLogs(PAGE.page);
    });
  }
  function blockIp(ip) {
    openModal('<h4>封禁 ' + esc(ip) + '</h4>' +
      '<p class="muted" style="margin:6px 0 0">加入 IP 黑名单后会立即下发并 reload Web 服务；临时封禁到期由计划任务自动解除。</p>' +
      '<label>封禁时长</label><select id="blk-ttl">' +
      '<option value="24">24 小时</option><option value="0">永久</option>' +
      '<option value="1">1 小时</option><option value="168">7 天</option></select>' +
      '<label>备注</label><input id="blk-note" placeholder="如: 攻击日志页手动封禁">' +
      '<p><button class="btn primary" onclick="BFW.doBlockIp(\'' + jsq(ip) + '\')">确认封禁</button>' +
      ' <button class="btn" onclick="BFW.closeModal()">取消</button></p>');
  }
  function doBlockIp(ip) {
    var ttl = $('#blk-ttl').val() || 0;
    var note = $.trim($('#blk-note').val() || '') || ('日志封禁: ' + ip);
    api('AddRule', {
      rule_type: 'ip_black', name: note, note: note, pattern: ip,
      level: 'high', mode: 'block', ttl_hours: ttl
    }, function (r) {
      toast(r.msg || (r.status ? '已封禁' : '封禁失败'), !r.status);
      if (r.status) { closeModal(); loadIps(1); }
    });
  }
  function exportLogs(fmt) {
    var f = logFilter(); f.fmt = fmt || 'csv';
    api('ExportLogs', f, function (r) {
      if (!r.status) return toast(r.msg || '导出失败', true);
      var d = r.data || {};
      if (d.content && downloadText(d.filename, d.content, d.mime)) toast('已导出 ' + (f.keyword ? '当前筛选结果' : '日志'));
      else toast('文件已生成: ' + (d.path || ''));
    });
  }
  function analyzeNow() {
    toast('正在分析访问日志，请稍候…');
    api('TriggerAnalyze', {}, function (r) {
      toast(r.msg || (r.status ? '完成' : '分析失败'), !r.status);
      if (r.status) { loadStatusBar(); if ($('.nav-item.on').data('p') === 'p-logs') loadLogs(1); }
    });
  }
  function clearLogs() {
    var n = PAGE.total || 0;
    if (!confirm('将清空全部攻击日志' + (n ? '（当前 ' + n + ' 条）' : '') +
      '，该操作不可恢复，建议先导出。确认继续？')) return;
    api('ClearLogs', {}, function (r) { toast(r.msg || '已清理', !r.status); loadLogs(1); loadStatusBar(); });
  }

  /* ---------- 统计 ---------- */
  var STATS = null;

  function svgEsc(s) { return esc(s); }

  function trendSvg(trend) {
    var W = 720, H = 240, L = 48, R = 16, T = 18, B = 34;
    var n = (trend || []).length;
    if (!n) return '';
    var max = 1;
    trend.forEach(function (x) { max = Math.max(max, +x.c || 0); });
    var innerW = W - L - R, innerH = H - T - B;
    var stepX = n > 1 ? innerW / (n - 1) : 0;
    var px = function (i) { return L + (n > 1 ? i * stepX : innerW / 2); };
    var py = function (v) { return T + innerH * (1 - (v / max)); };
    var s = '<svg id="st-trend-svg" viewBox="0 0 ' + W + ' ' + H + '" width="100%" height="' + H +
      '" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit">';
    s += '<rect x="0" y="0" width="' + W + '" height="' + H + '" fill="#fff"/>';
    // 网格与 Y 轴刻度
    [0, 0.25, 0.5, 0.75, 1].forEach(function (r) {
      var v = Math.round(max * r), y = py(v);
      s += '<line x1="' + L + '" y1="' + y + '" x2="' + (W - R) + '" y2="' + y +
        '" stroke="#eef1f4" stroke-width="1"/>';
      s += '<text x="' + (L - 8) + '" y="' + (y + 4) + '" font-size="11" fill="#999" text-anchor="end">' + v + '</text>';
    });
    // 面积 + 折线
    var pts = trend.map(function (x, i) { return px(i) + ',' + py(+x.c || 0); });
    if (n > 1) {
      s += '<path d="M' + px(0) + ',' + py(0) + ' L' + pts.join(' L') +
        ' L' + px(n - 1) + ',' + py(0) + ' Z" fill="#20a53a" opacity="0.10"/>';
      s += '<polyline points="' + pts.join(' ') + '" fill="none" stroke="#20a53a" stroke-width="2"/>';
    } else {
      // 只有一天数据时画柱形, 否则只有一个孤点看不出量级
      var v0 = +trend[0].c || 0;
      s += '<rect x="' + (px(0) - 22) + '" y="' + py(v0) + '" width="44" height="' +
        Math.max(2, py(0) - py(v0)) + '" rx="3" fill="#20a53a" opacity="0.85">' +
        '<title>' + svgEsc(trend[0].d) + '：' + v0 + ' 次</title></rect>';
    }
    trend.forEach(function (x, i) {
      var cx = px(i), cy = py(+x.c || 0);
      s += '<circle cx="' + cx + '" cy="' + cy + '" r="3.5" fill="#fff" stroke="#20a53a" stroke-width="2">' +
        '<title>' + svgEsc(x.d) + '：' + (+x.c || 0) + ' 次</title></circle>';
    });
    // X 轴标签: 最多 7 个
    var every = Math.max(1, Math.ceil(n / 7));
    trend.forEach(function (x, i) {
      if (i % every !== 0 && i !== n - 1) return;
      s += '<text x="' + px(i) + '" y="' + (H - 12) + '" font-size="11" fill="#999" text-anchor="middle">' +
        svgEsc(String(x.d || '').slice(5)) + '</text>';
    });
    s += '<line x1="' + L + '" y1="' + (H - B) + '" x2="' + (W - R) + '" y2="' + (H - B) +
      '" stroke="#dfe4e8" stroke-width="1"/>';
    s += '</svg>';
    return s;
  }

  function typesSvg(types, total) {
    var W = 720, rowH = 26, H = 12 + (types || []).length * rowH;
    var max = 1;
    (types || []).forEach(function (x) { max = Math.max(max, +x.c || 0); });
    var s = '<svg id="st-types-svg" viewBox="0 0 ' + W + ' ' + H + '" width="100%" height="' + H +
      '" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit">';
    s += '<rect x="0" y="0" width="' + W + '" height="' + H + '" fill="#fff"/>';
    (types || []).forEach(function (x, i) {
      var y = 6 + i * rowH, name = RULE_NAMES[x.t] || x.t;
      var c = +x.c || 0, pct = total ? (c * 100 / total).toFixed(1) : '0';
      var bw = Math.max(2, Math.round((c / max) * 440));
      s += '<text x="0" y="' + (y + 13) + '" font-size="12" fill="#333">' + svgEsc(name) + '</text>';
      s += '<rect x="110" y="' + y + '" width="' + bw + '" height="14" rx="3" fill="#ff9900" opacity="0.85">' +
        '<title>' + svgEsc(name) + '：' + c + ' 次（' + pct + '%）</title></rect>';
      s += '<text x="' + (112 + bw) + '" y="' + (y + 12) + '" font-size="11" fill="#666">' + c + '（' + pct + '%）</text>';
    });
    s += '</svg>';
    return s;
  }

  function loadStats() {
    api('GetStats', { days: $('#st-days').val() }, function (r) {
      if (!r.status) return;
      var d = r.data;
      STATS = d;
      var sumTypes = 0;
      (d.types || []).forEach(function (x) { sumTypes += x.c; });
      $('#st-cards').html(
        card('总记录', '<span class="v err">' + d.total + '</span>', '近' + d.days + '天') +
        card('拦截生效', '<span class="v">' + (d.blocked || 0) + '</span>', '动作为拦截') +
        card('误报率', '<span class="v ' + ((d.fp_rate || 0) > 0.15 ? 'warn' : '') + '">' +
          ((d.fp_rate || 0) * 100).toFixed(1) + '%</span>', (d.fp || 0) + ' 条已标记') +
        card('今日拦截', '<span class="v">' + (d.today_blocked || 0) + '</span>', '自然日') +
        card('攻击类型', '<span class="v">' + (d.types || []).length + '</span>', '共 ' + sumTypes + ' 次命中') +
        card('Top 攻击 IP', '<span class="v">' + (d.top_ips || []).length + '</span>', '展示前 10'));
      $('#st-trend').html((d.trend || []).length ? trendSvg(d.trend) : '<div class="empty">暂无数据</div>');
      $('#st-types').html((d.types || []).length ? typesSvg(d.types, sumTypes) : '<div class="empty">暂无数据</div>');
      if (!(d.top_ips || []).length) { $('#st-ips').html('<div class="empty">暂无数据</div>'); return; }
      var ip = '<table><tr><th>IP</th><th>攻击次数</th><th>占比</th><th>操作</th></tr>';
      var topSum = 0;
      d.top_ips.forEach(function (x) { topSum += x.c; });
      d.top_ips.forEach(function (x) {
        var pct = d.total ? (x.c * 100 / d.total).toFixed(1) : '0';
        ip += '<tr><td>' + esc(x.ip) + '</td><td>' + x.c + '</td><td class="muted">' + pct + '%</td>' +
          '<td><button class="btn sm err" onclick="BFW.blockIp(\'' + jsq(x.ip) + '\')">封禁</button></td></tr>';
      });
      $('#st-ips').html(ip + '</table>');
    });
  }

  function exportStats(fmt) {
    api('ExportStats', { days: $('#st-days').val(), fmt: fmt || 'csv' }, function (r) {
      if (!r.status) return toast(r.msg || '导出失败', true);
      var d = r.data || {};
      if (d.content && downloadText(d.filename, d.content, d.mime)) toast('统计已导出');
      else toast('已生成: ' + (d.path || ''));
    });
  }

  function exportStatsPng() {
    var t = document.getElementById('st-trend-svg'), y = document.getElementById('st-types-svg');
    if (!t && !y) return toast('当前没有可导出的图表', true);
    var W = 900, pad = 24;
    var h1 = t ? 260 : 0, h2 = y ? Math.round(parseFloat(y.getAttribute('height')) || 200) : 0;
    var H = h1 + h2 + 80;
    var scale = 2;
    var cv = document.createElement('canvas');
    cv.width = W * scale; cv.height = H * scale;
    var ctx = cv.getContext('2d');
    ctx.scale(scale, scale);
    ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, W, H);
    ctx.fillStyle = '#333'; ctx.font = 'bold 18px "Microsoft YaHei",sans-serif';
    ctx.fillText('司南防火墙 攻击统计（近 ' + ((STATS && STATS.days) || '') + ' 天）', pad, 30);
    ctx.fillStyle = '#888'; ctx.font = '12px "Microsoft YaHei",sans-serif';
    ctx.fillText('生成时间 ' + new Date().toLocaleString() + ' · 总记录 ' + ((STATS && STATS.total) || 0) +
      ' 条 · 拦截 ' + ((STATS && STATS.blocked) || 0) + ' 条', pad, 50);
    var draw = function (el, top, height, cb) {
      if (!el || height <= 0) return cb();
      var str = new XMLSerializer().serializeToString(el);
      var svg = new Blob([str], { type: 'image/svg+xml;charset=utf-8' });
      var url = URL.createObjectURL(svg);
      var img = new Image();
      img.onload = function () {
        ctx.drawImage(img, pad, top, W - pad * 2, height);
        URL.revokeObjectURL(url); cb();
      };
      img.onerror = function () { URL.revokeObjectURL(url); cb(); };
      img.src = url;
    };
    draw(t, 64, h1, function () {
      draw(y, 64 + h1, h2, function () {
        cv.toBlob(function (blob) {
          if (!blob) return toast('导出图片失败', true);
          var a = document.createElement('a');
          a.href = URL.createObjectURL(blob);
          a.download = 'sinanwaf_stats_' + new Date().toISOString().slice(0, 10) + '.png';
          document.body.appendChild(a); a.click();
          setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 200);
          toast('图片已导出');
        }, 'image/png');
      });
    });
  }

  /* ---------- 智能优化 ---------- */
  function loadAi() {
    api('GetSettings', {}, function (r) {
      if (!r.status) return;
      $('#ai-auto').prop('checked', r.data.auto_apply === 'auto');
      setOn($('#ai-learn'), 'on', !!r.data.auto_learn);
      if (!r.data.auto_learn) {
        $('#ai-feats').html('<div class="hint warn">自学习已关闭，后台计划任务不会修改规则。开启后每 10 分钟自动执行一次分析。</div>');
      }
    });
    api('GetAnalysis', {}, function (r) {
      if (!r.status) return;
      var d = r.data || {};
      if (d.empty) { $('#ai-feats').html('<div class="empty">暂无攻击数据，等待日志分析</div>'); return; }
      var strong = d.strong_attackers || [];
      var h = '<p class="muted">近7天样本 ' + d.total + ' 条，高置信攻击者 ' + strong.length + ' 个</p>';
      if (!strong.length) {
        h += '<div class="empty">暂无满足条件的强攻击者（≥10次且覆盖多类型）</div>';
      } else {
        h += '<table><tr><th>IP</th><th>命中</th><th>攻击类型</th><th>置信度</th><th>操作</th></tr>';
        strong.slice(0, 8).forEach(function (x) {
          var types = (x.types || []).map(function (t) { return RULE_NAMES[t] || t; }).join('、');
          h += '<tr><td>' + esc(x.ip) + '</td><td>' + x.hits + '</td><td class="muted">' + esc(types) + '</td>' +
            '<td>' + x.confidence + '</td><td><button class="btn sm err" onclick="BFW.blockIp(\'' + esc(x.ip) + '\')">封禁</button></td></tr>';
        });
        h += '</table>';
      }
      if ((d.tool_uas || []).length) {
        h += '<p class="muted">工具UA指纹: ' + esc(d.tool_uas.slice(0, 4).join(' | ').slice(0, 160)) + '</p>';
      }
      $('#ai-feats').html(h);
    });
    api('GetRuleEvaluation', {}, function (r) {
      if (!r.status) return;
      var ev = r.data;
      var h = '<p class="muted">近' + (ev.window_days || 7) + '天全局误报率: <b style="color:' +
        (ev.fp_rate > 0.15 ? '#e54545' : '#20a53a') + '">' + (ev.fp_rate * 100).toFixed(2) + '%</b>' +
        '（阈值 15%，样本 ' + ev.all_total + ' 条），按滚动窗口统计</p>' +
        '<div class="table-wrap"><table><tr><th>规则</th><th>类型</th><th>命中</th><th>误报率</th><th>状态</th></tr>';
      (ev.rules || []).slice(0, 15).forEach(function (x) {
        h += '<tr><td>' + esc(x.name) + '</td><td>' + (RULE_NAMES[x.type] || x.type) + '</td><td>' + x.hits + '</td>' +
          '<td>' + (x.fp_rate * 100).toFixed(1) + '%' + (x.fp_rate > 0.15 ? ' <span class="tag warn">自动降级</span>' : '') + '</td>' +
          '<td>' + (x.on ? '启用' : '休眠') + '/' + (x.mode === 'block' ? '拦截' : '记录') + '</td></tr>';
      });
      $('#ai-eval').html(h + '</table></div>');
    });
    api('GetPendingRules', {}, function (r) {
      var p = (r && r.data) || [];
      setOn($('#badge-ai'), 'hide', !p.length).text(p.length);
      if (!p.length) { $('#ai-pending').html('<div class="empty">暂无待确认规则</div>'); return; }
      var h = '<table><tr><th>类型</th><th>名称</th><th>规则</th><th>依据</th><th>操作</th></tr>';
      p.forEach(function (x) {
        h += '<tr><td>' + (RULE_NAMES[x.type] || x.type) + '</td><td>' + esc(x.name) + '</td>' +
          '<td><code>' + esc(x.pattern) + '</code></td><td class="muted">' + esc(x.reason) + '</td>' +
          '<td><button class="btn sm primary" onclick="BFW.approve(\'' + jsq(x.pattern) + '\',1)">采纳</button>' +
          '<button class="btn sm plain" onclick="BFW.approve(\'' + jsq(x.pattern) + '\',0)">忽略</button></td></tr>';
      });
      $('#ai-pending').html(h + '</table>');
    });
    api('GetLearnHistory', {}, function (r) {
      var rows = (r && r.data) || [];
      if (!rows.length) { $('#ai-history').html('<div class="empty">暂无学习记录</div>'); return; }
      var h = '<table><tr><th>时间</th><th>阶段</th><th>详情</th></tr>';
      rows.slice(0, 12).forEach(function (x) {
        var detail = x.detail;
        var txt = '';
        if (typeof detail === 'string') txt = detail;
        else if (detail && typeof detail === 'object') {
          if (detail.generated !== undefined) txt = '生成规则 ' + detail.generated + ' 条，优化 ' + ((detail.optimized || {}).changed || 0) + ' 条';
          else if (detail.rolled_back) txt = '自动回滚至版本 #' + detail.to;
          else txt = JSON.stringify(detail);
        }
        h += '<tr><td style="white-space:nowrap">' + (x.time_str || fmtTime(x.ts)) + '</td><td>' + esc(x.stage) +
          '</td><td class="muted" title="' + esc(JSON.stringify(detail)) + '">' + esc(String(txt).slice(0, 160)) + '</td></tr>';
      });
      $('#ai-history').html(h + '</table>');
    });
  }
  function runAnalysis() {
    var btn = $('#ai-run');
    btn.prop('disabled', true).html('<span class="loading"></span>分析中…');
    api('RunAnalysis', {}, function (r) {
      btn.prop('disabled', false).text('立即执行分析');
      if (!r.status) { toast(r.msg || '分析失败', true); return; }
      var d = r.data || {};
      if (d.skip) { toast('未执行：' + d.skip, true); return; }
      toast('分析完成：生成规则 ' + (d.generated || 0) + ' 条，优化 ' + ((d.optimized || {}).changed || 0) + ' 条' +
        (d.rollback ? '，已自动回滚' : ''));
      loadAi(); loadStatusBar();
    });
  }
  function approve(pat, ok) {
    api('ApprovePending', { pattern: pat, approve: ok }, function (r) {
      toast(r.msg || (r.status ? '已处理' : '处理失败'), !r.status);
      if (r.status) loadAi();
    });
  }
  function rollbackRules() {
    if (!confirm('回滚规则至上一稳定版本？当前规则会先自动备份。')) return;
    api('RollbackRules', {}, function (r) { toast(r.msg || (r.status ? '已回滚' : '回滚失败'), !r.status); });
  }
  function toggleAutoLearn() {
    var next = !$('#ai-learn').hasClass('on');
    api('SetAutoLearn', { on: next ? '1' : '0' }, function (r) {
      toast(r.msg || '已更新', !r.status);
      if (r.status) { setOn($('#ai-learn'), 'on', next); loadAi(); }
    });
  }
  function saveAiAuto(on) {
    if (on && !confirm('开启后，高置信度规则会自动入库（可能包含自动封禁 IP）。确认开启？')) {
      $('#ai-auto').prop('checked', false); return;
    }
    api('SaveSettings', { settings: JSON.stringify({ auto_apply: on ? 'auto' : 'confirm' }) },
      function (r) { toast(r.msg || (r.status ? '已保存' : '保存失败'), !r.status); });
  }

  /* ---------- 系统 ---------- */
  function exportRules() {
    api('ExportRules', {}, function (r) {
      if (!r.status) return;
      var d = r.data || {};
      if (d.content && downloadText(d.filename, d.content, d.mime)) toast('规则已导出');
      else toast('已导出: ' + d.path);
    });
  }
  function showImport() {
    openModal('<h4>导入规则</h4><label>粘贴规则JSON（支持插件导出格式）</label>' +
      '<textarea id="imp-data" rows="10" style="width:100%"></textarea>' +
      '<label>导入方式 <select id="imp-mode"><option value="merge">合并(跳过重复)</option><option value="cover">覆盖</option></select></label>' +
      '<p><button class="btn primary" onclick="BFW.doImport()">导入</button> <button class="btn" onclick="BFW.closeModal()">取消</button></p>');
  }
  function doImport() {
    var data = $.trim($('#imp-data').val() || '');
    if (!data) return toast('请粘贴规则 JSON', true);
    if ($('#imp-mode').val() === 'cover' && !confirm('覆盖模式会用导入内容替换现有全部规则（自动先备份），确认继续？')) return;
    api('ImportRules', { data: data, mode: $('#imp-mode').val() },
      function (r) { toast(r.msg || (r.status ? '导入成功' : '导入失败'), !r.status); if (r.status) closeModal(); });
  }
  function createBackup() {
    api('CreateBackup', {}, function (r) { toast(r.msg || '已创建', !r.status); if (r.status) loadBackups(); });
  }
  function loadBackups() {
    api('GetBackups', {}, function (r) {
      if (!r.status) return;
      var vs = r.data.versions || [];
      var h = '<table><tr><th>版本ID</th><th>时间</th><th>标签</th><th>说明</th><th>操作</th></tr>';
      if (!vs.length) h += '<tr><td colspan="5" class="empty">暂无快照</td></tr>';
      vs.forEach(function (v) {
        h += '<tr><td>#' + v.id + '</td><td style="white-space:nowrap">' + new Date(v.ts * 1000).toLocaleString() + '</td>' +
          '<td><span class="tag ' + (v.tag === 'stable' ? 'ok' : 'gray') + '">' + esc(v.tag) + '</span></td>' +
          '<td class="muted">' + esc(v.summary) + '</td>' +
          '<td><button class="btn sm" onclick="BFW.restore(' + v.id + ')">恢复</button>' +
          '<button class="btn sm err" onclick="BFW.delBackupVersion(' + v.id + ')">删除</button></td></tr>';
      });
      $('#bk-table').html(h + '</table>');
      var files = r.data.files || [];
      if (!files.length) { $('#bk-files').html('<div class="empty">暂无导出文件备份</div>'); return; }
      var f = '<table><tr><th>文件名</th><th>时间</th><th>操作</th></tr>';
      files.forEach(function (x) {
        f += '<tr><td><code>' + esc(x.file) + '</code></td><td class="muted">' + esc(x.time) + '</td>' +
          '<td><button class="btn sm" onclick="BFW.downloadBackup(\'' + jsq(x.file) + '\')">下载</button>' +
          '<button class="btn sm" onclick="BFW.restoreFromFile(\'' + jsq(x.file) + '\')">恢复</button>' +
          '<button class="btn sm err" onclick="BFW.delBackupFile(\'' + jsq(x.file) + '\')">删除</button></td></tr>';
      });
      $('#bk-files').html(f + '</table>');
    });
  }
  function restore(vid) {
    if (!confirm('恢复到版本 #' + vid + '？当前规则会先自动备份。')) return;
    api('RestoreBackup', { version_id: vid }, function (r) {
      toast(r.msg || (r.status ? '已恢复' : '恢复失败'), !r.status);
      if (r.status) { loadBackups(); loadDeployHint(); }
    });
  }
  function restoreFromFile(file) {
    if (!confirm('从备份文件恢复规则：' + file + '？当前规则会先自动备份。')) return;
    api('RestoreBackup', { file: file }, function (r) {
      toast(r.msg || (r.status ? '已恢复' : '恢复失败'), !r.status);
      if (r.status) { loadBackups(); loadDeployHint(); }
    });
  }
  function downloadBackup(file) {
    api('DownloadBackup', { file: file }, function (r) {
      if (!r.status) return toast(r.msg || '下载失败', true);
      var d = r.data || {};
      if (!downloadText(d.filename, d.content, d.mime)) toast('浏览器不允许下载，请到 backup/ 目录取文件', true);
    });
  }
  function delBackupFile(file) {
    if (!confirm('删除备份文件 ' + file + '？此操作不可恢复。')) return;
    api('DelBackup', { file: file }, function (r) {
      toast(r.msg || (r.status ? '已删除' : '删除失败'), !r.status);
      if (r.status) loadBackups();
    });
  }
  function delBackupVersion(id) {
    if (!confirm('删除快照 #' + id + '？删除后无法再恢复到该版本。')) return;
    api('DelBackup', { version_id: id }, function (r) {
      toast(r.msg || (r.status ? '已删除' : '删除失败'), !r.status);
      if (r.status) loadBackups();
    });
  }
  var CH_TYPE_NAME = { webhook: 'Webhook', dingtalk: '钉钉机器人', wecom: '企业微信', mail: '邮件' };
  var EV_NAME = { attack: '攻击', malware: '木马', rollback: '规则回滚', digest: '防护摘要' };
  var ALERT_CH = [];

  function shortTarget(v) {
    v = String(v || '');
    if (!v) return '-';
    if (v.indexOf('@') > 0 && v.indexOf('://') < 0) return v;
    var m = v.match(/^https?:\/\/([^\/]+)/i);
    return (m ? m[1] : v) + (m ? '/…' : '');
  }
  function detectKind(v) {
    if (/qyapi\.weixin\.qq\.com/i.test(v)) return 'wecom';
    if (/oapi\.dingtalk\.com/i.test(v)) return 'dingtalk';
    if (/^https?:\/\//i.test(v)) return 'webhook';
    if (v.indexOf('@') > 0) return 'mail';
    return '';
  }

  function loadAlertCfg() {
    api('GetAlertConfig', {}, function (r) {
      if (!r.status) {
        $('#alert-box').html('<div class="empty">加载失败: ' + esc(r.msg || '') + '</div>');
        return;
      }
      var c = r.data || {};
      var chs = c.channels || [];
      ALERT_CH = chs;
      var h = '';
      // 1) 最短路径: 粘贴地址即可
      if (!chs.length) {
        h += '<div class="quick-add">' +
          '<input id="qa-url" placeholder="粘贴企业微信/钉钉机器人 Webhook 地址（或收件邮箱）">' +
          '<select id="qa-type"><option value="">自动识别</option><option value="wecom">企业微信</option>' +
          '<option value="dingtalk">钉钉</option><option value="webhook">通用 Webhook</option>' +
          '<option value="mail">邮件</option></select>' +
          '<button class="btn primary" onclick="BFW.quickAddChannel()">添加通道</button>' +
          '</div>' +
          '<div class="step-tip">企业微信：群设置 → 群机器人 → 添加 → 复制 Webhook 地址 → 粘贴到上面即可，添加后会自动发一条测试消息。</div>';
      } else {
        h += '<div class="toolbar" style="margin-bottom:0">' +
          '<button class="btn primary" onclick="BFW.quickAddChannel()">+ 添加通道</button>' +
          '<span class="muted">推荐直接粘贴机器人地址，自动识别类型</span></div>';
      }
      // 2) 通道列表
      if (chs.length) {
        h += '<div class="sec">已配置通道（' + chs.length + '）</div>';
        chs.forEach(function (ch, i) {
          var target = ch.type === 'mail' ? (ch.to || '') : (ch.url || '');
          var evs = ch.events;
          var evTxt = (evs && evs.length) ? evs.map(function (x) { return EV_NAME[x] || x; }).join('、') : '全部事件';
          var on = ch.enable !== false;
          var last = '';
          if (ch.last_ts) {
            last = '最近：' + fmtTime(ch.last_ts) + (ch.last_ok ? ' 成功' : ' 失败');
          }
          h += '<div class="ch-row">' +
            '<span class="switch ' + (on ? 'on' : '') + '" onclick="BFW.toggleChannel(' + i + ',' + (!on) + ')"><i></i></span>' +
            '<div class="ch-main"><b>' + esc(ch.name || CH_TYPE_NAME[ch.type] || ch.type) + '</b> ' +
            '<span class="tag info">' + (CH_TYPE_NAME[ch.type] || esc(ch.type)) + '</span>' +
            (on ? '' : ' <span class="tag gray">已停用</span>') +
            '<div class="muted">' + esc(shortTarget(target)) + ' · 最低级别 ' +
            esc(ch.min_level || '跟随全局') + ' · ' + esc(evTxt) +
            (last ? ' · ' + esc(last) : '') + '</div></div>' +
            '<button class="btn sm" onclick="BFW.testChannel(' + i + ')">测试</button>' +
            '<button class="btn sm plain" onclick="BFW.editChannel(' + i + ')">编辑</button>' +
            '<button class="btn sm err" onclick="BFW.delChannel(' + i + ')">删除</button></div>';
        });
      }
      // 3) 全局策略(改动即保存, 无需点按钮)
      h += '<details class="fold"' + (chs.length ? '' : ' open') + '><summary>全局策略（级别 / 冷却 / 静默，改动即生效）</summary>' +
        '<div class="toolbar">' +
        '<label class="inline">告警开关 <span class="switch ' + (c.enable ? 'on' : '') +
        '" onclick="BFW.alertToggle()"><i></i></span></label>' +
        '<label class="inline">最低级别 <select id="al-level" onchange="BFW.saveAlert()">' +
        ['info', 'warn', 'high', 'critical'].map(function (l) {
          return '<option ' + (c.min_level === l ? 'selected' : '') + '>' + l + '</option>';
        }).join('') + '</select></label>' +
        '<label class="inline">同类冷却 <input id="al-cool" value="' + (c.cooldown || 300) +
        '" style="width:70px" onchange="BFW.saveAlert()"> 秒</label></div>' +
        '<div class="toolbar" style="margin-top:6px">' +
        '<label class="inline">静默时段 <span class="switch ' + ((c.silence || {}).enable ? 'on' : '') +
        '" id="al-silence" onclick="BFW.toggleSilence()"><i></i></span></label>' +
        '<input id="al-silence-start" value="' + esc((c.silence || {}).start || '23:00') +
        '" style="width:76px" placeholder="23:00" onchange="BFW.saveAlert()">' +
        '<span class="muted">至</span>' +
        '<input id="al-silence-end" value="' + esc((c.silence || {}).end || '07:00') +
        '" style="width:76px" placeholder="07:00" onchange="BFW.saveAlert()">' +
        '<span class="muted">期间不发送非强制告警（攻击高峰等仍发送）</span></div>' +
        '<div class="step-tip">告警来源：木马检出、攻击高峰（10 分钟 ≥100 次）、规则自动回滚。</div>' +
        '</details>';
      $('#alert-box').html(h);
    });
  }

  function saveAlert() {
    var cfg = {
      min_level: $('#al-level').val(),
      cooldown: +($('#al-cool').val() || 300),
      silence: {
        enable: $('#al-silence').hasClass('on'),
        start: $.trim($('#al-silence-start').val() || '23:00'),
        end: $.trim($('#al-silence-end').val() || '07:00')
      }
    };
    api('SaveAlertConfig', { cfg: JSON.stringify(cfg) }, function (r) {
      toast(r.status ? '已自动保存' : (r.msg || '保存失败'), !r.status);
    });
  }
  function toggleSilence() {
    var el = $('#al-silence');
    if (el.hasClass('on')) el.removeClass('on'); else el.addClass('on');
    saveAlert();
  }
  function alertToggle() {
    api('GetAlertConfig', {}, function (r) {
      var c = r.data || {};
      api('SaveAlertConfig', { cfg: JSON.stringify({ enable: !c.enable }) }, function (rr) {
        toast(rr.msg, !rr.status); loadAlertCfg();
      });
    });
  }

  function switchAlertTab(t) {
    $('#alert-tabs .stab').removeClass('on');
    $('#alert-tabs .stab[data-t="' + t + '"]').addClass('on');
    $('#p-alert .subpanel').removeClass('on');
    $('#' + t).addClass('on');
    if (t === 'al-push' && !PUSH.data) loadPush();
    if (t === 'al-hist') loadAlertHistory(1);
  }
  $(document).on('click', '#alert-tabs .stab', function () {
    switchAlertTab($(this).data('t'));
  });

  function quickAddChannel() {
    if (!$('#qa-url').length) {
      openModal('<h4>添加通道</h4>' +
        '<label>粘贴机器人地址</label><input id="qa-url" placeholder="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=...">' +
        '<label>类型</label><select id="qa-type"><option value="">自动识别</option>' +
        '<option value="wecom">企业微信</option><option value="dingtalk">钉钉</option>' +
        '<option value="webhook">通用 Webhook</option><option value="mail">邮件</option></select>' +
        '<p><button class="btn primary" onclick="BFW.quickAddChannel()">添加通道</button> ' +
        '<button class="btn" onclick="BFW.closeModal()">取消</button></p>');
      return;
    }
    var v = $.trim($('#qa-url').val() || '');
    if (!v) return toast('请粘贴机器人地址或邮箱', true);
    var t = $('#qa-type').val() || detectKind(v);
    if (!t) return toast('无法识别类型，请在下拉中手动选择', true);
    if (t === 'mail') {
      if (v.indexOf('@') < 0) return toast('请填写收件邮箱', true);
      closeModal();
      channelModal({ type: 'mail', to: v }, null);
      return;
    }
    if (!/^https?:\/\//i.test(v)) return toast('地址必须以 http:// 或 https:// 开头', true);
    var ch = { type: t, name: CH_TYPE_NAME[t] || 'Webhook', url: v, enable: true };
    if (t === 'mail') ch.to = v;
    api('GetAlertConfig', {}, function (r) {
      var c = r.data || {}; c.channels = c.channels || [];
      c.channels.push(ch);
      var idx = c.channels.length - 1;
      api('SaveAlertConfig', { cfg: JSON.stringify({ channels: c.channels }) }, function (rr) {
        if (!rr.status) return toast(rr.msg || '添加失败', true);
        closeModal();
        toast('已添加，正在发送测试消息…');
        loadAlertCfg();
        api('TestAlert', { index: idx }, function (t2) {
          toast(t2.msg || (t2.status ? '测试发送成功' : '测试发送失败'), !t2.status);
          loadAlertCfg();
        });
      });
    });
  }

  function toggleChannel(i, on) {
    api('GetAlertConfig', {}, function (r) {
      var c = r.data || {}; c.channels = c.channels || [];
      if (!c.channels[i]) return;
      c.channels[i].enable = !!on;
      api('SaveAlertConfig', { cfg: JSON.stringify({ channels: c.channels }) }, function (rr) {
        toast(rr.status ? (on ? '通道已启用' : '通道已停用') : (rr.msg || '操作失败'), !rr.status);
        loadAlertCfg();
      });
    });
  }
  function testChannel(i) {
    toast('正在发送测试消息…');
    api('TestAlert', { index: i }, function (r) {
      toast(r.msg || (r.status ? '测试发送成功' : '发送失败'), !r.status);
      loadAlertCfg();
    });
  }

  function channelModal(ch, idx) {
    ch = ch || {};
    var isEdit = typeof idx === 'number';
    var t = ch.type || 'webhook';
    var evs = ch.events;
    var checked = function (k) {
      return (!evs || !evs.length || evs.indexOf(k) >= 0) ? ' checked' : '';
    };
    var lv = ch.min_level || '';
    var h = '<h4>' + (isEdit ? '编辑通道' : '添加通道') + '</h4>' +
      '<label>类型</label><select id="ch-type" onchange="BFW.chTypeChange()">' +
      ['webhook', 'wecom', 'dingtalk', 'mail'].map(function (k) {
        return '<option value="' + k + '"' + (t === k ? ' selected' : '') + '>' + CH_TYPE_NAME[k] + '</option>';
      }).join('') + '</select>' +
      '<label>名称（可选）</label><input id="ch-name" value="' + esc(ch.name || '') + '" placeholder="如: 运维群">' +
      '<label>最低级别</label><select id="ch-level">' +
      ['', 'info', 'warn', 'high', 'critical'].map(function (l) {
        return '<option value="' + l + '"' + (lv === l ? ' selected' : '') + '>' +
          (l ? l : '跟随全局') + '</option>';
      }).join('') + '</select>' +
      '<label>接收事件（全选＝不过滤）</label><div class="toolbar" style="margin:4px 0 0">' +
      '<label class="inline"><input type="checkbox" id="ch-ev-attack" style="width:auto"' + checked('attack') + '> 攻击</label>' +
      '<label class="inline"><input type="checkbox" id="ch-ev-malware" style="width:auto"' + checked('malware') + '> 木马</label>' +
      '<label class="inline"><input type="checkbox" id="ch-ev-rollback" style="width:auto"' + checked('rollback') + '> 规则回滚</label>' +
      '<label class="inline"><input type="checkbox" id="ch-ev-digest" style="width:auto"' + checked('digest') + '> 防护摘要</label></div>' +
      '<div id="ch-http">' +
      '<label>Webhook / 钉钉 / 企微地址</label><input id="ch-url" value="' + esc(ch.url || '') + '">' +
      '<label>钉钉加签 Secret（可选）</label><input id="ch-secret" value="' + esc(ch.secret || '') + '">' +
      '</div>' +
      '<div id="ch-mail" style="display:none">' +
      '<label>收件人</label><input id="ch-to" value="' + esc(ch.to || '') + '" placeholder="ops@example.com">' +
      '<label>SMTP 服务器</label><input id="ch-smtp" value="' + esc(ch.smtp || '') + '" placeholder="smtp.example.com">' +
      '<label>SMTP 端口</label><input id="ch-port" value="' + (ch.port || 465) + '">' +
      '<label>发件人</label><input id="ch-from" value="' + esc(ch.from || '') + '" placeholder="sinanwaf@example.com">' +
      '<label>账号</label><input id="ch-user" value="' + esc(ch.user || '') + '">' +
      '<label>密码 / 授权码</label><input id="ch-pass" type="password">' +
      '<label class="inline" style="margin-top:8px"><input type="checkbox" id="ch-ssl" style="width:auto"' +
      (ch.ssl === false ? '' : ' checked') + '> 使用 SSL/TLS</label>' +
      '</div>' +
      '<p><button class="btn primary" onclick="BFW.doAddChannel(' + (isEdit ? idx : '') + ')">' +
      (isEdit ? '保存' : '添加') + '</button> <button class="btn" onclick="BFW.closeModal()">取消</button>' +
      (isEdit ? ' <button class="btn warn" onclick="BFW.testChannel(' + idx + ')">先测试</button>' : '') + '</p>';
    openModal(h);
    chTypeChange();
  }
  function addChannel() { channelModal({}, null); }
  function editChannel(i) {
    api('GetAlertConfig', {}, function (r) {
      var chs = (r.data || {}).channels || [];
      if (!chs[i]) return toast('通道不存在', true);
      channelModal(chs[i], i);
    });
  }
  function chTypeChange() {
    var isMail = $('#ch-type').val() === 'mail';
    if (isMail) { $('#ch-mail').show(); $('#ch-http').hide(); }
    else { $('#ch-mail').hide(); $('#ch-http').show(); }
  }
  function doAddChannel(idx) {
    var isEdit = String(idx || '').length > 0;
    var t = $('#ch-type').val();
    var ch = { type: t, name: $.trim($('#ch-name').val() || '') };
    var lv = $('#ch-level').val();
    if (lv) ch.min_level = lv;
    var evs = [];
    if ($('#ch-ev-attack').prop('checked')) evs.push('attack');
    if ($('#ch-ev-malware').prop('checked')) evs.push('malware');
    if ($('#ch-ev-rollback').prop('checked')) evs.push('rollback');
    if ($('#ch-ev-digest').prop('checked')) evs.push('digest');
    if (!evs.length) return toast('至少选择一种接收事件', true);
    if (evs.length < 4) ch.events = evs;
    if (t === 'mail') {
      ch.to = $.trim($('#ch-to').val() || '');
      if (!ch.to) return toast('请填写收件人', true);
      ch.smtp = $.trim($('#ch-smtp').val() || '');
      ch.port = +($('#ch-port').val() || 465);
      ch.from = $.trim($('#ch-from').val() || '');
      ch.user = $.trim($('#ch-user').val() || '');
      ch.password = $('#ch-pass').val() || '';
      ch.ssl = $('#ch-ssl').prop('checked');
    } else {
      ch.url = $.trim($('#ch-url').val() || '');
      if (!ch.url) return toast('请填写通道地址', true);
      ch.secret = $.trim($('#ch-secret').val() || '');
    }
    api('GetAlertConfig', {}, function (r) {
      var c = r.data || {}; c.channels = c.channels || [];
      if (isEdit) {
        var old = c.channels[parseInt(idx, 10)] || {};
        ch.enable = old.enable !== false;
        if (!ch.password && old.password) ch.password = old.password;
        c.channels[parseInt(idx, 10)] = ch;
      } else {
        ch.enable = true;
        c.channels.push(ch);
      }
      api('SaveAlertConfig', { cfg: JSON.stringify({ channels: c.channels }) }, function (rr) {
        toast(rr.status ? (isEdit ? '已保存' : '已添加') : (rr.msg || '保存失败'), !rr.status);
        if (rr.status) { closeModal(); loadAlertCfg(); }
      });
    });
  }
  function delChannel(i) {
    var ch = ALERT_CH[i] || {};
    if (!confirm('删除通道“' + (ch.name || CH_TYPE_NAME[ch.type] || '') + '”？删除后该通道不再接收告警。')) return;
    api('GetAlertConfig', {}, function (r) {
      var c = r.data; c.channels = c.channels || [];
      c.channels.splice(i, 1);
      api('SaveAlertConfig', { cfg: JSON.stringify({ channels: c.channels }) },
        function (rr) { toast(rr.msg, !rr.status); loadAlertCfg(); });
    });
  }
  function testAlert() {
    toast('正在发送测试消息…');
    api('TestAlert', {}, function (r) { toast(r.msg || (r.status ? '测试已发送' : '发送失败'), !r.status); });
  }
  function loadAlertHistory(page) {
    api('GetAlertHistory', { page: page || 1 }, function (r) {
      if (!r.status) return;
      var rows = (r.data && r.data.rows) || [];
      if (!rows.length) { $('#alert-history').html('<div class="empty">暂无告警记录</div>'); return; }
      var h = '<table><tr><th>时间</th><th>通道</th><th>级别</th><th>标题</th><th>结果</th></tr>';
      rows.forEach(function (x) {
        h += '<tr><td style="white-space:nowrap">' + (x.time_str || fmtTime(x.ts)) + '</td><td>' + esc(x.channel) +
          '</td><td><span class="tag ' + (x.level === 'critical' || x.level === 'high' ? 'high' : 'warn') + '">' +
          esc(x.level) + '</span></td><td>' + esc(x.title) + '<div class="muted">' + esc((x.body || '').slice(0, 90)) +
          '</div></td><td>' + (x.ok ? '<span class="tag ok">成功</span>' : '<span class="tag high">失败</span>') +
          '</td></tr>';
      });
      $('#alert-history').html(h + '</table>');
    });
  }
  /* ---------- 状态/威慑推送(Webhook) ---------- */
  var PUSH = { data: null };
  var PUSH_KIND = { wecom: '企业微信机器人', dingtalk: '钉钉机器人', generic: '通用 Webhook' };
  var PUSH_FMT_TIP = {
    markdown: '企微/钉钉内排版美观：标题、引用、加粗、警示色',
    text: '纯文本无任何标记，兼容性最高，适合转发到个人微信'
  };

  function pushPreviewText() {
    if (!PUSH.data) return '';
    var kind = $('#push-pv-kind').length ? $('#push-pv-kind').val() : 'status';
    var fmt = $('#push-pv-fmt').length ? $('#push-pv-fmt').val() : 'markdown';
    var pv = (PUSH.data.preview || {})[kind] || {};
    return pv[fmt] || '';
  }
  function loadPush() {
    api('GetNotifyConfig', {}, function (r) {
      if (!r.status) {
        $('#push-box').html('<div class="empty">加载失败: ' + esc(r.msg || '') + '</div>');
        return;
      }
      PUSH.data = r.data;
      var c = r.data.cfg || {};
      var kinds = ['wecom', 'dingtalk', 'generic'].map(function (k) {
        return '<option value="' + k + '"' + (c.kind === k ? ' selected' : '') + '>' + PUSH_KIND[k] + '</option>';
      }).join('');
      var fmts = ['markdown', 'text'].map(function (f) {
        return '<option value="' + f + '"' + (c.format === f ? ' selected' : '') + '>' +
          (f === 'markdown' ? 'Markdown（企微内查看）' : '纯文本（兼容个人微信）') + '</option>';
      }).join('');
      var h =
        '<div class="quick-add">' +
        '<input id="push-url" value="' + esc(c.url || '') +
        '" placeholder="粘贴企业微信/钉钉机器人 Webhook 地址">' +
        '<select id="push-kind">' + kinds + '</select>' +
        '<select id="push-format">' + fmts + '</select>' +
        '<button class="btn primary" onclick="BFW.savePush()">保存</button>' +
        '<button class="btn" onclick="BFW.testPush()">发送测试</button></div>' +
        '<div class="step-tip"><span id="push-fmt-tip">' + (PUSH_FMT_TIP[c.format] || '') +
        '</span>　最近结果：' + esc(c.last_result || '暂无推送记录') + '</div>' +
        '<details class="fold" open><summary>推送策略（总开关 / 定时状态 / 拦截威慑）</summary>' +
        '<div class="toolbar">' +
        '<label class="inline">启用自动推送 <span class="switch ' + (c.enable ? 'on' : '') +
        '" id="push-enable" onclick="BFW.togglePush(\'enable\')"><i></i></span></label>' +
        '<label class="inline">定时状态 <span class="switch ' + (c.status_enable ? 'on' : '') +
        '" id="push-status" onclick="BFW.togglePush(\'status\')"><i></i></span></label>' +
        '<label class="inline">拦截威慑 <span class="switch ' + (c.deter_enable ? 'on' : '') +
        '" id="push-deter" onclick="BFW.togglePush(\'deter\')"><i></i></span></label>' +
        '<span class="muted">开关改动后点上方「保存」生效</span></div></details>' +
        '<details class="fold"><summary>高级（钉钉加签 / 推送间隔 / 触发阈值）</summary>' +
        '<div class="toolbar">' +
        '<label class="inline">钉钉加签 <input id="push-secret" value="' + esc(c.secret || '') +
        '" style="width:170px" placeholder="仅钉钉需要"></label>' +
        '<label class="inline">状态间隔 <input id="push-interval" value="' + (c.status_interval || 6) +
        '" style="width:60px"> 小时</label>' +
        '<label class="inline">威慑阈值 <input id="push-min" value="' + (c.deter_min || 5) +
        '" style="width:60px"> 条</label>' +
        '<label class="inline">最小间隔 <input id="push-gap" value="' + (c.deter_gap || 60) +
        '" style="width:60px"> 分钟</label></div></details>' +
        '<div class="toolbar" style="margin-top:10px">' +
        '<button class="btn" onclick="BFW.pushNow(\'status\')">立即推送运行状态</button>' +
        '<button class="btn warn" onclick="BFW.pushNow(\'deter\')">立即推送威慑消息</button>' +
        '<span class="muted">定时推送由计划任务每 10 分钟检查一次，按间隔与阈值触发</span></div>' +
        '<div class="sec">消息预览（实际发送内容）</div>' +
        '<div class="toolbar" style="margin-bottom:6px">' +
        '<select id="push-pv-kind"><option value="status">运行状态</option><option value="deter">拦截威慑</option></select>' +
        '<select id="push-pv-fmt"><option value="markdown">Markdown</option><option value="text">纯文本</option></select>' +
        '<button class="btn sm plain" onclick="BFW.previewPush()">生成预览</button>' +
        '<span class="muted">Markdown 适合企微/钉钉内查看；纯文本无标记，可直接转发到个人微信</span></div>' +
        '<pre id="push-preview" style="max-height:320px">' + esc(pushPreviewText()) + '</pre>';
      $('#push-box').html(h);
      $('#push-pv-kind').val('status');
      $('#push-pv-fmt').val(c.format === 'text' ? 'text' : 'markdown');
      $('#push-preview').text(pushPreviewText());
      $('#push-format').change(function () {
        $('#push-fmt-tip').text(PUSH_FMT_TIP[$(this).val()] || '');
      });
      $('#push-pv-kind').change(function () { $('#push-preview').text(pushPreviewText()); });
      $('#push-pv-fmt').change(function () { $('#push-preview').text(pushPreviewText()); });
    });
  }
  function togglePush(which) {
    var id = which === 'enable' ? '#push-enable' : (which === 'status' ? '#push-status' : '#push-deter');
    var el = $(id);
    if (el.hasClass('on')) el.removeClass('on'); else el.addClass('on');
  }
  function savePush() {
    var cfg = {
      enable: $('#push-enable').hasClass('on'),
      url: $.trim($('#push-url').val() || ''),
      kind: $('#push-kind').val(),
      format: $('#push-format').val(),
      secret: $.trim($('#push-secret').val() || ''),
      status_enable: $('#push-status').hasClass('on'),
      status_interval: +($('#push-interval').val() || 6),
      deter_enable: $('#push-deter').hasClass('on'),
      deter_min: +($('#push-min').val() || 5),
      deter_gap: +($('#push-gap').val() || 60)
    };
    if (!cfg.url) return toast('请填写 Webhook 地址', true);
    if (!/^https?:\/\//i.test(cfg.url)) return toast('地址必须以 http:// 或 https:// 开头', true);
    api('SaveNotifyConfig', { cfg: JSON.stringify(cfg) }, function (r) {
      toast(r.msg || (r.status ? '已保存' : '保存失败'), !r.status);
      if (r.status) loadPush();
    });
  }
  function pushNow(kind) {
    toast('正在推送…');
    api('PushNotify', { kind: kind }, function (r) {
      toast(r.msg || (r.status ? '已推送' : '推送失败'), !r.status);
      if ($('#push-last').length) $('#push-last').text((r.data || {}).msg || '');
    });
  }
  function testPush() {
    toast('正在发送测试消息…');
    api('TestNotify', {}, function (r) {
      toast(r.msg || (r.status ? '测试已发送' : '发送失败'), !r.status);
    });
  }
  function previewPush() {
    api('GetNotifyConfig', {}, function (r) {
      if (!r.status) return toast('预览生成失败', true);
      PUSH.data = r.data;
      $('#push-preview').text(pushPreviewText());
    });
  }

  function loadPerm() {
    api('GetSettings', {}, function (r) {
      var p = (r.data && r.data.permissions) || {};
      var h = '<div class="table-wrap"><table><tr><th>角色</th><th>权限</th></tr>';
      Object.keys(p).forEach(function (k) {
        h += '<tr><td><b>' + k + '</b></td><td><code>' + p[k].join(', ') + '</code></td></tr>';
      });
      h += '</table></div><p class="muted" style="margin-top:8px">可用权限：view(查看) toggle(启停/模式) rule(规则) site(站点) ' +
        'logs(日志/导出/误报) alert(告警) ai(智能优化) scan(查杀) admin(全部)。角色定义可在 ' +
        '/www/server/sinanwaf/settings.json → permissions 中编辑。</p>';
      $('#perm-box').html(h);
      loadUserRoles();
    });
  }

  var UROLES = [], UROLE_ROLES = [];
  function loadUserRoles() {
    api('GetUserRoles', {}, function (r) {
      if (!r.status) {
        $('#urole-box').html('<div class="hint">' + esc(r.msg || '无法读取用户角色映射') + '</div>');
        return;
      }
      var m = (r.data && r.data.mapping) || {};
      UROLES = [];
      Object.keys(m).forEach(function (k) { UROLES.push({ user: k, role: m[k] }); });
      UROLE_ROLES = (r.data && r.data.roles) || ['admin', 'operator', 'auditor'];
      renderUserRoles();
    });
  }
  function renderUserRoles() {
    var h = '<table><tr><th>面板用户名</th><th>角色</th><th style="width:80px">操作</th></tr>';
    if (!UROLES.length) {
      h += '<tr><td colspan="3" class="empty">尚未配置映射</td></tr>';
    }
    UROLES.forEach(function (x, i) {
      h += '<tr><td><input value="' + esc(x.user) + '" oninput="BFW.uRoleEdit(' + i +
        ',\'user\',this.value)" placeholder="如 admin" style="width:100%"></td><td>' +
        '<select onchange="BFW.uRoleEdit(' + i + ',\'role\',this.value)" style="width:100%">' +
        UROLE_ROLES.map(function (r) {
          return '<option value="' + r + '"' + (x.role === r ? ' selected' : '') + '>' + r + '</option>';
        }).join('') + '</select></td>' +
        '<td><button class="btn sm err" onclick="BFW.uRoleDel(' + i + ')">移除</button></td></tr>';
    });
    h += '</table><div class="toolbar" style="margin-top:8px">' +
      '<button class="btn plain" onclick="BFW.uRoleAdd()">添加映射</button>' +
      '<button class="btn primary" onclick="BFW.saveUserRoles()">保存映射</button>' +
      '<span class="muted">仅管理员可保存</span></div>';
    $('#urole-box').html(h);
  }
  function uRoleEdit(i, k, v) { if (UROLES[i]) UROLES[i][k] = v; }
  function uRoleAdd() { UROLES.push({ user: '', role: UROLE_ROLES[1] || 'admin' }); renderUserRoles(); }
  function uRoleDel(i) { UROLES.splice(i, 1); renderUserRoles(); }
  function saveUserRoles() {
    var m = {};
    UROLES.forEach(function (x) {
      var u = $.trim(x.user || '');
      if (u) m[u] = x.role;
    });
    api('SaveUserRoles', { mapping: JSON.stringify(m) }, function (r) {
      toast(r.msg || (r.status ? '已保存' : '保存失败'), !r.status);
      if (r.status) loadUserRoles();
    });
  }
  function loadAudit(page) {
    api('GetAuditLog', { page: page || 1, limit: 50, keyword: $.trim($('#audit-kw').val() || '') }, function (r) {
      if (!r.status) return;
      var d = r.data || {};
      $('#audit-path').text('（' + (d.path || '') + '）');
      var rows = d.rows || [];
      if (!rows.length) { $('#audit-table').html('<div class="empty">暂无审计记录</div>'); return; }
      var h = '<table><tr><th>记录</th></tr>';
      rows.forEach(function (x) { h += '<tr><td style="font-family:Consolas,monospace;font-size:12px">' + esc(x) + '</td></tr>'; });
      h += '</table><div class="pager">' + pagerHtml(d.page || 1, Math.ceil((d.total || 0) / (d.limit || 50)), 'BFW.auditPage', d.total) + '</div>';
      $('#audit-table').html(h);
    });
  }

  /* ---------- WAF 配置联动状态 ---------- */
  function loadWafStatus() {
    api('GetWafStatus', {}, function (r) {
      if (!r.status) return;
      var d = r.data;
      var t = function (v) { return v === true ? '<span class="tag ok">通过</span>' :
        v === false ? '<span class="tag high">失败</span>' : '<span class="tag info">不可用</span>'; };
      var unsupported = d.apache_unsupported || [];
      var siteErr = d.site_errors || [];
      $('#waf-box').html('<div class="table-wrap"><table><tr><th>项目</th><th>状态</th></tr>' +
        '<tr><td>Nginx</td><td>' + (d.nginx ? '已安装' : '未安装') + ' / 配置校验 ' + t(d.nginx_test) + '</td></tr>' +
        '<tr><td>Apache</td><td>' + (d.apache ? '已安装' : '未安装') + ' / 配置校验 ' + t(d.apache_test) + '</td></tr>' +
        '<tr><td>全局配置注入</td><td>' + (d.global_injected ? '<span class="tag ok">已注入</span>' : '<span class="tag warn">未注入</span>') + '</td></tr>' +
        '<tr><td>已生成站点配置</td><td>Nginx ' + d.nginx_sites + ' 个 / Apache ' + d.apache_sites + ' 个</td></tr>' +
        '<tr><td>频率规则限速 zone</td><td>' + (d.freq_rules || 0) + ' 个' +
        (d.freq_rules ? '（仅对匹配 URI 计数）' : '（未配置频率规则）') + '</td></tr>' +
        '<tr><td>运行环境</td><td>Python ' + (d.python || '-') +
        (d.platform ? ' / ' + esc(d.platform) : '') +
        ' <span class="muted">（面板 7.x~13.x 通用；异常时请对照面板版本反馈）</span></td></tr>' +
        '<tr><td>端口规则下发开关</td><td>' + (d.port_enforce ? '<span class="tag ok">开启</span>' : '<span class="tag gray">关闭</span>') + '</td></tr>' +
        '<tr><td>最近一次部署</td><td class="muted">' + esc(JSON.stringify(d.last_deploy || {}).slice(0, 220)) + '</td></tr>' +
        '<tr><td>最近下发失败的站点</td><td>' + (siteErr.length ?
          '<span class="tag high">' + siteErr.length + ' 个</span> <span class="muted">' +
          siteErr.slice(0, 5).map(function (x) { return esc(x.site); }).join('、') + '</span>' :
          '<span class="tag ok">无</span>') + '</td></tr>' +
        '</table></div>' +
        (siteErr.length ? '<div style="margin-top:8px"><button class="btn sm plain" onclick="BFW.go(\'p-sites\')">到站点防护查看详情</button></div>' : '') +
        (unsupported.length ? '<div class="hint warn">有 ' + unsupported.length +
          ' 条 IP 规则无法在 Apache 侧精确表达（仅 Nginx/日志层生效）：' +
          unsupported.slice(0, 8).map(function (x) { return esc(x.pattern); }).join('、') + '</div>' : ''));
      var p = d.rules || {};
      var byType = p.by_type || {};
      var lines = Object.keys(byType).map(function (k) { return (RULE_NAMES[k] || k) + ' ' + byType[k] + ' 条'; });
      $('#deploy-preview').html('规则库中共有 <b>' + (p.total || 0) + '</b> 条规则会写入 Web 服务器配置' +
        (lines.length ? '（' + lines.join('、') + '）' : '') + '。' +
        (p.skipped_count ? '<div class="hint warn">' + p.skipped_count + ' 条未下发：' +
          (p.skipped || []).slice(0, 8).map(function (x) { return esc(x.pattern) + '(' + esc(x.reason) + ')'; }).join('、') +
          '</div>' : ''));
    });
  }
  function deployGlobal() {
    api('DeployGlobal', {}, function (r) {
      toast(r.msg || (r.status ? '已下发' : '下发失败'), !r.status);
      loadWafStatus(); loadStatusBar();
    });
  }

  /* ---------- 木马查杀 ---------- */
  var _scanPolling = false, _scanStarted = false, _scanWait = 0;
  var _avPage = 1, _avTotal = 0;
  function loadAv() {
    loadScanStats(); loadScanResults(1); pollScan(true);
  }
  function loadScanStats() {
    api('GetScanStats', {}, function (r) {
      if (!r.status) return;
      var d = r.data, lv = { critical: 0, high: 0, medium: 0, low: 0 };
      (d.levels || []).forEach(function (x) { lv[x.level] = x.c; });
      $('#av-cards').html(
        card('严重威胁', '<span class="v err">' + (lv.critical || 0) + '</span>') +
        card('高危文件', '<span class="v warn">' + (lv.high || 0) + '</span>') +
        card('中/低可疑', '<span class="v">' + ((lv.medium || 0) + (lv.low || 0)) + '</span>') +
        card('已隔离', '<span class="v">' + d.quarantined + '</span>') +
        card('病毒特征', '<span class="v">' + d.signature_count + '</span>', '条'));
      var h = '<table><tr><th>时间</th><th>类型</th><th>扫描文件</th><th>检出</th><th>耗时</th><th>状态</th></tr>';
      (d.tasks || []).forEach(function (t) {
        h += '<tr><td>' + t.time_str + '</td><td>' + (t.type === 'full' ? '全量' : '增量') + '</td>' +
          '<td>' + t.files + '</td><td>' + t.threats + '</td><td>' + t.duration + 's</td><td>' + esc(t.status) + '</td></tr>';
      });
      $('#av-tasks').html((d.tasks || []).length ? (h + '</table>')
        : '<div class="empty">暂无扫描记录</div>');
    });
  }
  function loadScanResults(page) {
    _avPage = page || 1;
    api('GetScanResults', {
      page: _avPage, limit: 20, level: $('#av-level').val(),
      keyword: $('#av-kw').val(), include_fp: $('#av-fp').prop('checked') ? '1' : '0'
    }, function (r) {
      if (!r.status) return;
      _avTotal = r.data.total;
      var rows = r.data.rows;
      setOn($('#badge-av'), 'hide', !_avTotal).text(_avTotal);
      if (!rows.length) { $('#av-table').html('<div class="empty">暂无检出记录，点击上方"快速扫描"开始</div>'); return; }
      var h = '<table><tr><th>等级/评分</th><th>站点</th><th>文件路径</th><th>命中特征</th><th>状态</th><th>操作</th></tr>';
      rows.forEach(function (x) {
        var ops = '';
        if (x.quarantined) {
          ops += '<button class="btn sm" onclick="BFW.restoreFile(' + x.id + ')">恢复</button>' +
                 '<button class="btn sm err" onclick="BFW.deleteFile(' + x.id + ')">删除</button>';
        } else {
          ops += '<button class="btn sm warn" onclick="BFW.quarantine(' + x.id + ')">隔离</button>';
        }
        ops += x.fp
          ? '<button class="btn sm plain" onclick="BFW.unmarkScanFp(' + x.id + ')">撤销误报</button>'
          : '<button class="btn sm plain" onclick="BFW.markScanFp(' + x.id + ')">误报</button>';
        h += '<tr><td><span class="tag ' + (x.level === 'critical' || x.level === 'high' ? 'high' : 'medium') + '">' +
          esc(x.level) + '</span> ' + x.score + '</td><td>' + esc(x.site) + '</td>' +
          '<td style="max-width:260px"><code>' + esc(x.path) + '</code><div class="muted">MD5 ' + esc(x.md5) + '</div></td>' +
          '<td style="max-width:280px" class="muted">' + esc(x.reasons) + '</td>' +
          '<td>' + (x.quarantined ? '<span class="tag warn">已隔离</span>' : esc(x.action)) +
          (x.fp ? ' <span class="tag gray">误报</span>' : '') + '</td>' +
          '<td style="white-space:nowrap">' + ops + '</td></tr>';
      });
      h += '</table><div class="pager">' + pagerHtml(_avPage, Math.ceil(_avTotal / 20), 'BFW.avPage', _avTotal) + '</div>';
      $('#av-table').html(h);
    });
  }
  function scanNow(full, fix) {
    if (fix && !confirm('一键查杀将自动隔离达阈值的高危文件（可在隔离区恢复），确认继续？')) return;
    api('ScanNow', { full: full ? '1' : '0', auto_fix: fix ? '1' : '0' }, function (r) {
      toast(r.msg || (r.status ? '扫描已启动' : '启动失败'), !r.status);
      if (r.status) pollScan(true);
    });
  }
  function pollScan(start) {
    if (start) { _scanPolling = true; _scanStarted = false; _scanWait = 0; }
    if (!_scanPolling) return;
    api('GetScanProgress', {}, function (r) {
      if (!r.status) { _scanPolling = false; return; }
      var d = r.data;
      if (d.running) {
        _scanStarted = true; _scanWait = 0;
        $('#av-progress').html('<div class="hint" style="margin-bottom:10px"><span class="loading"></span>' +
          '<b>扫描中（' + (d.type === 'full' ? '全量' : '增量') + '）</b> 已检查 ' + d.done +
          ' 个文件，检出 ' + d.found + ' 个' +
          '<div class="muted" style="margin-top:4px">当前: ' + esc(d.current || '') + '</div>' +
          '<div class="muted">扫描总文件数需遍历后确定，此处只显示进度计数；可随时点击"停止"。</div></div>');
      } else if (!d.type && !d.done) {
        $('#av-progress').html('<div class="muted">尚未扫描。点击右上角「快速扫描」或「全量扫描」开始' +
          '（默认扫描网站目录，可在「查杀设置」调整范围）。</div>');
      } else {
        $('#av-progress').html('<div class="muted">上次扫描(' + esc(d.type === 'full' ? '全量' : '增量') +
          ')：检查 ' + d.done + ' 个文件，检出 ' + d.found + ' 个，耗时 ' + (d.duration || 0) + 's' +
          (d.error ? ' | <span style="color:#e54545">错误: ' + esc(d.error) + '</span>' : '') + '</div>');
        if (_scanStarted) {
          loadScanStats(); loadScanResults(1);
          _scanPolling = false; _scanStarted = false;
        } else {
          _scanWait++;
          if (_scanWait > 5) _scanPolling = false;   // 等待后台线程启动，最多12秒
        }
      }
      if (_scanPolling) setTimeout(function () { pollScan(false); }, 2000);
    });
  }
  function stopScan() { api('StopScan', {}, function (r) { toast(r.msg); }); }
  function quarantine(id) {
    if (!confirm('隔离该文件？文件会被移入隔离区，可随时恢复。')) return;
    api('QuarantineFile', { id: id }, function (r) {
      toast(r.msg || (r.status ? '已隔离' : '隔离失败'), !r.status);
      loadScanResults(_avPage); loadScanStats();
    });
  }
  function quarantineAll() {
    if (!confirm('隔离所有达阈值的高危文件？（可在列表中逐一恢复）')) return;
    api('QuarantineAll', {}, function (r) {
      toast(r.msg || '已处理', !r.status); loadScanResults(1); loadScanStats();
    });
  }
  function restoreFile(id) {
    api('RestoreFile', { id: id }, function (r) {
      toast(r.msg || (r.status ? '已恢复' : '恢复失败'), !r.status); loadScanResults(_avPage);
    });
  }
  function deleteFile(id) {
    if (!confirm('永久删除该隔离文件？此操作不可恢复！')) return;
    api('DeleteInfected', { id: id }, function (r) {
      toast(r.msg || (r.status ? '已删除' : '删除失败'), !r.status); loadScanResults(_avPage);
    });
  }
  function markScanFp(id) {
    api('MarkScanFp', { id: id }, function (r) {
      toast(r.msg || '已标记误报', !r.status); loadScanResults(_avPage);
    });
  }
  function unmarkScanFp(id) {
    api('UnmarkScanFp', { id: id }, function (r) {
      toast(r.msg || (r.status ? '已撤销' : '撤销失败'), !r.status); loadScanResults(_avPage);
    });
  }
  function exportScanReport() {
    api('ExportScanReport', { fmt: 'csv' }, function (r) {
      if (!r.status) return toast(r.msg || '导出失败', true);
      var d = r.data || {};
      if (d.content && downloadText(d.filename, d.content, d.mime)) toast('报告已导出');
      else toast('报告已导出: ' + d.path);
    });
  }
  function clearScanResults() {
    if (!confirm('清空全部扫描结果？（不影响已隔离文件）')) return;
    api('ClearScanResults', {}, function (r) { toast(r.msg, !r.status); loadAv(); });
  }
  function loadAvCfg() {
    api('GetScanConfig', {}, function (r) {
      if (!r.status) return;
      var c = r.data;
      var kv = function (k, v) { return '<div class="k">' + k + '</div><div>' + v + '</div>'; };
      $('#avcfg-box').html('<div class="kv">' +
        kv('扫描目录', esc((c.targets || []).join(', ') || '自动扫描全部宝塔站点')) +
        kv('排除目录', esc((c.exclude_dirs || []).join(', ') || '按内置默认')) +
        kv('单文件上限', (c.max_file_size / 1048576).toFixed(2) + ' MB') +
        kv('文件数上限', c.max_files) +
        kv('超时', c.timeout + ' 秒') +
        kv('增量回溯', c.quick_hours + ' 小时') +
        kv('自动隔离', (c.auto_quarantine ? '<span class="tag warn">已开启</span>' : '关闭（推荐）') +
          '，阈值评分 ≥ ' + c.quarantine_score) +
        kv('联动', '生成 WAF 规则 ' + (c.auto_waf_rule ? '开' : '关') + ' / 告警 ' + (c.alert_on_found ? '开' : '关')) +
        '</div>');
    });
  }
  function showScanCfg() {
    api('GetScanConfig', {}, function (r) {
      var c = r.data;
      openModal('<h4>扫描设置</h4>' +
        '<label>扫描目录(逗号分隔, 留空=自动扫描全部宝塔站点)</label><input id="sc-targets" value="' + esc((c.targets || []).join(',')) + '">' +
        '<label>单文件大小上限(字节)</label><input id="sc-size" value="' + c.max_file_size + '">' +
        '<label>最大扫描文件数</label><input id="sc-max" value="' + c.max_files + '">' +
        '<label>超时(秒)</label><input id="sc-timeout" value="' + c.timeout + '">' +
        '<label>增量扫描回溯时长(小时)</label><input id="sc-hours" value="' + c.quick_hours + '">' +
        '<label>自动隔离阈值(评分≥)</label><input id="sc-th" value="' + c.quarantine_score + '">' +
        '<label>排除目录(逗号分隔)</label><input id="sc-ex" value="' + esc((c.exclude_dirs || []).join(',')) + '">' +
        '<label style="margin-top:8px"><input type="checkbox" id="sc-aq" style="width:auto" ' + (c.auto_quarantine ? 'checked' : '') + '> 自动隔离高危文件（建议关闭，人工复核后再处理）</label>' +
        '<label><input type="checkbox" id="sc-waf" style="width:auto" ' + (c.auto_waf_rule ? 'checked' : '') + '> 发现木马自动生成WAF拦截规则</label>' +
        '<label><input type="checkbox" id="sc-alert" style="width:auto" ' + (c.alert_on_found ? 'checked' : '') + '> 发现木马发送告警</label>' +
        '<p><button class="btn primary" onclick="BFW.saveScanCfg()">保存</button> <button class="btn" onclick="BFW.closeModal()">取消</button></p>');
    });
  }
  function saveScanCfg() {
    var split = function (v) { return v.split(',').map(function (x) { return $.trim(x); }).filter(function (x) { return x; }); };
    var cfg = {
      targets: split($('#sc-targets').val()), exclude_dirs: split($('#sc-ex').val()),
      max_file_size: +$('#sc-size').val(), max_files: +$('#sc-max').val(),
      timeout: +$('#sc-timeout').val(), quick_hours: +$('#sc-hours').val(),
      quarantine_score: +$('#sc-th').val(),
      auto_quarantine: $('#sc-aq').prop('checked'),
      auto_waf_rule: $('#sc-waf').prop('checked'),
      alert_on_found: $('#sc-alert').prop('checked')
    };
    api('SaveScanConfig', { cfg: JSON.stringify(cfg) }, function (r) {
      if (r.status) { toast('已保存'); closeModal(); }
    });
  }
  function showSigs() {
    api('GetSignatures', {}, function (r) {
      var s = r.data, sigs = s.signatures || [];
      var h = '<h4>病毒特征库 v' + esc(s.version) + '</h4><p class="muted">内置+自定义共 ' + sigs.length +
        ' 条特征' + (s.invalid && s.invalid.length ? '，无效: ' + s.invalid.join(',') : '') + '</p>' +
        '<table><tr><th>ID</th><th>名称</th><th>分组</th><th>分值</th></tr>';
      sigs.slice(0, 40).forEach(function (x) {
        h += '<tr><td>' + esc(x.id) + '</td><td>' + esc(x.name) + '</td><td>' + esc(x.group) + '</td><td>' + x.score + '</td></tr>';
      });
      h += '</table><label>自定义特征(JSON数组, 字段: id/name/pattern/score)，保存后覆盖自定义库</label>' +
        '<textarea id="sig-data" rows="6" style="width:100%" placeholder=\'[{"name":"自定义后门","pattern":"evil_function\\\\s*\\\\(","score":60}]\'></textarea>' +
        '<p><button class="btn primary" onclick="BFW.saveSigs()">保存自定义特征</button> <button class="btn" onclick="BFW.closeModal()">关闭</button></p>';
      openModal(h);
    });
  }
  function saveSigs() {
    var v = $.trim($('#sig-data').val());
    if (!v) return toast('请输入JSON数组');
    api('SaveSignatures', { data: v }, function (r) { toast(r.msg); if (r.status) closeModal(); });
  }
  function showWhite() {
    api('GetWhitelist', {}, function (r) {
      var w = r.data;
      var h = '<h4>扫描白名单</h4><p class="muted">按文件MD5或目录前缀跳过检测，用于排除误报</p>' +
        '<table><tr><th>类型</th><th>值</th><th>操作</th></tr>';
      (w.md5 || []).forEach(function (x) {
        h += '<tr><td>MD5</td><td><code>' + esc(x) + '</code></td><td><button class="btn sm err" onclick="BFW.delWhite(\'md5\',\'' + esc(x) + '\')">移除</button></td></tr>';
      });
      (w.paths || []).forEach(function (x) {
        h += '<tr><td>目录</td><td><code>' + esc(x) + '</code></td><td><button class="btn sm err" onclick="BFW.delWhite(\'path\',\'' + esc(x) + '\')">移除</button></td></tr>';
      });
      h += '</table><label>新增MD5或目录前缀</label><input id="wh-val">' +
        '<label>类型</label><select id="wh-type"><option value="md5">文件MD5</option><option value="path">目录前缀</option></select>' +
        '<p><button class="btn primary" onclick="BFW.addWhite()">添加</button> <button class="btn" onclick="BFW.closeModal()">关闭</button></p>';
      openModal(h);
    });
  }
  function addWhite() {
    var t = $('#wh-type').val(), v = $.trim($('#wh-val').val());
    if (!v) return toast('请输入内容');
    var d = {}; d[t] = v;
    api('AddWhitelist', d, function (r) { if (r.status) { toast('已添加'); showWhite(); } });
  }
  function delWhite(t, v) {
    var d = {}; d[t] = v;
    api('DelWhitelist', d, function (r) { if (r.status) showWhite(); });
  }

  /* 对外暴露 */
  var API = {
    /* 导航与全局 */
    go: go, reloadAll: reloadAll, loadStatusBar: loadStatusBar, loadOverview: loadOverview,
    toggleWaf: toggleWaf, toast: toast, closeModal: closeModal, closeDrawer: closeDrawer,
    showLogDetail: showLogDetail,
    /* 站点 */
    loadSites: loadSites, setSiteMode: setSiteMode,
    pickSite: pickSite, pickSitePage: pickSitePage, batchSite: batchSite,
    batchAllSites: batchAllSites, retryFailedSites: retryFailedSites, clearSiteSel: clearSiteSel,
    showSitePreview: showSitePreview, previewTab: previewTab, loadDeployReport: loadDeployReport,
    /* 规则 */
    loadRules: loadRules, addRule: addRule, loadDeployHint: loadDeployHint,
    showRuleTest: showRuleTest, runRuleTest: runRuleTest,
    /* IP 名单 */
    loadIps: loadIps, addIp: addIp, exportIps: exportIps, delSelectedIps: delSelectedIps,
    purgeExpired: purgeExpired,
    pickIp: pickIp, pickIpPage: pickIpPage, pickIpAll: pickIpAll, ipPage: ipPage,
    loadRegion: loadRegion, addRegion: addRegion,
    /* 端口 */
    loadPortStatus: loadPortStatus, togglePortEnforce: togglePortEnforce, syncPortRules: syncPortRules,
    /* 限速 */
    saveLimits: saveLimits,
    /* IP 粘贴提取 */
    toggleIpMode: toggleIpMode, copyIps: copyIps, banIps: banIps, ipxExtract: ipxExtract,
    showIpBanTool: showIpBanTool,
    /* 日志与统计 */
    loadLogs: loadLogs, logPage: function (p) { loadLogs(p); }, resetLogFilter: resetLogFilter,
    markFp: markFp, undoMarkFp: undoMarkFp, blockIp: blockIp, doBlockIp: doBlockIp,
    exportLogs: exportLogs,
    analyzeNow: analyzeNow, clearLogs: clearLogs, loadStats: loadStats,
    exportStats: exportStats, exportStatsPng: exportStatsPng,
    /* 告警 */
    loadAlertCfg: loadAlertCfg, saveAlert: saveAlert, alertToggle: alertToggle,
    addChannel: addChannel, chTypeChange: chTypeChange, doAddChannel: doAddChannel,
    delChannel: delChannel, testAlert: testAlert, loadAlertHistory: loadAlertHistory,
    toggleSilence: toggleSilence, switchAlertTab: switchAlertTab,
    quickAddChannel: quickAddChannel, toggleChannel: toggleChannel,
    testChannel: testChannel, editChannel: editChannel,
    /* 状态/威慑推送 */
    loadPush: loadPush, savePush: savePush, pushNow: pushNow, testPush: testPush,
    previewPush: previewPush, togglePush: togglePush,
    /* 智能优化 */
    loadAi: loadAi, runAnalysis: runAnalysis, approve: approve, rollbackRules: rollbackRules,
    toggleAutoLearn: toggleAutoLearn, saveAiAuto: saveAiAuto,
    /* 版本与备份 */
    loadBackups: loadBackups, createBackup: createBackup, restore: restore,
    restoreFromFile: restoreFromFile, exportRules: exportRules,
    downloadBackup: downloadBackup, delBackupFile: delBackupFile, delBackupVersion: delBackupVersion,
    showImport: showImport, doImport: doImport,
    /* WAF */
    loadWafStatus: loadWafStatus, deployGlobal: deployGlobal,
    /* 权限与审计 */
    loadPerm: loadPerm, loadAudit: loadAudit,
    loadUserRoles: loadUserRoles, uRoleEdit: uRoleEdit, uRoleAdd: uRoleAdd,
    uRoleDel: uRoleDel, saveUserRoles: saveUserRoles,
    auditPage: function (p) { loadAudit(p); },
    /* 木马 */
    loadAv: loadAv, loadAvCfg: loadAvCfg, loadScanResults: loadScanResults, loadScanStats: loadScanStats,
    scanNow: scanNow, stopScan: stopScan, quarantine: quarantine, quarantineAll: quarantineAll,
    restoreFile: restoreFile, deleteFile: deleteFile, markScanFp: markScanFp,
    unmarkScanFp: unmarkScanFp, exportScanReport: exportScanReport,
    clearScanResults: clearScanResults, showScanCfg: showScanCfg, saveScanCfg: saveScanCfg,
    showSigs: showSigs, saveSigs: saveSigs, showWhite: showWhite, addWhite: addWhite, delWhite: delWhite,
    avPage: function (p) { loadScanResults(p); }
  };
  for (var k in _siteOps) { API[k] = _siteOps[k]; }
  return API;
})();

/* 初始化: 类型筛选下拉 + 首页数据 */
(function init() {
  var names = window.BFW_RULE_NAMES || {};
  var opts = ['<option value="">全部类型</option>'];
  for (var k in names) {
    if (k === 'freq') continue;
    opts.push('<option value="' + k + '">' + names[k] + '</option>');
  }
  $('#lg-type').html(opts.join(''));
  $('#rg-mode').val('log');
  BFW.loadOverview();
  setInterval(function () { BFW.loadStatusBar(); }, 60 * 1000);   // 状态条定时刷新
})();
