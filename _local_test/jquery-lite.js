/* ============================================================
 * jquery-lite.js —— 本地测试专用 jQuery 兼容层
 * 仅实现插件界面用到的 API 子集，生产环境由宝塔面板提供真实 jQuery。
 * 支持: $(selector/dom/document)、html/text/val/show/hide/addClass/
 *       removeClass/hasClass/prop/css/data/click/change/on/trigger/
 *       first/each、$(document).on 事件委托、$.post(...).fail()、$.trim
 * ============================================================ */
(function (global) {
  'use strict';
  var cache = {};

  function arr(x) { return Array.prototype.slice.call(x || []); }
  function match(el, sel) {
    try {
      return el.matches ? el.matches(sel) : !!(el.msMatchesSelector && el.msMatchesSelector(sel));
    } catch (e) { return false; }
  }
  function select(sel, ctx) {
    ctx = ctx || document;
    if (typeof sel === 'string') {
      try { return arr(ctx.querySelectorAll(sel)); } catch (e) { return []; }
    }
    if (sel === document || sel === global) return [document];
    if (sel && sel.nodeType) return [sel];
    if (sel && sel.els) return sel.els.slice();
    if (sel && sel.length !== undefined && typeof sel !== 'function') return arr(sel);
    return [];
  }

  function W(els) { this.els = els || []; this.length = this.els.length; }

  W.prototype.each = function (fn) {
    this.els.forEach(function (e, i) { fn.call(e, i, e); });
    return this;
  };
  W.prototype.html = function (v) {
    if (v === undefined) return this.els.length ? this.els[0].innerHTML : '';
    this.els.forEach(function (e) { e.innerHTML = v; });
    return this;
  };
  W.prototype.text = function (v) {
    if (v === undefined) return this.els.length ? this.els[0].textContent : '';
    this.els.forEach(function (e) { e.textContent = v; });
    return this;
  };
  W.prototype.val = function (v) {
    if (v === undefined) return this.els.length ? this.els[0].value : '';
    this.els.forEach(function (e) { e.value = (v === null ? '' : v); });
    return this;
  };
  W.prototype.show = function () {
    this.els.forEach(function (e) { e.style.display = 'block'; });
    return this;
  };
  W.prototype.hide = function () {
    this.els.forEach(function (e) { e.style.display = 'none'; });
    return this;
  };
  W.prototype.addClass = function (c) {
    this.els.forEach(function (e) { if (e.classList) e.classList.add(c); });
    return this;
  };
  W.prototype.removeClass = function (c) {
    this.els.forEach(function (e) { if (e.classList) e.classList.remove(c); });
    return this;
  };
  W.prototype.hasClass = function (c) {
    return this.els.some(function (e) { return e.classList && e.classList.contains(c); });
  };
  W.prototype.prop = function (k, v) {
    if (v === undefined) return this.els.length ? this.els[0][k] : undefined;
    this.els.forEach(function (e) { e[k] = v; });
    return this;
  };
  W.prototype.attr = function (k, v) {
    if (v === undefined) return this.els.length ? this.els[0].getAttribute(k) : undefined;
    this.els.forEach(function (e) { e.setAttribute(k, v); });
    return this;
  };
  W.prototype.css = function (k, v) {
    if (typeof k === 'string') {
      if (v === undefined) return this.els.length ? this.els[0].style[k] : undefined;
      this.els.forEach(function (e) { e.style[k] = v; });
    } else {
      var o = k;
      this.els.forEach(function (e) {
        Object.keys(o).forEach(function (kk) { e.style[kk] = o[kk]; });
      });
    }
    return this;
  };
  W.prototype.data = function (k) {
    if (!this.els.length) return undefined;
    return this.els[0].getAttribute('data-' + k);
  };
  W.prototype.on = function (ev, sel, fn) {
    if (typeof sel === 'function') { fn = sel; sel = null; }
    var self = this;
    this.els.forEach(function (root) {
      root.addEventListener(ev, function (e) {
        if (sel) {
          var t = e.target, m = null;
          while (t && t !== root) {
            if (t.nodeType === 1 && match(t, sel)) { m = t; break; }
            t = t.parentNode;
          }
          if (!m) return;
          fn.call(m, e);
        } else {
          fn.call(root, e);
        }
      }, false);
    });
    return self;
  };
  W.prototype.click = function (fn) { return this.on('click', fn); };
  W.prototype.change = function (fn) { return this.on('change', fn); };
  W.prototype.trigger = function (ev) {
    this.els.forEach(function (e) {
      var evt;
      try { evt = new Event(ev, { bubbles: true }); }
      catch (err) { evt = document.createEvent('HTMLEvents'); evt.initEvent(ev, true, true); }
      e.dispatchEvent(evt);
    });
    return this;
  };
  W.prototype.first = function () { return new W(this.els.slice(0, 1)); };
  W.prototype.remove = function () {
    this.els.forEach(function (e) { if (e.parentNode) e.parentNode.removeChild(e); });
    return this;
  };
  W.prototype.focus = function () { if (this.els[0]) this.els[0].focus(); return this; };

  function $(sel, ctx) {
    if (typeof sel === 'string') {
      // 同一选择器复用同一个包装对象，让界面里挂在包装对象上的计时器状态得以保留
      if (!cache[sel]) cache[sel] = new W(select(sel, ctx));
      else cache[sel].els = select(sel, ctx);
      cache[sel].length = cache[sel].els.length;
      return cache[sel];
    }
    return new W(select(sel, ctx));
  }

  $.trim = function (s) { return String(s == null ? '' : s).replace(/^\s+|\s+$/g, ''); };

  $.post = function (url, data, cb) {
    var body = [];
    Object.keys(data || {}).forEach(function (k) {
      var v = data[k];
      if (v === undefined || v === null) return;
      body.push(encodeURIComponent(k) + '=' + encodeURIComponent(v));
    });
    var promise = fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.join('&')
    }).then(function (r) {
      return r.text();
    }).then(function (t) {
      var out;
      try { out = JSON.parse(t); } catch (e) { out = t; }
      if (cb) cb(out);
      return out;
    });
    return {
      fail: function (fn) { promise.catch(function (e) { if (fn) fn(e); }); return this; },
      then: function (fn) { return promise.then(fn); }
    };
  };

  global.$ = global.jQuery = $;
})(window);
