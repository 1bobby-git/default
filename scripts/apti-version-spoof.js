'use strict';

function emit(kind, data) {
  const row = Object.assign({ ts: new Date().toISOString(), kind: kind }, data || {});
  send(row);
}

function safeUrl(value) {
  let text = String(value === null || value === undefined ? '' : value);
  text = text.replace(/([?&](?:access[_-]?token|refresh[_-]?token|token|authorization|auth|session|sid|password|passwd|secret|api[_-]?key)=)[^&#]*/ig, '$1<redacted>');
  return text.slice(0, 4000);
}

Java.perform(function () {
  emit('hook_ready', { pid: Process.id });

  try {
    const WebView = Java.use('android.webkit.WebView');
    WebView.setWebContentsDebuggingEnabled(true);
    emit('webview_debugging_enabled', {});

    const load1 = WebView.loadUrl.overload('java.lang.String');
    load1.implementation = function (url) {
      emit('webview_load_url', { url: safeUrl(url), headerNames: [] });
      return load1.call(this, url);
    };

    const load2 = WebView.loadUrl.overload('java.lang.String', 'java.util.Map');
    load2.implementation = function (url, headers) {
      const names = [];
      try {
        const it = headers.keySet().iterator();
        while (it.hasNext()) names.push(String(it.next()));
      } catch (_) {}
      emit('webview_load_url', { url: safeUrl(url), headerNames: names });
      return load2.call(this, url, headers);
    };

    const addJs = WebView.addJavascriptInterface.overload('java.lang.Object', 'java.lang.String');
    addJs.implementation = function (object, name) {
      let className = '';
      try { className = String(object.getClass().getName()); } catch (_) {}
      emit('webview_add_js_interface', { name: String(name), className: className });
      return addJs.call(this, object, name);
    };
  } catch (e) {
    emit('webview_hook_error', { error: String(e) });
  }

  try {
    const PackageInfo = Java.use('android.content.pm.PackageInfo');
    const originalGetLong = PackageInfo.getLongVersionCode.overload();
    originalGetLong.implementation = function () {
      try {
        if (String(this.packageName.value) === 'aptip.app') {
          emit('version_spoof_get_long', { versionName: '3.3.59', versionCode: 1739 });
          return 1739;
        }
      } catch (_) {}
      return originalGetLong.call(this);
    };
  } catch (e) {
    emit('package_info_long_hook_error', { error: String(e) });
  }

  try {
    const APM = Java.use('android.app.ApplicationPackageManager');
    APM.getPackageInfo.overloads.forEach(function (overload) {
      overload.implementation = function () {
        const result = overload.apply(this, arguments);
        try {
          if (result && String(result.packageName.value) === 'aptip.app') {
            const beforeName = String(result.versionName.value);
            let beforeCode = null;
            try { beforeCode = Number(result.versionCode.value); } catch (_) {}
            result.versionName.value = '3.3.59';
            try { result.versionCode.value = 1739; } catch (_) {}
            emit('version_spoof_package_info', {
              beforeVersionName: beforeName,
              beforeVersionCode: beforeCode,
              afterVersionName: '3.3.59',
              afterVersionCode: 1739
            });
          }
        } catch (e) {
          emit('version_spoof_mutation_error', { error: String(e) });
        }
        return result;
      };
    });
  } catch (e) {
    emit('package_manager_hook_error', { error: String(e) });
  }

  try {
    const CookieManager = Java.use('android.webkit.CookieManager');
    CookieManager.setCookie.overloads.forEach(function (overload) {
      overload.implementation = function () {
        const url = arguments.length > 0 ? safeUrl(arguments[0]) : '';
        const cookie = arguments.length > 1 ? String(arguments[1]) : '';
        const names = cookie.split(';').map(function (part) { return part.split('=', 1)[0].trim(); }).filter(Boolean);
        emit('cookie_set', { url: url, names: names });
        return overload.apply(this, arguments);
      };
    });
    const getCookie = CookieManager.getCookie.overload('java.lang.String');
    getCookie.implementation = function (url) {
      const value = getCookie.call(this, url);
      const names = value ? String(value).split(';').map(function (part) { return part.split('=', 1)[0].trim(); }).filter(Boolean) : [];
      emit('cookie_get', { url: safeUrl(url), names: names });
      return value;
    };
  } catch (e) {
    emit('cookie_hook_error', { error: String(e) });
  }
});
