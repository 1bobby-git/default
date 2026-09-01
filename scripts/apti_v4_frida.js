'use strict';

function clip(value, limit) {
  const text = String(value === null || value === undefined ? '' : value);
  return text.length > limit ? text.slice(0, limit) + '…' : text;
}

function safeUrl(value) {
  let text = clip(value, 5000);
  try {
    text = text.replace(/([?&](?:access[_-]?token|refresh[_-]?token|token|authorization|auth|session|sid|jsessionid|password|passwd|secret|api[_-]?key)=)[^&#]*/ig, '$1<redacted>');
  } catch (_) {}
  return text;
}

function cookieNames(value) {
  if (!value) return [];
  return String(value).split(';').map(function (item) {
    return item.split('=', 1)[0].trim();
  }).filter(Boolean);
}

function emit(kind, data) {
  console.log('[APTI_V4] ' + JSON.stringify(Object.assign({
    ts: new Date().toISOString(),
    kind: kind
  }, data || {})));
}

Java.perform(function () {
  emit('frida_ready', { pid: Process.id });

  try {
    const WebView = Java.use('android.webkit.WebView');
    try {
      WebView.setWebContentsDebuggingEnabled(true);
      emit('webview_debugging_enabled', {});
    } catch (e) {
      emit('webview_debugging_error', { error: String(e) });
    }

    const loadUrl1 = WebView.loadUrl.overload('java.lang.String');
    loadUrl1.implementation = function (url) {
      emit('webview_load_url', { url: safeUrl(url), header_names: [] });
      return loadUrl1.call(this, url);
    };

    const loadUrl2 = WebView.loadUrl.overload('java.lang.String', 'java.util.Map');
    loadUrl2.implementation = function (url, headers) {
      const names = [];
      try {
        const iterator = headers.keySet().iterator();
        while (iterator.hasNext()) names.push(String(iterator.next()).toLowerCase());
      } catch (_) {}
      emit('webview_load_url', { url: safeUrl(url), header_names: names.sort() });
      return loadUrl2.call(this, url, headers);
    };

    const postUrl = WebView.postUrl.overload('java.lang.String', '[B');
    postUrl.implementation = function (url, body) {
      emit('webview_post_url', { url: safeUrl(url), body_bytes: body ? body.length : 0 });
      return postUrl.call(this, url, body);
    };

    const addJs = WebView.addJavascriptInterface.overload('java.lang.Object', 'java.lang.String');
    addJs.implementation = function (object, name) {
      let className = null;
      try { className = String(object.getClass().getName()); } catch (_) {}
      emit('webview_add_js_interface', { name: String(name), class_name: className });
      return addJs.call(this, object, name);
    };

    const evaluate = WebView.evaluateJavascript.overload('java.lang.String', 'android.webkit.ValueCallback');
    evaluate.implementation = function (script, callback) {
      const text = clip(script, 12000).replace(/((?:access[_-]?token|refresh[_-]?token|token|authorization|password|passwd|session|secret)\s*[:=]\s*["'])[^"]+/ig, '$1<redacted>');
      emit('webview_evaluate_js', { script_length: String(script || '').length, script: text });
      return evaluate.call(this, script, callback);
    };
  } catch (e) {
    emit('webview_hook_error', { error: String(e) });
  }

  try {
    const CookieManager = Java.use('android.webkit.CookieManager');
    const setCookie2 = CookieManager.setCookie.overload('java.lang.String', 'java.lang.String');
    setCookie2.implementation = function (url, value) {
      emit('cookie_set', { url: safeUrl(url), names: cookieNames(value) });
      return setCookie2.call(this, url, value);
    };
    const setCookie3 = CookieManager.setCookie.overload('java.lang.String', 'java.lang.String', 'android.webkit.ValueCallback');
    setCookie3.implementation = function (url, value, callback) {
      emit('cookie_set', { url: safeUrl(url), names: cookieNames(value) });
      return setCookie3.call(this, url, value, callback);
    };
    const getCookie = CookieManager.getCookie.overload('java.lang.String');
    getCookie.implementation = function (url) {
      const value = getCookie.call(this, url);
      emit('cookie_get', { url: safeUrl(url), names: cookieNames(value) });
      return value;
    };
    const removeAll = CookieManager.removeAllCookies.overload('android.webkit.ValueCallback');
    removeAll.implementation = function (callback) {
      emit('cookie_remove_all', {});
      return removeAll.call(this, callback);
    };
  } catch (e) {
    emit('cookie_hook_error', { error: String(e) });
  }

  function safeIntent(intent) {
    const row = { action: null, data: null, component: null, flags: null, extra_names: [] };
    try { row.action = String(intent.getAction()); } catch (_) {}
    try { row.data = intent.getData() ? safeUrl(intent.getDataString()) : null; } catch (_) {}
    try { row.component = intent.getComponent() ? String(intent.getComponent().flattenToShortString()) : null; } catch (_) {}
    try { row.flags = Number(intent.getFlags()); } catch (_) {}
    try {
      const extras = intent.getExtras();
      if (extras) {
        const iterator = extras.keySet().iterator();
        while (iterator.hasNext()) row.extra_names.push(String(iterator.next()));
      }
    } catch (_) {}
    return row;
  }

  try {
    const Activity = Java.use('android.app.Activity');
    const start1 = Activity.startActivity.overload('android.content.Intent');
    start1.implementation = function (intent) {
      emit('activity_start', safeIntent(intent));
      return start1.call(this, intent);
    };
    const start2 = Activity.startActivity.overload('android.content.Intent', 'android.os.Bundle');
    start2.implementation = function (intent, options) {
      emit('activity_start', safeIntent(intent));
      return start2.call(this, intent, options);
    };
  } catch (e) {
    emit('activity_hook_error', { error: String(e) });
  }

  try {
    const MainActivity = Java.use('aptip.app.MainActivity');
    if (MainActivity.onNewIntent) {
      const onNewIntent = MainActivity.onNewIntent.overload('android.content.Intent');
      onNewIntent.implementation = function (intent) {
        emit('main_on_new_intent', safeIntent(intent));
        return onNewIntent.call(this, intent);
      };
    }
  } catch (e) {
    emit('main_activity_hook_error', { error: String(e) });
  }

  try {
    const CustomTabsIntent = Java.use('androidx.browser.customtabs.CustomTabsIntent');
    const launchUrl = CustomTabsIntent.launchUrl.overload('android.content.Context', 'android.net.Uri');
    launchUrl.implementation = function (context, uri) {
      emit('custom_tab_launch', { url: safeUrl(uri) });
      return launchUrl.call(this, context, uri);
    };
  } catch (e) {
    emit('custom_tab_hook_unavailable', { error: String(e) });
  }

  try {
    const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    const SSLContext = Java.use('javax.net.ssl.SSLContext');
    const TrustManager = Java.registerClass({
      name: 'org.openai.apti.TrustAllManager',
      implements: [X509TrustManager],
      methods: {
        checkClientTrusted: function () {},
        checkServerTrusted: function () {},
        getAcceptedIssuers: function () { return []; }
      }
    });
    const trustManagers = [TrustManager.$new()];
    const init = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
    init.implementation = function (keyManagers, _trustManagers, secureRandom) {
      emit('ssl_context_init_replaced', {});
      return init.call(this, keyManagers, trustManagers, secureRandom);
    };
  } catch (e) {
    emit('ssl_hook_error', { error: String(e) });
  }

  try {
    const CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check.overloads.forEach(function (overload) {
      overload.implementation = function () {
        emit('okhttp_pin_bypass', { host: arguments.length ? clip(arguments[0], 300) : null });
        return;
      };
    });
  } catch (e) {
    emit('okhttp_pin_hook_unavailable', { error: String(e) });
  }
});
