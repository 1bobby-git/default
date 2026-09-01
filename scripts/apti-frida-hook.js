'use strict';

function clip(value, limit) {
  const text = String(value === null || value === undefined ? "" : value);
  return text.length > limit ? text.slice(0, limit) + "…" : text;
}

function safeUrl(value) {
  let text = clip(value, 4000);
  try {
    text = text.replace(
      /([?&](?:access[_-]?token|refresh[_-]?token|token|authorization|auth|session|sid|jsessionid|password|passwd|secret|api[_-]?key)=)[^&#]*/ig,
      "$1<redacted>"
    );
  } catch (_) {}
  return text;
}

function safeScript(value) {
  let text = clip(value, 800);
  try {
    text = text.replace(
      /((?:access[_-]?token|refresh[_-]?token|token|authorization|auth|session|sid|jsessionid|password|passwd|secret|api[_-]?key)[\s\"']*[:=][\s\"']*)[^\"'&,;)}\s]+/ig,
      "$1<redacted>"
    );
  } catch (_) {}
  return text;
}

function cookieNames(value) {
  if (!value) return [];
  return String(value).split(";").map(function (item) {
    return item.split("=", 1)[0].trim();
  }).filter(Boolean);
}

function safeIntent(intent) {
  const result = { action: null, data: null, component: null, flags: null, extras: [] };
  try { result.action = String(intent.getAction()); } catch (_) {}
  try { result.data = intent.getData() ? safeUrl(intent.getDataString()) : null; } catch (_) {}
  try { result.component = intent.getComponent() ? String(intent.getComponent().flattenToShortString()) : null; } catch (_) {}
  try { result.flags = Number(intent.getFlags()); } catch (_) {}
  try {
    const extras = intent.getExtras();
    if (extras) {
      const it = extras.keySet().iterator();
      while (it.hasNext()) result.extras.push(String(it.next()));
    }
  } catch (_) {}
  return result;
}

function emit(kind, data) {
  const row = Object.assign({ ts: new Date().toISOString(), kind: kind }, data || {});
  console.log("[APTI_PROBE] " + JSON.stringify(row));
}

Java.perform(function () {
  emit("frida_ready", { pid: Process.id });

  try {
    const WebView = Java.use("android.webkit.WebView");
    try {
      WebView.setWebContentsDebuggingEnabled(true);
      emit("webview_debugging_enabled", {});
    } catch (e) {
      emit("webview_debugging_error", { error: String(e) });
    }

    const load1 = WebView.loadUrl.overload("java.lang.String");
    load1.implementation = function (url) {
      emit("webview_load_url", { url: safeUrl(url), headers: [] });
      return load1.call(this, url);
    };

    const load2 = WebView.loadUrl.overload("java.lang.String", "java.util.Map");
    load2.implementation = function (url, headers) {
      const names = [];
      try {
        const it = headers.keySet().iterator();
        while (it.hasNext()) names.push(String(it.next()));
      } catch (_) {}
      emit("webview_load_url", { url: safeUrl(url), headers: names });
      return load2.call(this, url, headers);
    };

    const postUrl = WebView.postUrl.overload("java.lang.String", "[B");
    postUrl.implementation = function (url, body) {
      emit("webview_post_url", { url: safeUrl(url), body_bytes: body ? body.length : 0 });
      return postUrl.call(this, url, body);
    };

    const addJs = WebView.addJavascriptInterface.overload("java.lang.Object", "java.lang.String");
    addJs.implementation = function (object, name) {
      let className = null;
      try { className = String(object.getClass().getName()); } catch (_) {}
      emit("webview_add_js_interface", { name: String(name), class_name: className });
      return addJs.call(this, object, name);
    };

    const evalJs = WebView.evaluateJavascript.overload(
      "java.lang.String", "android.webkit.ValueCallback"
    );
    evalJs.implementation = function (script, callback) {
      emit("webview_evaluate_js", { script: safeScript(script), script_length: script ? String(script).length : 0 });
      return evalJs.call(this, script, callback);
    };
  } catch (e) {
    emit("webview_hook_error", { error: String(e) });
  }

  try {
    const WebSettings = Java.use("android.webkit.WebSettings");
    const setUa = WebSettings.setUserAgentString.overload("java.lang.String");
    setUa.implementation = function (ua) {
      emit("webview_set_user_agent", { user_agent: clip(ua, 1000) });
      return setUa.call(this, ua);
    };
    const setDomStorage = WebSettings.setDomStorageEnabled.overload("boolean");
    setDomStorage.implementation = function (enabled) {
      emit("webview_dom_storage", { enabled: Boolean(enabled) });
      return setDomStorage.call(this, enabled);
    };
    const setJavaScript = WebSettings.setJavaScriptEnabled.overload("boolean");
    setJavaScript.implementation = function (enabled) {
      emit("webview_javascript", { enabled: Boolean(enabled) });
      return setJavaScript.call(this, enabled);
    };
  } catch (e) {
    emit("websettings_hook_error", { error: String(e) });
  }

  try {
    const CookieManager = Java.use("android.webkit.CookieManager");
    const setCookie2 = CookieManager.setCookie.overload("java.lang.String", "java.lang.String");
    setCookie2.implementation = function (url, value) {
      emit("cookie_set", { url: safeUrl(url), names: cookieNames(value) });
      return setCookie2.call(this, url, value);
    };
    const setCookie3 = CookieManager.setCookie.overload(
      "java.lang.String", "java.lang.String", "android.webkit.ValueCallback"
    );
    setCookie3.implementation = function (url, value, callback) {
      emit("cookie_set", { url: safeUrl(url), names: cookieNames(value) });
      return setCookie3.call(this, url, value, callback);
    };
    const getCookie = CookieManager.getCookie.overload("java.lang.String");
    getCookie.implementation = function (url) {
      const value = getCookie.call(this, url);
      emit("cookie_get", { url: safeUrl(url), names: cookieNames(value) });
      return value;
    };
    const removeAll = CookieManager.removeAllCookies.overload("android.webkit.ValueCallback");
    removeAll.implementation = function (callback) {
      emit("cookie_remove_all", {});
      return removeAll.call(this, callback);
    };
    const setAcceptCookie = CookieManager.setAcceptCookie.overload("boolean");
    setAcceptCookie.implementation = function (accept) {
      emit("cookie_accept", { enabled: Boolean(accept) });
      return setAcceptCookie.call(this, accept);
    };
    const setAcceptThirdPartyCookies = CookieManager.setAcceptThirdPartyCookies.overload(
      "android.webkit.WebView", "boolean"
    );
    setAcceptThirdPartyCookies.implementation = function (webView, accept) {
      emit("cookie_accept_third_party", { enabled: Boolean(accept) });
      return setAcceptThirdPartyCookies.call(this, webView, accept);
    };
  } catch (e) {
    emit("cookie_hook_error", { error: String(e) });
  }

  try {
    const Activity = Java.use("android.app.Activity");
    const start1 = Activity.startActivity.overload("android.content.Intent");
    start1.implementation = function (intent) {
      emit("activity_start", safeIntent(intent));
      return start1.call(this, intent);
    };
    const start2 = Activity.startActivity.overload(
      "android.content.Intent", "android.os.Bundle"
    );
    start2.implementation = function (intent, options) {
      emit("activity_start", safeIntent(intent));
      return start2.call(this, intent, options);
    };
    const startForResult = Activity.startActivityForResult.overload(
      "android.content.Intent", "int"
    );
    startForResult.implementation = function (intent, requestCode) {
      const row = safeIntent(intent);
      row.request_code = requestCode;
      emit("activity_start_for_result", row);
      return startForResult.call(this, intent, requestCode);
    };
  } catch (e) {
    emit("activity_hook_error", { error: String(e) });
  }

  try {
    const ContextWrapper = Java.use("android.content.ContextWrapper");
    const contextStart = ContextWrapper.startActivity.overload("android.content.Intent");
    contextStart.implementation = function (intent) {
      emit("context_start_activity", safeIntent(intent));
      return contextStart.call(this, intent);
    };
  } catch (e) {
    emit("context_hook_error", { error: String(e) });
  }

  try {
    const CustomTabsIntent = Java.use("androidx.browser.customtabs.CustomTabsIntent");
    const launchUrl = CustomTabsIntent.launchUrl.overload(
      "android.content.Context", "android.net.Uri"
    );
    launchUrl.implementation = function (context, uri) {
      emit("custom_tab_launch", { url: safeUrl(uri) });
      return launchUrl.call(this, context, uri);
    };
  } catch (e) {
    emit("custom_tab_hook_unavailable", { error: String(e) });
  }

  try {
    const MainActivity = Java.use("aptip.app.MainActivity");
    if (MainActivity.onNewIntent) {
      const onNewIntent = MainActivity.onNewIntent.overload("android.content.Intent");
      onNewIntent.implementation = function (intent) {
        emit("main_on_new_intent", safeIntent(intent));
        return onNewIntent.call(this, intent);
      };
    }
  } catch (e) {
    emit("main_activity_hook_error", { error: String(e) });
  }
});
