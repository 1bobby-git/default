#!/usr/bin/env python3
from __future__ import annotations

import base64
import importlib.util
import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

ROOT = Path(os.environ.get('GITHUB_WORKSPACE', Path.cwd()))
SPEC = importlib.util.spec_from_file_location('apti_v4_probe', ROOT / 'scripts/apti_v4_probe.py')
if SPEC is None or SPEC.loader is None:
    raise RuntimeError('unable to load Apti v4 probe module')
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def install_adb_keyboard() -> str | None:
    apk = probe.WORK / 'ADBKeyboard.apk'
    url = 'https://raw.githubusercontent.com/senzhk/ADBKeyBoard/master/ADBKeyboard.apk'
    try:
        probe.run(['curl', '-fL', '--retry', '5', url, '-o', str(apk)], timeout=180)
        probe.adb('install', '-r', str(apk), check=False, timeout=120)
        listing = probe.adb_shell('ime list -a -s', check=False, timeout=30, sensitive=True).stdout or ''
        components = [line.strip() for line in listing.splitlines() if '/' in line]
        component = next((line for line in components if re.search(r'adb.*keyboard|adbime', line, re.I)), None)
        (probe.OUT / 'ime-components.txt').write_text(
            '\n'.join(probe.redact(line) for line in components) + '\n', encoding='utf-8'
        )
        if component:
            probe.adb_shell(f'ime enable {component}', check=False, timeout=30)
            selected = probe.adb_shell(f'ime set {component}', check=False, timeout=30)
            if selected.returncode == 0:
                return component
    except Exception as exc:
        probe.log(f'ADBKeyboard setup failed: {exc}')
    return None


def ime_text(value: str, component: str | None) -> None:
    probe.clear_focused_field()
    if component:
        encoded = base64.b64encode(value.encode('utf-8')).decode('ascii')
        subprocess.run(
            ['adb', 'shell', 'am', 'broadcast', '-a', 'ADB_INPUT_B64', '--es', 'msg', encoded],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=30,
        )
    else:
        probe.input_text_secret(value)


def choose_id_tab(nodes: list[dict[str, Any]]) -> None:
    exact = [
        node for node in nodes
        if re.fullmatch(r'\s*아이디\s*', re.sub(r'\s+', ' ', str(node.get('label', ''))), re.I)
        and node['center'][1] > 250
    ]
    if exact:
        exact.sort(key=lambda item: (0 if item.get('clickable') else 1, item['center'][1], item['area']))
        probe.tap_xy(*exact[0]['center'])
        return
    combined = [
        node for node in nodes
        if re.search(r'휴대폰\s*번호', str(node.get('label', '')), re.I)
        and re.search(r'아이디', str(node.get('label', '')), re.I)
        and node['center'][1] > 250
    ]
    if combined:
        combined.sort(key=lambda item: item['area'])
        x1, y1, x2, y2 = combined[0]['bounds']
        probe.tap_xy(int(x1 + (x2 - x1) * 0.76), (y1 + y2) // 2)
        return
    width, _ = probe.screen_size()
    probe.tap_xy(int(width * 0.75), 390)


def login_v5(username: str, password: str) -> dict[str, Any]:
    result: dict[str, Any] = {'attempted': False, 'success': False, 'reason': 'unknown', 'input_method': None}
    _, nodes = probe.dump_ui('v5-01-before-login')
    if probe.has_label(nodes, r'로그아웃|마이페이지|내 아파트|회원정보') and not probe.has_label(nodes, r'비밀번호'):
        result.update({'success': True, 'reason': 'already_logged_in', 'labels': probe.labels(nodes)[:150]})
        return result

    if not probe.has_label(nodes, r'비밀번호|휴대폰\s*번호|아이디'):
        probe.tap_matching(nodes, r'^로그인$', min_y=100, max_y=900)
        time.sleep(3)
        _, nodes = probe.dump_ui('v5-02-login-entry')

    choose_id_tab(nodes)
    time.sleep(2)
    _, nodes = probe.dump_ui('v5-03-id-tab')

    component = install_adb_keyboard()
    result['input_method'] = component or 'adb-input-text'
    fields = probe.locate_fields(nodes)
    width, height = probe.screen_size()
    if len(fields) >= 2:
        user_xy, pass_xy = fields[0]['center'], fields[1]['center']
    else:
        semantic_user = [n for n in nodes if re.search(r'아이디|ID', str(n.get('label','')), re.I) and n['center'][1] > 350]
        semantic_pass = [n for n in nodes if re.search(r'비밀번호|password', str(n.get('label','')), re.I) and n['center'][1] > 350]
        user_xy = min(semantic_user, key=lambda n:n['area'])['center'] if semantic_user else (width//2, int(height*0.31))
        pass_xy = min(semantic_pass, key=lambda n:n['area'])['center'] if semantic_pass else (width//2, int(height*0.405))

    result['attempted'] = True
    probe.tap_xy(*user_xy)
    time.sleep(0.7)
    ime_text(username, component)
    time.sleep(1)
    probe.tap_xy(*pass_xy)
    time.sleep(0.7)
    ime_text(password, component)
    time.sleep(1.5)
    probe.screenshot('v5-04-login-filled-sensitive')
    _, filled_nodes = probe.dump_ui('v5-04-login-filled')

    submit = [
        n for n in filled_nodes
        if re.fullmatch(r'\s*로그인\s*', re.sub(r'\s+', ' ', str(n.get('label',''))), re.I)
        and n['center'][1] > pass_xy[1]
    ]
    if submit:
        submit.sort(key=lambda n:(0 if n.get('clickable') else 1,n['center'][1]))
        probe.tap_xy(*submit[0]['center'])
    else:
        probe.adb_shell('input keyevent KEYCODE_ENTER', check=False)
        time.sleep(1)
        probe.tap_xy(width//2, int(height*0.55))

    deadline = time.time() + 50
    index = 0
    last_nodes: list[dict[str, Any]] = []
    while time.time() < deadline:
        time.sleep(2)
        _, last_nodes = probe.dump_ui(f'v5-05-login-result-{index:02d}')
        current = probe.labels(last_nodes)
        error = probe.has_label(last_nodes, r'일치하지|확인해|실패|오류|잠시 후|잠겼|제한|올바르지')
        form = probe.has_label(last_nodes, r'비밀번호') and probe.has_label(last_nodes, r'^로그인$')
        explicit = probe.has_label(last_nodes, r'로그아웃|마이페이지|내 아파트|회원정보|우리집 관리비|관리비 납부')
        if explicit or not form:
            result.update({'success': True, 'reason': 'explicit_logged_in_ui' if explicit else 'login_screen_disappeared', 'labels': current[:160]})
            break
        if error:
            result.update({'reason': 'visible_login_error', 'labels': current[:160]})
            break
        index += 1
    else:
        result.update({'reason': 'login_screen_remained', 'labels': probe.labels(last_nodes)[:160]})

    probe.screenshot('v5-05-login-result')
    probe.adb_shell('ime reset', check=False, timeout=30)
    return result


def prompt_helper(stop: threading.Event) -> None:
    index = 0
    while not stop.is_set():
        try:
            _, nodes = probe.dump_ui(f'v5-prompt-{index:03d}', attempts=2)
            index += 1
            patterns = [
                r'^열기$', r'앱에서 열기', r'^계속$', r'^Open$', r'Continue',
                r'^항상$', r'^이번만$', r'아파트아이에서 열기', r'Open in app',
            ]
            acted = False
            for pattern in patterns:
                if probe.tap_matching(nodes, pattern, min_y=250, prefer_lowest=True):
                    time.sleep(1.5)
                    acted = True
                    break
            if not acted and probe.has_label(nodes, r'연결 프로그램|다음으로 열기|Open with'):
                if probe.tap_matching(nodes, r'아파트아이', min_y=300, prefer_lowest=False):
                    time.sleep(1)
                    acted = True
            if not acted:
                time.sleep(0.8)
        except Exception:
            time.sleep(1)


def launch_original_url_v5() -> dict[str, Any]:
    stop = threading.Event()
    thread = threading.Thread(target=prompt_helper, args=(stop,), daemon=True)
    thread.start()
    try:
        result = probe.launch_original_url()
    finally:
        stop.set()
        thread.join(timeout=4)
    return result


def main() -> int:
    credentials = json.loads(probe.CREDENTIALS_FILE.read_text(encoding='utf-8'))
    username = str(credentials['username'])
    password = str(credentials['password'])
    probe.SECRET_VALUES.extend([username, password])
    probe.start_logcat()
    probe.download_and_install_app()
    probe.launch_app()
    login_result = login_v5(username, password)
    probe.start_frida()
    launch_result = launch_original_url_v5()
    probe.storage_inventory()
    probe.summarize(login_result, launch_result)
    (probe.OUT / 'variant.txt').write_text('v5-clean-login-before-instrumentation\n', encoding='utf-8')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        probe.log(f'v5 fatal: {type(exc).__name__}: {exc}')
        (probe.OUT / 'FATAL-v5.txt').write_text(probe.redact(f'{type(exc).__name__}: {exc}\n'), encoding='utf-8')
        raise
    finally:
        probe.cleanup()
