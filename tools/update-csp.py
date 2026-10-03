#!/usr/bin/env python3
"""Пересчитывает хэши встроенных скриптов в Content-Security-Policy файла index.html.

Страница разрешает выполнять только те <script>, чей SHA-256 записан в CSP.
После ЛЮБОЙ правки кода внутри <script> запустите:

    python3 tools/update-csp.py index.html

Иначе браузер заблокирует изменённый скрипт и страница не заработает.
"""
import base64, hashlib, re, sys

path = sys.argv[1] if len(sys.argv) > 1 else 'index.html'
html = open(path, encoding='utf-8', newline='').read()
if '\r' in html:
    sys.exit('В файле есть CRLF-переводы строк: хэши не совпадут с тем, что получит браузер. Сохраните файл с LF.')

scripts = re.findall(r'<script>(.*?)</script>', html, re.S)
if not scripts:
    sys.exit('Встроенные скрипты не найдены')
hashes = ["'sha256-%s'" % base64.b64encode(hashlib.sha256(s.encode('utf-8')).digest()).decode() for s in scripts]

m = re.search(r"script-src [^;]*;", html)
if not m:
    sys.exit('Директива script-src не найдена')
new = "script-src %s 'wasm-unsafe-eval';" % ' '.join(hashes)
html = html[:m.start()] + new + html[m.end():]
open(path, 'w', encoding='utf-8', newline='').write(html)
print('script-src обновлён: %d скрипт(а)' % len(scripts))
