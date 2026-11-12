#!/bin/bash
# Один раз, от root:  sudo bash scripts/install-helper.sh
# Кладёт root-владельные скрипты и бинарь sing-box в /usr/local/fork_lite и разрешает ВАШЕМУ пользователю запускать
# ровно эти два скрипта без пароля. Ничего больше sudoers не получает.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "Запусти через sudo"; exit 1; }
ME=${SUDO_USER:?запусти через sudo из своей сессии}
H=$(cd "$(dirname "$0")" && pwd); [ -d "$H/helper" ] || H=$(cd "$H/.." && pwd)
[ -d "$H/helper" ] || { echo "Не нашёл каталог helper рядом с установщиком"; exit 1; }
SB=${SINGBOX:-$(sudo -u "$ME" bash -lc 'command -v sing-box' || true)}
[ -x "$SB" ] || { echo "sing-box не найден: brew install sing-box"; exit 1; }

F=/usr/local/fork_lite
mkdir -p $F
for s in fork-core-start fork-core-stop; do
  install -m 755 -o root -g wheel "$H/helper/$s" "$F/$s"
done
install -m 755 -o root -g wheel "$SB" "$F/sing-box"
chown -R root:wheel $F; chmod -R go-w $F

T=/etc/sudoers.d/fork.tmp
echo "$ME ALL=(root) NOPASSWD: $F/fork-core-start, $F/fork-core-stop" > $T
chmod 440 $T; chown root:wheel $T
visudo -cf $T && mv $T /etc/sudoers.d/fork
echo "OK: установлено в $F, sing-box $($F/sing-box version | head -1)"
