#!/bin/bash
# Один раз, от root:  sudo bash scripts/install-helper.sh
# Кладёт root-владельные скрипты и бинарь sing-box в /usr/local/fork_lite и разрешает ВАШЕМУ пользователю запускать
# ровно эти два скрипта без пароля. Ничего больше sudoers не получает.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "Запусти через sudo"; exit 1; }
ME=${SUDO_USER:?запусти через sudo из своей сессии}
H=$(cd "$(dirname "$0")" && pwd); [ -d "$H/helper" ] || H=$(cd "$H/.." && pwd)
[ -d "$H/helper" ] || { echo "Не нашёл каталог helper рядом с установщиком"; exit 1; }
[ -x "$H/vendor/bin/sing-box" ] || { echo "В приложении нет sing-box"; exit 1; }

F=/usr/local/fork_lite
mkdir -p $F
for s in fork-core-start fork-core-stop fork-awg-start fork-awg-stop; do
  install -m 755 -o root -g wheel "$H/helper/$s" "$F/$s"
done
install -m 755 -o root -g wheel "$H/vendor/bin/sing-box" "$F/sing-box"
for binary in amneziawg-go awg; do
  install -m 755 -o root -g wheel "$H/vendor/bin/$binary" "$F/$binary"
done
chown -R root:wheel $F; chmod -R go-w $F

T=/etc/sudoers.d/fork_lite.tmp
echo "$ME ALL=(root) NOPASSWD: $F/fork-core-start, $F/fork-core-stop, $F/fork-awg-start, $F/fork-awg-stop" > $T
chmod 440 $T; chown root:wheel $T
visudo -cf $T && mv $T /etc/sudoers.d/fork_lite
echo "OK: установлено в $F, sing-box $($F/sing-box version | head -1)"
