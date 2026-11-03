#!/bin/bash

set -eu

PORT=${PORT:-9999}

# 检查 FLAG 环境变量
if [ -z "${FLAG+x}" ]; then
    echo "[-] FLAG environment variable not set"
    exit 1
fi

# 创建 /flag
umask 077
printf '%s\n' "$FLAG" > /flag

# 设置权限：所有用户可读，不可写
chmod 444 /flag

# 清除子进程中的 FLAG 环境变量
unset FLAG

echo "[+] Pwn Challenge Started"
echo "[+] Port: $PORT"

# 切换普通用户，启动 socat
exec gosu pwn socat TCP-LISTEN:${PORT},reuseaddr,fork \
    EXEC:"timeout -k 2 60 /home/pwn/pwn",stderr
