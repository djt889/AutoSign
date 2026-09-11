#!/usr/bin/env bash
# ============================================================
#  AutoSign WebUI 启动脚本(Linux / macOS)
#  首次运行会自动创建虚拟环境并安装依赖
#  Ctrl+C 停止服务
# ============================================================
set -u

cd "$(dirname "$0")" || exit 1

PORT="${JUSTSIGN_PORT:-37421}"
VENV=".venv"
PYEXE="$VENV/bin/python"

echo "==============================================="
echo "  AutoSign  WebUI  http://127.0.0.1:${PORT}"
echo "-----------------------------------------------"
echo "  按 Ctrl+C 停止服务"
echo "==============================================="
echo

if [ ! -x "$PYEXE" ]; then
  # ---------- 1) 找系统 Python ----------
  if command -v python3 >/dev/null 2>&1; then
    SYS_PY=python3
  elif command -v python >/dev/null 2>&1; then
    SYS_PY=python
  else
    echo "[错误] 未检测到 Python3。"
    echo "        Debian/Ubuntu:  sudo apt install python3 python3-venv"
    echo "        macOS:          brew install python"
    exit 1
  fi

  # macOS 常见:python3 存在但缺 venv 模块
  if ! "$SYS_PY" -c "import venv" >/dev/null 2>&1; then
    echo "[错误] 当前 Python 缺少 venv 模块。"
    echo "        Debian/Ubuntu:  sudo apt install python3-venv"
    exit 1
  fi

  # ---------- 2) 建虚拟环境 + 装依赖(仅首次) ----------
  echo "[初始化] 首次运行,正在创建虚拟环境..."
  if ! "$SYS_PY" -m venv "$VENV"; then
    echo "[错误] 创建虚拟环境失败。"
    exit 1
  fi
  echo "[初始化] 正在安装依赖(需要几分钟)..."
  "$PYEXE" -m pip install --upgrade pip >/dev/null 2>&1
  if ! "$PYEXE" -m pip install -r pc/requirements.txt; then
    echo "[错误] 依赖安装失败,请检查网络后重试。"
    exit 1
  fi
  echo
  echo "[提示] 依赖安装完成。"
  echo "        如需「全自动授权」,请再执行一次以下命令安装浏览器内核:"
  echo "            $VENV/bin/python -m scrapling install"
  echo "        不装也能用,只是授权时改走「手动浏览器」方式。"
  echo
fi

# ---------- 3) 启动服务 ----------
export PYTHONUTF8=1
"$PYEXE" -m pc.main
EC=$?

echo
if [ "$EC" -ne 0 ]; then
  echo "[错误] 服务异常退出(代码 $EC)。"
  echo "        常见原因:端口 ${PORT} 已被占用。"
  echo "        换端口重试:  JUSTSIGN_PORT=37555 ./start-server.sh"
else
  echo "服务已停止。"
fi
