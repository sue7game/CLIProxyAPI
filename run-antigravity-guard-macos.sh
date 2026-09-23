#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
START_DIR="$(pwd -P)"
PLUGIN_SOURCE_DIR="$ROOT_DIR/examples/plugin/antigravity-guard/go"
BUILD_DIR="$ROOT_DIR/build/antigravity-guard/macos-arm64"
MAIN_BINARY="$BUILD_DIR/cli-proxy-api-macos-arm64"
BUILT_PLUGIN="$BUILD_DIR/antigravity-guard.dylib"
CONFIG_FILE_INPUT="${CONFIG_FILE:-$ROOT_DIR/config.yaml}"
PLUGIN_DIR=""
INSTALLED_PLUGIN=""

case "$CONFIG_FILE_INPUT" in
  "~")
    CONFIG_FILE="$HOME"
    ;;
  "~/"*)
    CONFIG_FILE="$HOME/${CONFIG_FILE_INPUT#\~/}"
    ;;
  /*)
    CONFIG_FILE="$CONFIG_FILE_INPUT"
    ;;
  *)
    CONFIG_FILE="$START_DIR/$CONFIG_FILE_INPUT"
    ;;
esac

print_usage() {
  cat <<'EOF'
用法：
  ./run-antigravity-guard-macos.sh build
  ./run-antigravity-guard-macos.sh run
  ./run-antigravity-guard-macos.sh build-run
  ./run-antigravity-guard-macos.sh help

命令说明：
  build      测试并编译 macOS ARM64 主程序和 Antigravity Guard 插件
  run        安装已编译插件，然后以前台方式启动服务
  build-run  先编译，再安装插件并启动服务
  help       显示本说明

默认输出：
  build/antigravity-guard/macos-arm64/cli-proxy-api-macos-arm64
  build/antigravity-guard/macos-arm64/antigravity-guard.dylib
  build/antigravity-guard/macos-arm64/antigravity-guard.h（Go 自动生成，运行时不使用）

可选环境变量：
  CONFIG_FILE    配置文件，默认使用项目根目录 config.yaml
  REPLACE_PLUGIN 设为 1 时允许非交互覆盖现有插件；覆盖前仍会创建时间戳备份

说明：
  - 脚本不会停止任何正在运行的服务。
  - 如果端口已被占用，run 会直接退出，不安装或覆盖插件。
  - build 只覆盖专用 build 目录中的同名构建产物。
  - 覆盖旧插件前会询问，并在同目录保留时间戳备份。
  - 服务以前台方式运行，按 Ctrl+C 停止。
EOF
}

fail() {
  printf '错误：%s\n' "$*" >&2
  exit 1
}

require_command() {
  local name="$1"
  command -v "$name" >/dev/null 2>&1 || fail "缺少命令：$name"
}

check_environment() {
  local system
  local architecture

  system="$(uname -s)"
  architecture="$(uname -m)"
  [[ "$system" == "Darwin" ]] || fail "此脚本只用于 macOS，当前系统为 $system"
  [[ "$architecture" == "arm64" ]] || fail "此脚本只用于 M 系列 Mac，当前架构为 $architecture"

  require_command go
  require_command clang
  require_command grep
  require_command awk
  require_command lsof
  require_command cmp
  require_command file

  [[ -f "$CONFIG_FILE" ]] || fail "配置文件不存在：$CONFIG_FILE"
  [[ -d "$PLUGIN_SOURCE_DIR" ]] || fail "插件源码目录不存在：$PLUGIN_SOURCE_DIR"

  if ! grep -Eq '^[[:space:]]*antigravity-guard:[[:space:]]*$' "$CONFIG_FILE"; then
    fail "配置文件中没有 plugins.configs.antigravity-guard：$CONFIG_FILE"
  fi

  configure_plugin_path
}

detect_port() {
  awk '
    /^[[:space:]]*#/ { next }
    /^port:[[:space:]]*/ {
      value = $0
      sub(/^port:[[:space:]]*/, "", value)
      sub(/[[:space:]#].*$/, "", value)
      print value
      exit
    }
  ' "$CONFIG_FILE"
}

detect_plugin_dir() {
  awk '
    /^plugins:[[:space:]]*(#.*)?$/ {
      in_plugins = 1
      next
    }
    in_plugins && /^[^[:space:]#]/ {
      exit
    }
    in_plugins && /^[[:space:]]+dir:[[:space:]]*/ {
      value = $0
      sub(/^[[:space:]]+dir:[[:space:]]*/, "", value)
      sub(/[[:space:]]+#.*$/, "", value)
      sub(/^[[:space:]]+/, "", value)
      sub(/[[:space:]]+$/, "", value)
      print value
      exit
    }
  ' "$CONFIG_FILE"
}

configure_plugin_path() {
  local configured_dir

  configured_dir="$(detect_plugin_dir)"
  configured_dir="${configured_dir#\"}"
  configured_dir="${configured_dir%\"}"
  configured_dir="${configured_dir#\'}"
  configured_dir="${configured_dir%\'}"
  configured_dir="${configured_dir:-plugins}"

  case "$configured_dir" in
    "~")
      PLUGIN_DIR="$HOME"
      ;;
    "~/"*)
      PLUGIN_DIR="$HOME/${configured_dir#\~/}"
      ;;
    /*)
      PLUGIN_DIR="$configured_dir"
      ;;
    *)
      PLUGIN_DIR="$ROOT_DIR/$configured_dir"
      ;;
  esac

  INSTALLED_PLUGIN="$PLUGIN_DIR/darwin/arm64/antigravity-guard.dylib"
}

run_plugin_checks() {
  printf '\n[1/3] 运行插件 Go 测试\n'
  (
    cd "$PLUGIN_SOURCE_DIR"
    CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 CC=clang go test -race ./...
  )

  if command -v node >/dev/null 2>&1; then
    printf '\n[2/3] 检查管理页面 JavaScript 语法\n'
    node --check "$PLUGIN_SOURCE_DIR/web/api.js"
    node --check "$PLUGIN_SOURCE_DIR/web/app.js"
    node --check "$PLUGIN_SOURCE_DIR/web/format.js"
    node --check "$PLUGIN_SOURCE_DIR/web/search.js"
    node --check "$PLUGIN_SOURCE_DIR/web/proxy.js"
    node --check "$PLUGIN_SOURCE_DIR/web/settings.js"
    node --test "$PLUGIN_SOURCE_DIR/web/search.test.cjs"
    node --test "$PLUGIN_SOURCE_DIR/web/proxy.test.cjs"
    node --test "$PLUGIN_SOURCE_DIR/web/settings.test.cjs"
  else
    printf '\n[2/3] 警告：未安装 Node.js，跳过 JavaScript 语法检查\n' >&2
  fi
}

build_artifacts() {
  check_environment
  mkdir -p "$BUILD_DIR"

  run_plugin_checks

  printf '\n[3/3] 编译主程序和插件\n'
  (
    cd "$ROOT_DIR"
    CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 CC=clang \
      go build -buildvcs=false -o "$MAIN_BINARY" ./cmd/server
  )
  (
    cd "$PLUGIN_SOURCE_DIR"
    CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 CC=clang \
      go build -buildvcs=false -buildmode=c-shared -o "$BUILT_PLUGIN" .
  )

  printf '\n编译完成：\n'
  file "$MAIN_BINARY"
  file "$BUILT_PLUGIN"
  printf '\n运行命令：\n  ./run-antigravity-guard-macos.sh run\n'
}

check_port_available() {
  local port="$1"
  local listeners
  local status

  set +e
  listeners="$(lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>&1)"
  status=$?
  set -e

  if [[ "$status" -eq 0 ]]; then
    printf '端口 %s 已被占用，脚本不会停止现有服务：\n%s\n' "$port" "$listeners" >&2
    exit 1
  fi
  if [[ "$status" -ne 1 || -n "$listeners" ]]; then
    fail "无法确认端口 $port 是否空闲：$listeners"
  fi
}

confirm_plugin_replacement() {
  local answer

  if [[ "${REPLACE_PLUGIN:-0}" == "1" ]]; then
    return
  fi
  [[ -t 0 ]] || fail "已有不同版本插件；非交互运行时请先设置 REPLACE_PLUGIN=1"

  printf '已有插件：%s\n' "$INSTALLED_PLUGIN"
  printf '是否备份并替换为本次编译版本？[y/N] '
  read -r answer
  [[ "$answer" == "y" || "$answer" == "Y" ]] || fail "用户取消替换插件"
}

install_plugin() {
  local backup_path
  local pending_path

  [[ -f "$MAIN_BINARY" ]] || fail "主程序尚未编译，请先运行 build：$MAIN_BINARY"
  [[ -f "$BUILT_PLUGIN" ]] || fail "插件尚未编译，请先运行 build：$BUILT_PLUGIN"
  [[ ! -L "$INSTALLED_PLUGIN" ]] || fail "目标插件是符号链接，脚本不会覆盖：$INSTALLED_PLUGIN"

  mkdir -p "$(dirname -- "$INSTALLED_PLUGIN")"

  if [[ -f "$INSTALLED_PLUGIN" ]] && cmp -s "$BUILT_PLUGIN" "$INSTALLED_PLUGIN"; then
    printf '已安装的插件与本次编译版本一致，无需替换。\n'
    return
  fi

  if [[ -e "$INSTALLED_PLUGIN" ]]; then
    [[ -f "$INSTALLED_PLUGIN" ]] || fail "插件目标已存在且不是普通文件：$INSTALLED_PLUGIN"
    confirm_plugin_replacement
    backup_path="$INSTALLED_PLUGIN.backup-$(date '+%Y%m%d-%H%M%S')-$$"
    [[ ! -e "$backup_path" ]] || fail "插件备份路径已存在：$backup_path"
    cp -p "$INSTALLED_PLUGIN" "$backup_path"
    printf '旧插件已备份到：%s\n' "$backup_path"
  fi

  pending_path="$INSTALLED_PLUGIN.pending-$(date '+%Y%m%d-%H%M%S')-$$"
  [[ ! -e "$pending_path" ]] || fail "插件暂存路径已存在：$pending_path"
  cp "$BUILT_PLUGIN" "$pending_path"
  file "$pending_path" | grep -Eq 'Mach-O 64-bit.*arm64' || fail "暂存插件不是 macOS ARM64 动态库：$pending_path"
  mv -f "$pending_path" "$INSTALLED_PLUGIN"
  printf '插件已安装到：%s\n' "$INSTALLED_PLUGIN"
}

run_service() {
  local port

  check_environment
  port="$(detect_port)"
  port="${port:-8317}"
  [[ "$port" =~ ^[0-9]+$ ]] || fail "端口不是有效数字：$port"
  check_port_available "$port"
  install_plugin

  printf '\n正在启动 CLIProxyAPI：\n'
  printf '  配置：%s\n' "$CONFIG_FILE"
  printf '  管理页面：http://127.0.0.1:%s/v0/resource/plugins/antigravity-guard/dashboard\n' "$port"
  printf '  停止服务：按 Ctrl+C\n\n'

  cd "$ROOT_DIR"
  exec "$MAIN_BINARY" --config "$CONFIG_FILE"
}

main() {
  case "${1:-help}" in
    build)
      build_artifacts
      ;;
    run)
      run_service
      ;;
    build-run)
      build_artifacts
      run_service
      ;;
    help|-h|--help)
      print_usage
      ;;
    *)
      print_usage >&2
      fail "未知命令：$1"
      ;;
  esac
}

main "$@"
