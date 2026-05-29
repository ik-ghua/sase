#!/bin/sh
# PostToolUse hook:Edit/Write 后,若是 *.go 则自动 gofmt + goimports。
# 读 stdin 的 hook JSON 取 tool_input.file_path;始终 exit 0(不阻断编辑)。
input=$(cat)
f=$(printf '%s' "$input" | jq -r '.tool_input.file_path // empty' 2>/dev/null)
case "$f" in
  *.go)
    [ -f "$f" ] || exit 0
    "$HOME/.local/go/bin/gofmt" -w "$f" 2>/dev/null
    "$HOME/go/bin/goimports" -w "$f" 2>/dev/null
    ;;
esac
exit 0
