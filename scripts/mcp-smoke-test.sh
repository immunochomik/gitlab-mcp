#!/bin/sh

set -eu

endpoint=${1:-http://127.0.0.1:8787/mcp}
project=${2:-k8s/eats}
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/gitlab-mcp-smoke.XXXXXX")
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

step=0
session_id=

show_body() {
	body=$1
	if [ ! -s "$body" ]; then
		printf '  Response body: <empty>\n'
	elif command -v jq >/dev/null 2>&1 && jq -e . "$body" >/dev/null 2>&1; then
		jq . "$body"
	else
		cat "$body"
		printf '\n'
	fi
}

post() {
	name=$1
	expected_status=$2
	payload=$3
	headers="$tmp_dir/headers-$step"
	body="$tmp_dir/body-$step"
	step=$((step + 1))

	printf '\n[%s] %s\n' "$step" "$name"
	printf '  POST %s\n' "$endpoint"

	if [ -n "$session_id" ]; then
		status=$(curl -sS -D "$headers" -o "$body" -w '%{http_code}' \
			-X POST "$endpoint" \
			-H 'Content-Type: application/json' \
			-H 'Accept: application/json, text/event-stream' \
			-H "Mcp-Session-Id: $session_id" \
			-d "$payload") || {
			printf '  ERROR: curl could not connect to the server.\n' >&2
			exit 1
		}
	else
		status=$(curl -sS -D "$headers" -o "$body" -w '%{http_code}' \
			-X POST "$endpoint" \
			-H 'Content-Type: application/json' \
			-H 'Accept: application/json, text/event-stream' \
			-d "$payload") || {
			printf '  ERROR: curl could not connect to the server.\n' >&2
			exit 1
		}
	fi

	printf '  HTTP status: %s\n' "$status"
	show_body "$body"
	if [ "$status" != "$expected_status" ]; then
		printf '  ERROR: expected HTTP %s, received HTTP %s.\n' "$expected_status" "$status" >&2
		exit 1
	fi

	last_headers=$headers
}

printf 'GitLab MCP smoke test\n'
printf 'Endpoint: %s\n' "$endpoint"
printf 'Project:  %s\n' "$project"

post "Initialize MCP session" 200 '{
  "jsonrpc":"2.0",
  "id":1,
  "method":"initialize",
  "params":{
    "protocolVersion":"2025-11-25",
    "capabilities":{},
    "clientInfo":{"name":"curl-smoke-test","version":"1.0"}
  }
}'

session_id=$(awk 'tolower($1) == "mcp-session-id:" {gsub("\\r", "", $2); print $2}' "$last_headers")
if [ -z "$session_id" ]; then
	printf 'ERROR: initialize response did not contain Mcp-Session-Id.\n' >&2
	exit 1
fi
printf '  Session ID: %s\n' "$session_id"

post "Send initialized notification" 202 '{
  "jsonrpc":"2.0",
  "method":"notifications/initialized"
}'

post "List registered tools" 200 '{
  "jsonrpc":"2.0",
  "id":2,
  "method":"tools/list",
  "params":{}
}'

escaped_project=$(printf '%s' "$project" | sed 's/\\/\\\\/g; s/"/\\"/g')
post "Call search_mrs" 200 "{
  \"jsonrpc\":\"2.0\",
  \"id\":3,
  \"method\":\"tools/call\",
  \"params\":{
    \"name\":\"search_mrs\",
    \"arguments\":{\"project\":\"$escaped_project\",\"limit\":5}
  }
}"

printf '\nPASS: MCP initialization and tool calls completed successfully.\n'
