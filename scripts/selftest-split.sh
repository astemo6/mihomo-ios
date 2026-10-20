#!/usr/bin/env bash
# Split Self-test across the main repo and the org mirror (two free-plan macOS concurrency pools).
#   origin = astemo6/mihomo-ios   → go + ui zh-Hans light/dark
#   mirror = astemo666/mihomo-ios → ui en light/dark
# (shard rule lives in .github/workflows/ui-tests.yml)
#
# Usage:
#   scripts/selftest-split.sh <name> [ref]        push ref (default HEAD) to test/<name> on both, then wait
#   scripts/selftest-split.sh push <name> [ref]   push only, print the two run IDs once they appear
#   scripts/selftest-split.sh status <name>       one-shot status of both runs (exit 0 green, 1 failed, 2 running)
#   scripts/selftest-split.sh wait <name> [secs]  poll until both finish (default 7200 s); exit like status
#   scripts/selftest-split.sh rerun <name>        re-run failed jobs of whichever run failed
#   scripts/selftest-split.sh clean <name>        delete test/<name> on both remotes
# Env: MAIN_REMOTE (origin) MIRROR_REMOTE (mirror) MAIN_REPO (astemo6/mihomo-ios) MIRROR_REPO (astemo666/mihomo-ios)
#      GITHUB_TOKEN optional (sent as Bearer when set). POLL (60 s).
# The mirror remote is added on first use if missing. Pushes are normal (force only on the test/<name> branch).
set -euo pipefail
MAIN_REMOTE=${MAIN_REMOTE:-origin}
MIRROR_REMOTE=${MIRROR_REMOTE:-mirror}
MAIN_REPO=${MAIN_REPO:-astemo6/mihomo-ios}
MIRROR_REPO=${MIRROR_REPO:-astemo666/mihomo-ios}
POLL=${POLL:-60}
API=https://api.github.com

api() { # method path [json]
  local auth=()
  [ -n "${GITHUB_TOKEN:-}" ] && auth=(-H "Authorization: Bearer $GITHUB_TOKEN")
  if [ $# -ge 3 ]; then
    curl -sS -X "$1" ${auth[@]+"${auth[@]}"} -H "Accept: application/vnd.github+json" "$API$2" -d "$3"
  else
    curl -sS -X "$1" ${auth[@]+"${auth[@]}"} -H "Accept: application/vnd.github+json" "$API$2"
  fi
}

ensure_mirror() {
  git remote get-url "$MIRROR_REMOTE" >/dev/null 2>&1 || git remote add "$MIRROR_REMOTE" "https://github.com/$MIRROR_REPO"
}

branch_sha() { # repo branch
  api GET "/repos/$1/branches/$2" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("commit",{}).get("sha",""))'
}

run_for() { # repo branch → "id status conclusion url" of the newest Self-test push run on the branch head
  local sha; sha=$(branch_sha "$1" "$2")
  [ -n "$sha" ] || { echo "- missing - -"; return; }
  api GET "/repos/$1/actions/runs?branch=$2&event=push&head_sha=$sha&per_page=20" | python3 -c '
import json,sys
runs=[r for r in json.load(sys.stdin).get("workflow_runs",[]) if r.get("name")=="Self-test"]
runs.sort(key=lambda r:r["id"], reverse=True)
r=runs[0] if runs else None
print("%s %s %s %s" % (r["id"], r["status"], r["conclusion"] or "-", r["html_url"]) if r else "- queued-not-found - -")'
}

status() { # name → prints both, returns 0 green / 1 failed / 2 running
  local b="test/$1" m o rc=0
  m=$(run_for "$MAIN_REPO" "$b"); o=$(run_for "$MIRROR_REPO" "$b")
  echo "main   ($MAIN_REPO, go + zh-Hans): $m"
  echo "mirror ($MIRROR_REPO, en):         $o"
  for x in "$m" "$o"; do
    set -- $x
    if [ "$2" != completed ]; then rc=2
    elif [ "$3" != success ] && [ "$rc" != 2 ]; then rc=1; fi
  done
  case $rc in 0) echo "VERDICT: GREEN (both runs succeeded)";; 1) echo "VERDICT: FAILED";; 2) echo "VERDICT: RUNNING";; esac
  return $rc
}

push() { # name [ref]
  local b="test/$1" ref=${2:-HEAD} out
  ensure_mirror
  git push -f "$MAIN_REMOTE" "$ref:refs/heads/$b"
  git push -f "$MIRROR_REMOTE" "$ref:refs/heads/$b"
  for _ in $(seq 1 12); do
    sleep 10
    out=$(status "$1" || true)
    echo "$out" | grep -q not-found || break
  done
  status "$1" || true
}

wait_runs() { # name [secs]
  local end=$(( $(date +%s) + ${2:-7200} )) rc
  while :; do
    set +e; status "$1"; rc=$?; set -e
    [ "$rc" != 2 ] && return "$rc"
    [ "$(date +%s)" -ge "$end" ] && { echo "timeout"; return 2; }
    sleep "$POLL"
  done
}

rerun() {
  local b="test/$1" repo x
  for repo in "$MAIN_REPO" "$MIRROR_REPO"; do
    x=$(run_for "$repo" "$b"); set -- $x
    if [ "$2" = completed ] && [ "$3" != success ]; then
      api POST "/repos/$repo/actions/runs/$1/rerun-failed-jobs" >/dev/null && echo "re-ran failed jobs of $repo run $1"
    fi
  done
}

clean() {
  ensure_mirror
  git push "$MAIN_REMOTE" --delete "test/$1" || true
  git push "$MIRROR_REMOTE" --delete "test/$1" || true
}

case "${1:-}" in
  ""|-h|--help) sed -n '2,17p' "$0"; exit 0;;
  push) push "$2" "${3:-}";;
  status) status "$2";;
  wait) wait_runs "$2" "${3:-}";;
  rerun) rerun "$2";;
  clean) clean "$2";;
  *) push "$1" "${2:-}"; wait_runs "$1";;
esac
