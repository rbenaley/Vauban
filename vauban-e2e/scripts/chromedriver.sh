#!/usr/bin/env bash
# Print the path of a chromedriver matching the installed Chrome build,
# downloading it once from Chrome for Testing into target/e2e-drivers/.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) platform=mac-arm64 ;;
  Darwin-x86_64) platform=mac-x64 ;;
  Linux-x86_64) platform=linux64 ;;
  *) echo "unsupported platform $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

chrome="${VAUBAN_E2E_CHROME:-}"
if [[ -z "$chrome" ]]; then
  for c in "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" google-chrome chromium; do
    if command -v "$c" >/dev/null 2>&1 || [[ -x "$c" ]]; then chrome="$c"; break; fi
  done
fi
[[ -n "$chrome" ]] || { echo "Chrome not found (set VAUBAN_E2E_CHROME)" >&2; exit 1; }

version="$("$chrome" --version | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')"
build="${version%.*}"
dir="$root/target/e2e-drivers/$build"
driver="$dir/chromedriver-$platform/chromedriver"

if [[ ! -x "$driver" ]]; then
  meta="https://googlechromelabs.github.io/chrome-for-testing/latest-patch-versions-per-build-with-downloads.json"
  url="$(curl -fsSL "$meta" | python3 -c "
import json, sys
builds = json.load(sys.stdin)['builds']
entry = builds.get('$build')
if not entry:
    sys.exit('no chromedriver published for Chrome build $build')
print(next(d['url'] for d in entry['downloads']['chromedriver'] if d['platform'] == '$platform'))
")"
  mkdir -p "$dir"
  curl -fsSL "$url" -o "$dir/chromedriver.zip"
  unzip -oq "$dir/chromedriver.zip" -d "$dir"
  rm -f "$dir/chromedriver.zip"
  chmod +x "$driver"
fi

echo "$driver"
