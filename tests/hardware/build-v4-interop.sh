#!/bin/bash
# Compile only the public hardware-test drivers against an explicit installed
# app. Do not rebuild/copy application classes, install anything, or use a card.
set -euo pipefail
script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_dir="$(cd "$script_dir/../.." && pwd)"
if [[ $# -lt 1 || $# -gt 3 ]]; then
  echo 'Usage: JAVA_HOME=/patched/jdk build-v4-interop.sh APP-CONTENTS-APP [CLASSES-DIR] [--self-test]' >&2
  exit 2
fi
# Compare physical paths on both sides of the output guard. A caller may
# select the app through a symlink; logical pwd would otherwise let a resolved
# output path inside that same app appear unrelated to its aliased pathname.
app_dir="$(cd "$1" && pwd -P)"
classes="$repo_dir/build/tests/v4-interop"
self_test=0
if [[ $# -ge 2 ]]; then
  if [[ "$2" == --self-test ]]; then
    [[ $# == 2 ]] || { echo 'Unexpected argument after --self-test' >&2; exit 2; }
    self_test=1
  else
    classes="$2"
  fi
fi
if [[ $# == 3 ]]; then
  [[ "$3" == --self-test ]] || { echo 'Expected --self-test' >&2; exit 2; }
  self_test=1
fi
# Reuse the repository's patched-JDK check so javac and java come from the
# same supported runtime. A classpath cannot quietly select another JDK.
source "$repo_dir/scripts/check-java.sh"
[[ -f "$app_dir/hybrid-mail.jar" ]] || { echo 'APP-CONTENTS-APP must contain hybrid-mail.jar' >&2; exit 1; }
# Resolve a possibly new output path (including existing symlink parents)
# before creating it, so even an invalid request cannot add files to the app.
classes="$(python3 -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve())' "$classes")"
# Never write classes into the installed app, nor allow its directory to be
# nested within an output tree. Only the two driver source files are compiled.
case "$classes/" in "$app_dir/"*) echo 'Choose a class-output directory outside the app' >&2; exit 1;; esac
case "$app_dir/" in "$classes/"*) echo 'Choose a class-output directory separate from the app' >&2; exit 1;; esac
mkdir -p "$classes"
"$JAVA_HOME/bin/javac" -encoding UTF-8 -cp "$app_dir/*" -d "$classes" \
  "$script_dir/src/dev/hybridmail/V4HardwareInterop.java" \
  "$script_dir/src/dev/hybridmail/V4InstalledReceive.java"
echo "Compiled v4 interoperability drivers: $classes"
if [[ "$self_test" == 1 ]]; then
  # All keys are disposable software fixtures. This option neither reads a
  # physical card nor requests a PIN, contacts an account, or sends mail.
  "$JAVA_HOME/bin/java" -Djava.awt.headless=true -cp "$classes:$app_dir/*" \
    dev.hybridmail.V4InstalledReceive --self-test "$app_dir"
fi
