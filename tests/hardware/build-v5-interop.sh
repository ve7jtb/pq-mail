#!/bin/bash
# Compile just the v5 hardware-test drivers against one explicitly selected
# app. Nothing is installed and no physical card is accessed by this script.
set -euo pipefail
script_dir="$(cd "$(dirname "$0")" && pwd -P)"
repo_dir="$(cd "$script_dir/../.." && pwd -P)"
[[ $# == 2 || ( $# == 3 && "$3" == --self-test ) ]] || { echo 'Usage: JAVA_HOME=/patched/jdk build-v5-interop.sh APP-CONTENTS-APP CLASSES-DIR [--self-test]' >&2; exit 2; }
app_dir="$(cd "$1" && pwd -P)"
classes="$(python3 -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve())' "$2")"
# Resolve symlinks before mkdir, so an invalid output path cannot create even
# an empty directory inside the selected app or overwrite its classes.
case "$classes/" in "$app_dir/"*) echo 'Choose a class directory outside the app' >&2; exit 1;; esac
case "$app_dir/" in "$classes/"*) echo 'Choose a separate class directory' >&2; exit 1;; esac
source "$repo_dir/scripts/check-java.sh"
[[ -f "$app_dir/hybrid-mail.jar" ]] || { echo 'Selected app jar is missing' >&2; exit 1; }
mkdir -p "$classes"
"$JAVA_HOME/bin/javac" -encoding UTF-8 -cp "$app_dir/*" -d "$classes" \
  "$script_dir/src/dev/hybridmail/V5HardwareInterop.java" \
  "$script_dir/src/dev/hybridmail/V5InstalledReceive.java" \
  "$script_dir/src/dev/hybridmail/V5AdapterProtocolTest.java" \
  "$script_dir/src/dev/hybridmail/V5SoftwareFixture.java"
echo "Compiled v5 hardware-test drivers: $classes"
if [[ $# == 3 ]]; then
  # Fake executables exercise the real subprocess framing without a physical
  # device. In particular signing is Base64 while KEM output is raw bytes.
  "$JAVA_HOME/bin/java" -Djava.awt.headless=true -cp "$classes:$app_dir/*" \
    dev.hybridmail.V5AdapterProtocolTest
fi
