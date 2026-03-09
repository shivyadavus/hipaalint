#!/usr/bin/env bash

set -euo pipefail

pick_java_home() {
  if [[ -n "${JAVA_HOME:-}" && -x "${JAVA_HOME}/bin/java" ]]; then
    local current_major
    current_major=$("${JAVA_HOME}/bin/java" -version 2>&1 | awk -F '[\".]' '/version/ { print $2 }')
    if [[ "${current_major}" == "17" || "${current_major}" == "21" ]]; then
      echo "${JAVA_HOME}"
      return 0
    fi
  fi

  for candidate in "${JDK_21:-}" "${JDK_17:-}" "/tmp/hipaalint-jdks/jdk-21.0.10+7/Contents/Home"; do
    if [[ -n "${candidate}" && -x "${candidate}/bin/java" ]]; then
      echo "${candidate}"
      return 0
    fi
  done

  if command -v /usr/libexec/java_home >/dev/null 2>&1; then
    for version in 21 17; do
      if candidate=$(/usr/libexec/java_home -v "${version}" 2>/dev/null); then
        echo "${candidate}"
        return 0
      fi
    done
  fi

  return 1
}

if JAVA_HOME_RESOLVED=$(pick_java_home); then
  export JAVA_HOME="${JAVA_HOME_RESOLVED}"
  export PATH="${JAVA_HOME}/bin:${PATH}"
else
  echo "Unable to locate a supported JDK. Set JAVA_HOME, JDK_21, or JDK_17 to a JDK 21/17 installation." >&2
  exit 1
fi

exec ./jetbrains-plugin/gradlew -p jetbrains-plugin buildPlugin
