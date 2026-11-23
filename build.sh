#!/usr/bin/env bash
# 一键构建 + 跑离线自测（不需要 Burp，也不需要联网下载 Gradle）
#
#   bash build.sh          构建 jar
#   bash build.sh test     构建后跑 dev/ 下的三个自测
#
set -euo pipefail
cd "$(dirname "$0")"

find_gradle() {
  # 1) 本地 wrapper —— 只有当它要的那个版本已经躺在缓存里才用，
  #    否则 ./gradlew 会去 services.gradle.org 下载（很多内网机器连不上，会卡住）
  if [ -x ./gradlew ]; then
    ver=$(grep -o 'gradle-[0-9.]*-bin.zip' gradle/wrapper/gradle-wrapper.properties 2>/dev/null | head -1 | sed 's/-bin.zip//')
    if [ -n "$ver" ] && [ -n "$(find "$HOME/.gradle/wrapper/dists/$ver-bin" -maxdepth 3 -name gradle -type f 2>/dev/null | head -1)" ]; then
      echo "./gradlew"
      return
    fi
  fi
  # 2) PATH 里的 gradle
  if command -v gradle >/dev/null 2>&1; then
    echo "gradle"
    return
  fi
  # 3) 本机 Gradle 缓存里的任意一个 8.x 分发
  local hit
  hit=$(find "$HOME/.gradle/wrapper/dists" -maxdepth 6 -path "*/gradle-8*/bin/gradle" -type f 2>/dev/null | sort | tail -1)
  if [ -n "$hit" ]; then
    echo "$hit"
    return
  fi
  echo "找不到 gradle，请先装一个或让 ./gradlew 能联网" >&2
  exit 1
}

GRADLE=$(find_gradle)
echo "== 使用 $GRADLE"
"$GRADLE" --console=plain -q jar

JAR=build/libs/yuc-1.0.jar
ls -l "$JAR"

if [ "${1:-}" != "test" ]; then
  exit 0
fi

JAVA_BIN=${JAVA_HOME:+$JAVA_HOME/bin/}
API_JAR=$(find "$HOME/.gradle/caches/modules-2/files-2.1/net.portswigger.burp.extensions/montoya-api" \
  -name "montoya-api-*.jar" ! -name "*-sources.jar" ! -name "*-javadoc.jar" 2>/dev/null | sort | tail -1)
if [ -z "$API_JAR" ]; then
  echo "找不到 montoya-api jar，先跑一次构建" >&2
  exit 1
fi
# Windows 版 javac 不认 /c/Users/... 这种 MSYS 路径
if command -v cygpath >/dev/null 2>&1; then
  API_JAR=$(cygpath -w "$API_JAR")
fi
# Windows 版 java 的 classpath 分隔符是分号
if [[ "${OSTYPE:-}" == msys* || "${OSTYPE:-}" == cygwin* ]]; then SEP=";"; else SEP=":"; fi
CP="build/classes/java/main${SEP}${API_JAR}"

# SQLite 驱动（自带 native），自测要真连库
SQLITE_JAR=$(find "$HOME/.gradle/caches/modules-2/files-2.1/org.xerial/sqlite-jdbc" \
  -name "sqlite-jdbc-*.jar" ! -name "*-sources.jar" 2>/dev/null | sort | tail -1)
if [ -n "$SQLITE_JAR" ]; then
  if command -v cygpath >/dev/null 2>&1; then SQLITE_JAR=$(cygpath -w "$SQLITE_JAR"); fi
  CP="${CP}${SEP}${SQLITE_JAR}"
fi

mkdir -p dev/out
"${JAVA_BIN}javac" -encoding UTF-8 -cp "$CP" -d dev/out dev/*.java
for t in Harness RecorderSmoke HistorySmoke DbSmoke HeaderSmoke UrlSmoke PayloadSmoke BaseHeaderSmoke SamplesSmoke FilterSmoke UiSmoke; do
  echo "== $t"
  "${JAVA_BIN}java" -Dfile.encoding=UTF-8 -cp "$CP${SEP}dev/out" "$t"
done
