#!/usr/bin/env bash
# Поднимает версию проекта в CMakeLists.txt (project VERSION) и vcpkg.json
# (version-string), коммитит оба файла и создаёт аннотированный тег vX.Y.Z.
# Тег НЕ отправляется в origin — публикация вручную:
#   git push origin master && git push origin vX.Y.Z
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 X.Y.Z" >&2
  exit 1
fi

version="$1"
if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Error: version must match X.Y.Z (semver), got '${version}'" >&2
  exit 1
fi

tag="v${version}"
if git rev-parse --verify --quiet "refs/tags/${tag}" >/dev/null; then
  echo "Error: tag ${tag} already exists" >&2
  exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "Error: working tree is not clean; commit or stash changes first" >&2
  exit 1
fi

# Полное совпадение строки без обратных ссылок: `\1${version}` дал бы sed
# неоднозначное `\11.2.3` (группа 11 вместо группы 1 с цифрой).
sed -i -E "s/^project\(tls_echo_server VERSION [0-9.]+ LANGUAGES CXX\)/project(tls_echo_server VERSION ${version} LANGUAGES CXX)/" CMakeLists.txt
sed -i -E "s/^  \"version-string\": \"[0-9.]+\",/  \"version-string\": \"${version}\",/" vcpkg.json

# sed молча успешен и без совпадения: проверяем, что версия действительно
# записана, иначе откатываем файлы.
if ! grep -q "project(tls_echo_server VERSION ${version} LANGUAGES CXX)" CMakeLists.txt || \
   ! grep -q "\"version-string\": \"${version}\"" vcpkg.json; then
  git restore CMakeLists.txt vcpkg.json
  echo "Error: version pattern not found in CMakeLists.txt or vcpkg.json" >&2
  exit 1
fi

git add CMakeLists.txt vcpkg.json
git commit -m "Поднять версию до ${version}"
git tag -a "${tag}" -m "Release ${tag}"

echo "Version bumped to ${version}, annotated tag ${tag} created."
echo "Publish with: git push origin master && git push origin ${tag}"
