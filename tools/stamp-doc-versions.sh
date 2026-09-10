#!/usr/bin/env bash
# Stamps the install lines in README.md with a release tag, so a reader pastes
# a version that exists: stamp-doc-versions.sh <tag>.
set -euo pipefail
tag="${1:?usage: stamp-doc-versions.sh <tag>}"
version="${tag#v}"
sed -i.bak -E \
  -e "s|(from: \")[0-9][^\"]*(\")|\1${version}\2|" \
  -e "s|(io\.github\.avosa:gossveil:)[^\"]*|\1${version}|" \
  -e "s|(@myzonerocks/gossveil@)[^ \`]*|\1${version}|" \
  README.md
rm -f README.md.bak
echo "stamp-doc-versions: README.md names ${version}"
