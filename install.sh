#!/bin/sh
# Installe Coffre pour l'utilisateur courant (~/.local), depuis l'archive de publication.
set -eu
prefix="${PREFIX:-$HOME/.local}"
here="$(cd "$(dirname "$0")" && pwd)"
install -Dm755 "$here/coffre" "$prefix/bin/coffre"
install -Dm644 "$here/data/ca.octopusai.Coffre.desktop" "$prefix/share/applications/ca.octopusai.Coffre.desktop"
install -Dm644 "$here/data/ca.octopusai.Coffre.metainfo.xml" "$prefix/share/metainfo/ca.octopusai.Coffre.metainfo.xml"
install -Dm644 "$here/data/icons/hicolor/scalable/apps/ca.octopusai.Coffre.svg" "$prefix/share/icons/hicolor/scalable/apps/ca.octopusai.Coffre.svg"
echo "Coffre installé dans $prefix (assurez-vous que $prefix/bin est dans votre PATH)."
