#!/bin/sh
# Compile le paquet .apk de Coffre dans un conteneur Alpine (exécuté en root).
#
#   docker run --rm -v "$PWD:/src" alpine:3.24 /src/packaging/postmarketos/build-apk.sh
#
# Produit dans /src/dist/ : le paquet .apk, l'APKBUILD avec sa somme de contrôle,
# l'archive des sources et la clé publique de signature.
set -eu

src=/src
out="$src/dist"
pkgver=$(sed -n 's/^pkgver=//p' "$src/packaging/postmarketos/APKBUILD")
tarball="coffre-$pkgver.tar.gz"

apk add --no-cache alpine-sdk sudo git
adduser -D builder
addgroup builder abuild
echo "builder ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/builder

# Archive des sources, identique à celle jointe à la publication.
git config --global --add safe.directory "$src"
mkdir -p "$out" /home/builder/distfiles /home/builder/coffre
git -C "$src" archive --format=tar.gz --prefix="coffre-$pkgver/" -o "$out/$tarball" HEAD
cp "$out/$tarball" /home/builder/distfiles/
cp "$src/packaging/postmarketos/APKBUILD" /home/builder/coffre/
chown -R builder:builder /home/builder

su builder -c '
	set -eu
	export SRCDEST=/home/builder/distfiles
	abuild-keygen -a -n -i
	cd /home/builder/coffre
	abuild checksum
	abuild -r
'

cp /home/builder/packages/*/"$(apk --print-arch)"/coffre-*.apk "$out/"
cp /home/builder/coffre/APKBUILD "$out/APKBUILD"
cp /home/builder/.abuild/*.rsa.pub "$out/"
ls -l "$out"
