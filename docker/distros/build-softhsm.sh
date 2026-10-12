#!/bin/sh
# Builds SoftHSM2 from source, for distributions that do not package it
# without a subscription: SLES 15 (its softhsm is in SUSE Package Hub,
# which the public openSUSE Backports mirror no longer carries for SP7)
# and Red Hat UBI (softhsm is in RHEL, not in the UBI repositories).
#
# The tarball is GitHub's archive of the upstream release tag, pinned by
# SHA-256. Its SHA-512 is the one Fedora's softhsm package records in its
# `sources` file (src.fedoraproject.org/rpms/softhsm), checked when this
# was pinned. Archives of tags carry no generated configure, hence
# autogen.sh.
#
# Installs libsofthsm2.so under /usr/lib64/softhsm and softhsm2-util in
# /usr/bin, where SUSE's and Red Hat's own packages put them. With DESTDIR
# set, installs into that root filesystem instead (the UBI Micro image's,
# assembled in its builder stage).
set -eu

SOFTHSM_VERSION=2.7.0
SOFTHSM_SHA256=be14a5820ec457eac5154462ffae51ba5d8a643f6760514d4b4b83a77be91573

cd /tmp
curl --proto '=https' --tlsv1.2 -sSfLo softhsm.tar.gz \
    "https://github.com/softhsm/SoftHSMv2/archive/refs/tags/${SOFTHSM_VERSION}.tar.gz"
echo "${SOFTHSM_SHA256}  softhsm.tar.gz" | sha256sum -c -
tar xzf softhsm.tar.gz
cd "SoftHSMv2-${SOFTHSM_VERSION}"
sh autogen.sh
./configure --prefix=/usr --sysconfdir=/etc --libdir=/usr/lib64 \
    --with-crypto-backend=openssl --disable-gost --without-p11-kit
make -j"$(nproc)"
make install DESTDIR="${DESTDIR:-}"
cd /tmp
rm -rf softhsm.tar.gz "SoftHSMv2-${SOFTHSM_VERSION}"
[ -n "${DESTDIR:-}" ] || softhsm2-util --version
