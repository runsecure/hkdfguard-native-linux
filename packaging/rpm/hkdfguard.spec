# Built by packaging/build-rpm.sh inside packaging/Dockerfile.dnf (EL10,
# Amazon Linux 2023) or packaging/Dockerfile.suse (SLES 16, Leap 16), with
# the rustup toolchain pinned in rust-toolchain.toml on PATH (the
# distributions' own rust is older) and dependency sources fetched
# beforehand with `cargo fetch --locked`, so the build itself runs offline.

# SUSE's shared-library policy names the library package after its SONAME
# and the static archive's package -devel-static; Fedora-family
# distributions use -libs and -static.
%if 0%{?suse_version}
%global libpkg libhkdfguard1
%global staticpkg %{name}-devel-static
%else
%global libpkg %{name}-libs
%global staticpkg %{name}-static
%endif

# The library and CLI link Rust crates statically. Their notices ship in
# THIRD-PARTY-LICENSES.txt; `packaging/third-party-licenses.py --licenses`
# lists their license expressions, which this must cover.
%global linked_licenses Apache-2.0 AND BSD-3-Clause AND ISC AND MIT AND (Apache-2.0 OR MIT) AND (MIT OR Unlicense)

Name:           hkdfguard
Version:        0.9.2
Release:        1%{?dist}
Summary:        DEK wrapping under a TPM2, PKCS#11 or external-secret KEK (CLI)
License:        MPL-2.0 AND %{linked_licenses}
URL:            https://github.com/runsecure/hkdfguard-native-linux
Source0:        %{name}-%{version}.tar.gz

# tss-esapi-sys ships pregenerated bindings for these Linux targets only.
ExclusiveArch:  x86_64 aarch64

BuildRequires:  gcc
BuildRequires:  python3
BuildRequires:  pkgconfig(tss2-esys) >= 4.0
BuildRequires:  pkgconfig(tss2-mu)
BuildRequires:  pkgconfig(tss2-sys)
BuildRequires:  pkgconfig(tss2-tctildr)

# The CLI links the library code statically, but reads the same policy:
# keep the two at the same version.
Requires:       %{libpkg}%{?_isa} = %{version}-%{release}

%global common_description %{expand:
HKDFGuard wraps 32-byte Data Encryption Keys (DEKs) under a persistent,
per-service Key Encryption Key (KEK) held by the strongest provider the
host offers: a TPM 2.0, a PKCS#11 token, or an administrator-provisioned
secret file. Each DEK is wrapped with AES-256-GCM under a per-payload
key derived from the KEK with HMAC-SHA-256 (NIST SP 800-108); there is
no public-key step, so the scheme is safe against quantum computers.}

%description %{common_description}

This package contains the hkdfguard command, which provisions a
service's KEK and wraps DEKs under it at deployment time.

%package -n %{libpkg}
Summary:        DEK wrapping under a TPM2, PKCS#11 or external-secret KEK
License:        MPL-2.0 AND %{linked_licenses}
# %%pre creates the security model's groups (see packaging/hkdfguard.sysusers).
# Required by file, not package name: shadow-utils on Fedora-family
# distributions, shadow on SUSE.
Requires(pre):  /usr/bin/getent
Requires(pre):  /usr/sbin/groupadd
# %%post creates the TPM key directory when it is missing.
Requires(post): /usr/bin/install
# The group %%pre creates. SUSE's rpm turns the TPM key directory's
# %%attr group into a Requires on group(hkdfguard), so say who provides it.
Provides:       group(hkdfguard)

%description -n %{libpkg} %{common_description}

Provider selection is controlled by the root-owned policy file
/etc/hkdfguard/policy.toml, which this package does not create and the
library requires: every call fails until it exists. An annotated example
is installed as /usr/share/hkdfguard/policy.toml.example.
Unless the policy says otherwise the production security model applies:
only root creates KEKs, and only key files written by root or by a member
of the hkdfguard-deployers group, which this package creates, are trusted.

This package contains the shared library.

%package devel
Summary:        Development files for HKDFGuard
License:        MPL-2.0
Requires:       %{libpkg}%{?_isa} = %{version}-%{release}
# hkdfguard.pc's Requires.private names the tss2 modules. Required by
# module, not package name: tpm2-tss-devel on Fedora-family distributions,
# tpm2-0-tss-devel on SUSE.
Requires:       pkgconfig(tss2-esys)
Requires:       pkgconfig(tss2-mu)
Requires:       pkgconfig(tss2-sys)
Requires:       pkgconfig(tss2-tctildr)

%description devel %{common_description}

This package contains the C header and the pkg-config file.

%package -n %{staticpkg}
Summary:        Static library for HKDFGuard
License:        MPL-2.0 AND %{linked_licenses}
Requires:       %{name}-devel%{?_isa} = %{version}-%{release}

%description -n %{staticpkg} %{common_description}

This package contains the static library.

%prep
%autosetup

%build
# Keep debug info for the -debuginfo packages; Cargo.toml's release
# profile strips it, which suits the tarball release.
export CARGO_PROFILE_RELEASE_STRIP=false
export CARGO_PROFILE_RELEASE_DEBUG=line-tables-only
cargo build --locked --offline --release --all-features
python3 packaging/third-party-licenses.py target/THIRD-PARTY-LICENSES.txt

%install
# The library goes in under its SONAME (see build.rs), not Cargo's name.
install -D -m 0755 target/release/libhkdfguard.so %{buildroot}%{_libdir}/libhkdfguard.so.1
ln -s libhkdfguard.so.1 %{buildroot}%{_libdir}/libhkdfguard.so
install -D -m 0644 target/release/libhkdfguard.a %{buildroot}%{_libdir}/libhkdfguard.a
install -D -m 0644 include/hkdfguard.h %{buildroot}%{_includedir}/hkdfguard.h
install -d %{buildroot}%{_libdir}/pkgconfig
sed -e 's|@LIBDIR@|%{_libdir}|' -e 's|@VERSION@|%{version}|' \
    packaging/hkdfguard.pc.in > %{buildroot}%{_libdir}/pkgconfig/hkdfguard.pc
install -D -m 0755 target/release/hkdfguard %{buildroot}%{_bindir}/hkdfguard
install -D -m 0644 packaging/hkdfguard.1 %{buildroot}%{_mandir}/man1/hkdfguard.1
install -d -m 0755 %{buildroot}%{_sysconfdir}/hkdfguard
install -d -m 0750 %{buildroot}%{_sharedstatedir}/hkdfguard/tpm
install -D -m 0644 packaging/policy.toml.example %{buildroot}%{_datadir}/hkdfguard/policy.toml.example
install -D -m 0644 packaging/hkdfguard.sysusers %{buildroot}%{_prefix}/lib/sysusers.d/hkdfguard.conf

%check
cargo test --locked --offline
cargo test --locked --offline --all-features

# The groups in packaging/hkdfguard.sysusers, created before the files land.
# Plain groupadd rather than each distribution's sysusers macros, which
# differ between EL10, Amazon Linux 2023 and SUSE; rpm's own sysusers
# support, where it has it, finds them already there. Never removed (see
# that file for why), so there is no %%postun.
#
# A group that can't be created fails the install: the files below are
# installed for it, and under the production security model the library
# trusts hkdfguard-deployers by name.
#
# A group that is already there is adopted, as it must be on an upgrade --
# but getent answers from every NSS source, so on a first install "already
# there" may be a directory (LDAP, sssd) group of the same name, or a local
# one with members, that nobody meant to hand these roles to. That is said
# out loud. A group rpm's own sysusers support has just made is local and
# has no members, and is not remarked on.
%pre -n %{libpkg}
for group in hkdfguard hkdfguard-deployers; do
    if entry=$(getent group "$group"); then
        if [ "$1" -eq 1 ]; then
            members=${entry##*:}
            origin=
            grep -q "^$group:" /etc/group || origin=" It is not in /etc/group: it comes from a directory service."
            if [ -n "$origin" ] || [ -n "$members" ]; then
                echo "hkdfguard: WARNING: group $group already exists and is used as it is.$origin" >&2
                echo "hkdfguard:   members: ${members:-none listed (primary-group members are not shown)}" >&2
                case "$group" in
                    hkdfguard-deployers) echo "hkdfguard:   Under the production security model its members deploy key files the library trusts." >&2 ;;
                    *) echo "hkdfguard:   Its members can reach the TPM key directory." >&2 ;;
                esac
                echo "hkdfguard:   Check that every member is meant to hold that role (getent group $group)." >&2
            fi
        fi
    elif ! groupadd -r "$group"; then
        echo "hkdfguard: could not create group $group" >&2
        exit 1
    fi
done

# The TPM key directory, root:hkdfguard 0750 -- created here, only if it is
# missing, rather than installed: rpm reapplies the owner and mode of every
# file it installs on each upgrade, which would undo an administrator's
# choice (a narrower group, say) without a word. %%files lists it as
# %%ghost, so rpm still owns it but never sets its attributes.
#
# No trailing `exit 0`: a directory that couldn't be created is reported
# (rpm prints a failed %%post), not passed over in silence.
%post -n %{libpkg}
if [ ! -d %{_sharedstatedir}/hkdfguard/tpm ]; then
    install -d -m 0750 -o root -g hkdfguard %{_sharedstatedir}/hkdfguard/tpm || {
        echo "hkdfguard: could not create %{_sharedstatedir}/hkdfguard/tpm (root:hkdfguard 0750); create it before provisioning a TPM key" >&2
        exit 1
    }
fi
%if 0%{?suse_version}
# SUSE policy; Fedora-family glibc runs ldconfig from a file trigger. Here
# rather than through %%ldconfig_scriptlets, whose own %%post would be a
# second one.
%{ldconfig}
%endif

%if 0%{?suse_version}
%postun -n %{libpkg} -p %{ldconfig}
%endif

%files
%license LICENSE
%{_bindir}/hkdfguard
%{_mandir}/man1/hkdfguard.1*

%files -n %{libpkg}
%license LICENSE target/THIRD-PARTY-LICENSES.txt
%doc README.md
%{_libdir}/libhkdfguard.so.1
%dir %{_sysconfdir}/hkdfguard
# The TPM key directory: its group decides who may reach the key files
# (each key file takes it). %%ghost: %%post creates it, and rpm never resets
# its owner or mode on upgrade (see %%post). Left in place, key files and
# all, on erase.
%dir %attr(0755,root,root) %{_sharedstatedir}/hkdfguard
%ghost %dir %attr(0750,root,hkdfguard) %{_sharedstatedir}/hkdfguard/tpm
%dir %{_datadir}/hkdfguard
%{_datadir}/hkdfguard/policy.toml.example
%{_prefix}/lib/sysusers.d/hkdfguard.conf

%files devel
%{_includedir}/hkdfguard.h
%{_libdir}/libhkdfguard.so
%{_libdir}/pkgconfig/hkdfguard.pc

%files -n %{staticpkg}
%{_libdir}/libhkdfguard.a

%changelog
* Tue Nov 17 2026 runsecure <torin@torinblair.com> - 0.9.2-1
- Secrets: hkdfguard_wrap_secret, hkdfguard_unwrap_secret and
  hkdfguard_open_secret_file wrap a password (1 to 256 bytes) bound to a
  secret name; the CLI's new `protect` command writes one. The
  plaintext-key check also catches a DEK followed by CRLF. A forked child
  of a process holding ephemeral keys no longer wraps under the all-zero
  key it inherits. A provider that has gone missing while holding a
  service's KEK fails the call instead of handing it to a weaker
  provider; audit event 1006 records fallbacks. A PKCS#11 logout during a
  call is seen even when followed by a new login, and a forked child
  initializes the PKCS#11 module again for itself. TPM authValue files are
  root:<group> 0440 for the group in the new tpm.auth_groups policy table,
  else root:root 0400, never the key directory's group; provisioning always
  creates a new authValue. With no policy-allowed provider present, wrap,
  kek_exists and kek_fingerprint return PROVIDER_UNAVAILABLE (audited)
  instead of KEK_NOT_FOUND or a 0 answer. PKCS#11 keys must also be
  CKA_LOCAL and neither modifiable nor copyable to be used; every
  PIN-class login failure latches. wrap --force warns when it can't
  overwrite the file it replaces. Unwrap refuses over-long payloads before
  parsing them. The build refuses the release profile with
  --cfg hkdfguard_test_paths. The TPM key directory is created by %post
  and never reset on upgrade. File trust checks judge POSIX ACL entries
  too. Only a sticky directory on a read-only mount is exempt from the
  write-bit checks, so a plain ConfigMap volume (0777) is refused: mount
  a policy ConfigMap through a projected volume.

* Thu Oct 29 2026 runsecure <torin@torinblair.com> - 0.9.1-1
- Pre-release 0.9.1: post-quantum HMAC wrapping (payload format 1); TPM keys
  carry a per-service authValue (<service>.tpmauth) that keys session
  encryption; tpm.session_encryption is now "on" or "off"; a configured
  provider that is failing no longer hands KEKs to a weaker one; wrap
  --force replaces a key file atomically. TPM key files from 0.9.0 must be
  provisioned again.

* Fri Oct 02 2026 runsecure <torin@torinblair.com> - 0.9.0-1
- Initial packaging.
