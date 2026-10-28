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
Version:        0.9.0
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
# The group %%pre creates. SUSE's rpm turns the TPM key directory's
# %%attr group into a Requires on group(hkdfguard), so say who provides it.
Provides:       group(hkdfguard)

%description -n %{libpkg} %{common_description}

Provider selection is controlled by the root-owned policy file
/etc/hkdfguard/policy.toml, which this package does not create; an
annotated example is installed as /usr/share/hkdfguard/policy.toml.example.
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
%pre -n %{libpkg}
for group in hkdfguard hkdfguard-deployers; do
    getent group "$group" >/dev/null || groupadd -r "$group"
done
exit 0

%if 0%{?suse_version}
# SUSE policy; Fedora-family glibc runs ldconfig from a file trigger.
%ldconfig_scriptlets -n %{libpkg}
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
# The TPM key directory: its group decides who may use TPM keys (each key
# file takes it). %%pre creates the group before this lands. Left in place,
# key files and all, on erase.
%dir %attr(0755,root,root) %{_sharedstatedir}/hkdfguard
%dir %attr(0750,root,hkdfguard) %{_sharedstatedir}/hkdfguard/tpm
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
* Fri Oct 02 2026 runsecure <torin@torinblair.com> - 0.9.0-1
- Initial packaging.
