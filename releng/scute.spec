Name:           scute
Version:        0.1.0
Release:        1%{?dist}
Summary:        Run one command inside a deny-by-default Linux sandbox

License:        MIT
URL:            https://github.com/atgreen/scute
Source0:        scute-%{version}.tar.gz

# Disable debug packages and stripping since this is a Lisp binary with dumped image
%global debug_package %{nil}
%global _build_id_links none
%global __strip /bin/true
%global __brp_strip %{nil}
%global __brp_strip_comment_note %{nil}
%global __brp_strip_static_archive %{nil}

BuildRequires:  sbcl
BuildRequires:  ocicl
BuildRequires:  gcc
BuildRequires:  make


%description
Scute runs one local command inside a deny-by-default Linux sandbox built from
Landlock, namespaces, seccomp, and cgroup v2. It is a native sandbox rather
than a container or a virtual machine: one executable, no privileged daemon,
and a parent that establishes every requested control before it releases the
child that becomes the command. A host that cannot provide a control the
policy asks for gets an error instead of a weaker sandbox.

Scute shares the host kernel and does not claim to contain kernel exploits.

%prep
%autosetup

%build
# Dependencies are vendored in the source tarball
make
make sbom
make completions

%install
install -D -m 0755 scute %{buildroot}%{_bindir}/scute
install -D -m 0644 scute-sbom.spdx.json %{buildroot}%{_datadir}/sbom/scute-%{version}.spdx.json
%{_datadir}/bash-completion/completions/scute
%{_datadir}/zsh/site-functions/_scute
%{_datadir}/fish/vendor_completions.d/scute.fish
install -D -m 0644 completions/scute.bash %{buildroot}%{_datadir}/bash-completion/completions/scute
install -D -m 0644 completions/_scute %{buildroot}%{_datadir}/zsh/site-functions/_scute
install -D -m 0644 completions/scute.fish %{buildroot}%{_datadir}/fish/vendor_completions.d/scute.fish

%files
%license LICENSE
%doc README.md
%{_bindir}/scute
%{_datadir}/sbom/scute-%{version}.spdx.json
%{_datadir}/bash-completion/completions/scute
%{_datadir}/zsh/site-functions/_scute
%{_datadir}/fish/vendor_completions.d/scute.fish

%changelog
* Thu Sep 17 2026 Anthony Green <green@moxielogic.com> - 0.1.0-1
- Initial RPM package for scute
