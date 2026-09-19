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

# Opened by name at runtime rather than linked, so the automatic dependency
# generator cannot see it: without this the package installs and then refuses
# to launch anything.
Requires:       libseccomp

# KeyFence is not an optional companion: a policy that says nothing about the
# network is routed through it, which is how a sandbox uses a credential it never
# holds.  A policy with [network] mode = "none" needs no broker, and that is the
# only configuration this dependency is not required for.
Requires:       keyfence


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
make man

%install
install -D -m 0755 scute %{buildroot}%{_bindir}/scute
install -D -m 0644 scute-sbom.spdx.json %{buildroot}%{_datadir}/sbom/scute-%{version}.spdx.json
%{_datadir}/bash-completion/completions/scute
%{_datadir}/zsh/site-functions/_scute
%{_datadir}/fish/vendor_completions.d/scute.fish
%{_mandir}/man1/scute.1*
install -D -m 0644 completions/scute.bash %{buildroot}%{_datadir}/bash-completion/completions/scute
install -D -m 0644 completions/_scute %{buildroot}%{_datadir}/zsh/site-functions/_scute
install -D -m 0644 completions/scute.fish %{buildroot}%{_datadir}/fish/vendor_completions.d/scute.fish
%{_mandir}/man1/scute.1*
install -D -m 0644 man/scute.1 %{buildroot}%{_mandir}/man1/scute.1

# The policies Scute ships for the agents people run.  On the search path
# "scute run --policy NAME" uses, so an installed policy is one you can run by
# name; a copy in ~/.config/scute/policies outranks it, so editing one is not
# something an upgrade undoes.
for policy in policies/*.policy; do
  install -D -m 0644 "$policy" \
    %{buildroot}%{_datadir}/scute/policies/"$(basename "$policy")"
done

%files
%license LICENSE
%doc README.md
# CAP_BPF and CAP_NET_ADMIN, so that the default network is the kernel redirect
# rather than the port-level fallback: with them, every web connection a sandbox
# makes has its destination rewritten to the broker, and a client that ignores the
# proxy variables arrives there anyway instead of failing.
#
# This is a capability on a binary many people will have installed, so what it is
# used for is worth being exact about. Scute loads one BPF program, which it
# compiles itself from forms in its own source, attaches it to a cgroup it created,
# and then drops every capability it holds -- CapEff, CapPrm, CapInh and CapAmb all
# verified empty -- before the sandboxed child exists at all. The child never has
# them, and neither does Scute by the time it is running anything of yours.
#
# Refusing this and keeping the fallback is one line: setcap -r %{_bindir}/scute.
%caps(cap_bpf,cap_net_admin=ep) %{_bindir}/scute
%{_datadir}/sbom/scute-%{version}.spdx.json
%{_datadir}/bash-completion/completions/scute
%{_datadir}/zsh/site-functions/_scute
%{_datadir}/fish/vendor_completions.d/scute.fish
%{_mandir}/man1/scute.1*
%{_datadir}/scute/policies/*.policy

%changelog
* Thu Sep 17 2026 Anthony Green <green@moxielogic.com> - 0.1.0-1
- Initial RPM package for scute
