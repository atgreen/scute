Name:           scute
Version:        0.1.0
Release:        1%{?dist}
Summary:        Scute

License:        MIT
URL:            https://github.com/OWNER/scute
Source0:        scute-%{version}.tar.gz

%global debug_package %{nil}
%global _build_id_links none
%global __strip /bin/true
%global __brp_strip %{nil}
%global __brp_strip_comment_note %{nil}
%global __brp_strip_static_archive %{nil}

BuildRequires:  sbcl
BuildRequires:  gcc
BuildRequires:  make

%description
Scute - a Common Lisp application.

%prep
%autosetup

%build
make

%install
install -D -m 0755 scute %{buildroot}%{_bindir}/scute
install -D -m 0644 scute-sbom.spdx.json %{buildroot}%{_datadir}/sbom/scute-%{version}.spdx.json

%files
%license LICENSE
%doc README.md
%{_bindir}/scute
%{_datadir}/sbom/scute-%{version}.spdx.json

%changelog
-%{version}.spdx.json

%changelog
