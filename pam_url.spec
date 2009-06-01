Summary: PAM module to fetch from URL.
Name: pam_url
Version: 0
Release: 1
License: GPLv2
Group: System Environment/Base
Source: %{name}-%{version}.%{release}.tar.bz2
BuildRoot: /var/tmp/%{name}-root
Requires: pam libcurl
BuildRequires: pam-devel libcurl-devel

%description
PAM module to fetch from URL.

%prep
%setup -n %{name}

%build
make DEBUG=1 DESTDIR=%{buildroot} all

%install
make DESTDIR=%{buildroot} install
(cd %{buildroot}
find . -type f -iname '*.so' | sed 's/^\.//g' > /var/tmp/%{name}-files
cd -)

%clean
rm -rf $RPM_BUILD_ROOT

%files -f /var/tmp/%{name}-files
%defattr(-,root,root)

%changelog
* Sun May 03 2009 Sascha Thomas Spreitzer <sspreitzer@fedoraproject.org>
- First shot of rpm spec.

