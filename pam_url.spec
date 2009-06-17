Summary: PAM module to authenticate with http servers.
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
PAM module to authenticate with http servers. 
pam_url enabled you to literally form any web application that suits your ACL wishes.

%prep
%setup -n %{name}

%build
CFLAGS="%{optflags}" make DESTDIR=%{buildroot} all

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
* Tue Jun 09 2009 Sascha Thomas Spreitzer <sspreitzer@fedoraproject.org>
- Minor changes to description and summary. 
- Changed build step to common rpm optflags.
* Sun May 03 2009 Sascha Thomas Spreitzer <sspreitzer@fedoraproject.org>
- First shot of rpm spec.

