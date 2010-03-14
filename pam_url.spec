Summary: PAM module to authenticate with http servers.
Name: pam_url
Version: 0.1
Release: 0%{?dist}
License: GPLv2
Group: System Environment/Base
Source: %{name}-%{version}.tar.bz2
BuildRoot: /var/tmp/%{name}-%{version}-root
Requires: pam libcurl libconfig
BuildRequires: pam-devel libcurl-devel libconfig-devel

%description
PAM module to authenticate with http servers. 
pam_url enabled you to literally form any web application that suits your ACL wishes.

%prep
%setup -n %{name}-%{version}

%build
%{__rm} -rf %{buildroot}
CFLAGS="%{optflags}" make DESTDIR=%{buildroot} all

%install
make DESTDIR=%{buildroot} install
(cd %{buildroot}
find . -type f | sed 's/^\.//g' > /var/tmp/%{name}-files
cd -)

%clean
%{__rm} -rf %{buildroot}

%files -f /var/tmp/%{name}-files
%defattr(-,root,root)

%changelog
* Sun Mar 14 2010 Sascha Thomas Spreitzer <sspreitzer@fedoraproject.org>
- Added dependency to libconfig
* Tue Jun 09 2009 Sascha Thomas Spreitzer <sspreitzer@fedoraproject.org>
- Minor changes to description and summary. 
- Changed build step to common rpm optflags.
* Sun May 03 2009 Sascha Thomas Spreitzer <sspreitzer@fedoraproject.org>
- First shot of rpm spec.

