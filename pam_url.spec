Summary: PAM module to authenticate with HTTP servers
Name: pam_url
Version: 0.1
Release: 1%{?dist}
License: GPLv2
Group: System Environment/Base
URL: https://fedorahosted.org/pam_url
Source: %{name}-%{version}.tar.bz2
Requires: pam
BuildRequires: pam-devel libcurl-devel libconfig-devel

%description
pam_url enables you to authenticate users from a Web application.

%prep
%setup -q -n %{name}-%{version}

%build
CFLAGS="%{optflags} -std=c99" make %{?_smp_mflags} all

%install
make DESTDIR=%{buildroot} install
(cd %{buildroot}
find . -type f | sed 's/^\.//g' > /var/tmp/%{name}-files
cd -)

%files -f /var/tmp/%{name}-files
%defattr(-,root,root)
%config(noreplace) /etc/pam_url.conf

%changelog
* Tue May 08 2012 Andrew Wilcox <corgi@fedorapeople.org> 0.1-1
- Bring spec up to date with current guidelines (no clean/Buildroot)
- Modified CFLAGS
- Prettified description
- Set config file path
* Sun Mar 14 2010 Sascha Thomas Spreitzer <sspreitzer@fedoraproject.org>
- Added dependency to libconfig
* Tue Jun 09 2009 Sascha Thomas Spreitzer <sspreitzer@fedoraproject.org>
- Minor changes to description and summary. 
- Changed build step to common rpm optflags.
* Sun May 03 2009 Sascha Thomas Spreitzer <sspreitzer@fedoraproject.org>
- First shot of rpm spec.

