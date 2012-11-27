Summary:        PAM module to authenticate with HTTP servers
Name:           pam_url
Version:        0.2
Release:        1%{?dist}
Epoch:          1
License:        GPLv2
Group:          System Environment/Base
URL:            https://fedorahosted.org/pam_url
Source:         %{name}-%{version}.tar.bz2
Requires:       pam
BuildRequires:  pam-devel, libcurl-devel, libconfig-devel

%description
The pam_url module enables you to authenticate users against a Web application,
such as totpcgi.

%prep
%setup -q

%build
CFLAGS="%{optflags} -std=c99" make %{?_smp_mflags} all

%install
make DESTDIR=%{buildroot} install

%files
%defattr(-,root,root,-)
%doc AUTHOR COPYING INSTALL README examples
%config(noreplace) %{_sysconfdir}/pam_url.conf
/%{_lib}/security/pam_url.so


%changelog
* Mon Nov 19 2012 Konstantin Ryabitsev <icon@fedoraproject.org> - 0.2-1
- Prepare for 0.2 release
- Set the epoch to 1 to solve branching issues with other releases
- Add doc files

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

