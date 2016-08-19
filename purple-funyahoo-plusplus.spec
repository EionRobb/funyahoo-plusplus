#%%global commit0 48430a30045612d2b85d4045bff4aded9f69adcb
#%%global gittag0 GIT-TAG
#%%global shortcommit0 %(c=%{commit0}; echo ${c:0:7})
%define realname funyahoo-plusplus

Name:           purple-funyahoo-plusplus
Version:        0.1
Release:        1%{?dist}
Summary:        A replacement Yahoo prpl (protocol plugin) for Pidgin/libpurple

Group:          Applications/Internet
License:        GPLv3
URL:            https://github.com/EionRobb/funyahoo-plusplus
#git commit commit 48430a30045612d2b85d4045bff4aded9f69adcb , Fri Aug 19 09:58:29 2016 +1200
#Source0:         https://github.com/EionRobb/funyahoo-plusplus/%{name}/archive/%{commit0}.tar.gz#/%{name}-%{shortcommit0}.tar.gz
Source0:        https://github.com/EionRobb/%{realname}/archive/%{realname}-master.zip

BuildRequires:  json-glib-devel libpurple-devel
#Requires:       

%description

A replacement Yahoo prpl (protocol plugin) for Pidgin/libpurple compatible with
the new protocol enforced by Yahoo since Sept 2016

%prep
#%%autosetup -n %{name}-%{commit0}
%setup -n funyahoo-plusplus-master -q

%build
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/%{_libdir}/purple-2/
mv libyahoo-plusplus.so $RPM_BUILD_ROOT/%{_libdir}/purple-2/


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%doc README.md
%license LICENSE
%{_libdir}/purple-2/libyahoo-plusplus.so


%changelog
* Fri Aug 19 2016 Manuel Wolfshant <wolfy@fedoraproject.org> - 0.1-1
Initial package
