Summary:    A supervise(daemon tools) enhancement
Name:       avalokita
Version:    #VERSION#
Release:    1
Source:     %{name}.tgz
License:    GPL
Packager:   liugao02
Group:      System Environment/Daemons
URL:        https://github.com/ops-baidu/avalokita
BuildRoot:  %{_builddir}/%{name}-root

%description
A supervise(daemon tools) enhancement, support daemonize and remote upgrade.

%prep
%setup -q

%build

%install
mkdir -p ${RPM_BUILD_ROOT}/opt/%{name}/bin
install -m 755 bin/%{name} ${RPM_BUILD_ROOT}/opt/%{name}/bin/%{name}

%files
%defattr(-,root,root,-)
/opt/%{name}/bin/%{name}
