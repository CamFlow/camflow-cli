Summary: CamFlow command line interface
Name: camflow-cli
Version: 0.1.13
Release: 1
Group: audit/camflow
License: GPLv2
Source: %{expand:%%(pwd)}
BuildRoot: %{_topdir}/BUILD/%{name}-%{version}-%{release}

%description
%{summary}

%prep
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/bin
cd $RPM_BUILD_ROOT
cp -f %{SOURCEURL0}/src/camflow.o ./usr/bin/camflow
%clean
rm -r -f "$RPM_BUILD_ROOT"

%files
%defattr(755,root,root)
/usr/bin/camflow
