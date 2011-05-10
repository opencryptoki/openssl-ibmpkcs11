#
# spec file for the IBM PKCS#11 openssl engine package
#
# Copyright (c) 2006 SUSE LINUX Products GmbH, Nuernberg, Germany.
# This file and all modifications and additions to the pristine
# package are under the same license as the package itself.
#
# Copyright (c) 2010,2011 IBM Corp.
#

Name:           openssl-ibmpkcs11
Summary:        An IBM PKCS#11 OpenSSL dynamic engine
Version:        1.0.0
Release:        0
License:        Other License(s), see package, IBM Public License
Group:          Hardware/Other
Source:         %{name}-%{version}.tar.bz2
URL:            http://sourceforge.net/projects/opencryptoki
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
BuildRequires:  openssl-devel

%description
This package contains a shared object OpenSSL dynamic engine for the use
with a PKCS#11 implementation such as openCryptoki.

%prep
%setup -n %{name}-%{version}

%build
autoreconf --force --install
export CFLAGS="$RPM_OPT_FLAGS"
export CPPFLAGS="$RPM_OPT_FLAGS"
%configure --libdir=%{_libdir}/openssl/engines
make %{?_smp_mflags}

%install
make DESTDIR=%{buildroot} install

%clean
rm -rf %{buildroot}

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-, root, root)
%doc README ChangeLog openssl.cnf.sample
%{_libdir}/openssl/engines/libibmpkcs11.*

%changelog
* Mon May 9 2011 - key@linux.vnet.ibm.com
- Updated version number, copyright

* Fri Jul 9 2010 - yoder1@us.ibm.com
- initial version
