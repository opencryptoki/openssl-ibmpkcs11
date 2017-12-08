Name:           openssl-ibmpkcs11
Summary:        An IBM PKCS#11 OpenSSL dynamic engine
Version:        1.0.1
Release:        1%{?dist}
License:        OpenSSL
Group:          System Environment/Base
Source:         https://github.com/opencryptoki/%{name}/archive/v%{version}.tar.gz
URL:            https://github.com/opencryptoki/openssl-ibmpkcs11
BuildRequires:  openssl-devel >= 0.9.8, autoconf, automake, libtool
Requires:       openssl >= 0.9.8, opencryptoki >= 3.5.0

%description
This package contains a shared object OpenSSL dynamic engine for the use
with a PKCS#11 implementation such as openCryptoki.

%prep
%setup -q

%build
autoreconf --force --install
%configure --libdir=%{_libdir}/openssl/engines
make %{?_smp_mflags}

%install
make DESTDIR=%{buildroot} install

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%doc README ChangeLog openssl.cnf.sample
%{_libdir}/openssl/engines/libibmpkcs11.*

%changelog
* Mon May 9 2011 - key@linux.vnet.ibm.com
- Updated version number, copyright

* Fri Jul 9 2010 - yoder1@us.ibm.com
- initial version
