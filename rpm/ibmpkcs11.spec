%global enginesdir %(pkg-config --variable=enginesdir libcrypto)

Name:           openssl-ibmpkcs11
Version:        1.0.1
Release:        1%{?dist}
Summary:        An IBM PKCS#11 OpenSSL dynamic engine

License:        OpenSSL
URL:            https://github.com/opencryptoki/openssl-ibmpkcs11
Source:         https://github.com/opencryptoki/%{name}/archive/v%{version}/%{name}-%{version}.tar.gz

BuildRequires:  autoconf automake libtool
BuildRequires:  openssl-devel >= 0.9.8
Requires:       openssl >= 0.9.8, opencryptoki-libs%{?_isa}


%description
This package contains a shared object OpenSSL dynamic engine for the use
with a PKCS#11 implementation such as openCryptoki.

%prep
%setup -q -n %{name}-%{version}

./bootstrap.sh

%build
%configure --libdir=%{enginesdir}
%make_build

%install
%make_install
mv openssl.cnf.sample openssl.cnf.sample.%{_arch}
rm -f $RPM_BUILD_ROOT%{enginesdir}/*.la


%files
%license LICENSE
%doc README openssl.cnf.sample.%{_arch}
%{enginesdir}/ibmpkcs11.so

%changelog
* Mon May 9 2011 - key@linux.vnet.ibm.com
- Updated version number, copyright

* Fri Jul 9 2010 - yoder1@us.ibm.com
- initial version
