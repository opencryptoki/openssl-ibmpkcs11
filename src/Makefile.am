lib_LTLIBRARIES=libibmpkcs11.la

libibmpkcs11_la_CFLAGS=-I./include

libibmpkcs11_la_LDFLAGS=@LIBS@ -lc -lpthread -ldl
libibmpkcs11_la_SOURCES=e_pkcs11.c \
			e_pkcs11_err.c \
			e_pkcs11.h \
			pkcs11f.h \
			pkcs11t.h \
			cryptoki.h \
			e_pkcs11_err.h \
			pkcs11ext.h \
			pkcs11.h \
			pkcs-11v2-20a3.h
