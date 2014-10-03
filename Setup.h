#ifdef _WIN64
#define PKG_BIT " ( 64-bit )"
#else
#define PKG_BIT ""
#endif
#ifdef _DEBUG
#define PKG_BUILD " ( debug )"
#else
#define PKG_BUILD ""
#endif

/* Define to the full name of this package. */
#define PACKAGE_NAME "EstEID PKCS#11" PKG_BIT PKG_BUILD

#define PACKAGE_VER_MAJOR 0
#define PACKAGE_VER_MINOR 1
#define PACKAGE_BUILD 7

/* rc version */
#define RC_VERSION PACKAGE_VER_MAJOR,PACKAGE_VER_MINOR,PACKAGE_BUILD

/* Define to the version of this package. */
#define PACKAGE_VERSION "0.1.7"

/* Name of package */
#define PACKAGE "esteidpkcs11.dll"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING PACKAGE_NAME " " PACKAGE_VERSION
