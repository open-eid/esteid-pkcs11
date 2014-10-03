include_directories (../../)

set(LIBUTILITY_HEADERS 
  asnObject.h		asnCertificate.h
  logger.h		pkcs11module.h
  monitorThread.h	threadObj.h
  converters.h)

set(LIBUTILITY_SOURCES 
  asnObject.cpp		asnCertificate.cpp
  logger.cpp		pkcs11module.cpp
  monitorThread.cpp	threadObj.cpp
  converters.cpp)

if(WIN32)
  set(LIBUTILITY_SOURCES ${LIBUTILITY_SOURCES} pinDialog.cpp winInetObj.cpp)
  set(LIBUTILITY_HEADERS ${LIBUTILITY_HEADERS} pinDialog.h pinDialog_res.h winInetObj.h)
endif(WIN32)

if(UNIX)
  link_libraries (pthread)
endif(UNIX)

add_library (utility STATIC ${LIBUTILITY_SOURCES} ${LIBUTILITY_HEADERS}) 

install(TARGETS utility ARCHIVE DESTINATION esteidutil/lib)

