########################################################################
# Copyright (c) 1988-2022 $organization$
#
# This software is provided by the author and contributors ``as is''
# and any express or implied warranties, including, but not limited to,
# the implied warranties of merchantability and fitness for a particular
# purpose are disclaimed. In no event shall the author or contributors
# be liable for any direct, indirect, incidental, special, exemplary,
# or consequential damages (including, but not limited to, procurement
# of substitute goods or services; loss of use, data, or profits; or
# business interruption) however caused and on any theory of liability,
# whether in contract, strict liability, or tort (including negligence
# or otherwise) arising in any way out of the use of this software,
# even if advised of the possibility of such damage.
#
#   File: udentity.pri
#
# Author: $author$
#   Date: 4/2/2022, 7/13/2022
#
# os specific QtCreator project .pri file for framework udentity
########################################################################
# Repository Depends: vmachinae
# Depends: ubn;ump;urostra;unadir;ufila;ucrono;ucifra;urete;ustara;utalas;udentify

UNAME = $$system(uname)

contains(UNAME,Darwin) {
UDENTITY_OS = macosx
} else {
contains(UNAME,Linux) {
UDENTITY_OS = linux
} else {
UDENTITY_OS = windows
} # contains(UNAME,Linux)
} # contains(UNAME,Darwin)

contains(BUILD_OS,UDENTITY_OS) {
UDENTITY_BUILD = $${UDENTITY_OS}
} else {
UDENTITY_BUILD = $${BUILD_OS}
} # contains(BUILD_OS,UDENTITY_OS)

contains(BUILD_CPP_VERSION,10) {
CONFIG += c++0x
} else {
contains(BUILD_CPP_VERSION,98|03|11|14|17) {
CONFIG += c++$${BUILD_CPP_VERSION}
} else {
} # contains(BUILD_CPP_VERSION,98|03|11|14|17)
} # contains(BUILD_CPP_VERSION,10)

contains(UDENTITY_OS,macosx) {
} else {
contains(UDENTITY_OS,linux) {
QMAKE_CXXFLAGS += -fpermissive
} else {
contains(UDENTITY_OS,windows) {
} else {
} # contains(UDENTITY_OS,windows)
} # contains(UDENTITY_OS,linux)
} # contains(UDENTITY_OS,macosx)

########################################################################
# urostra
UROSTRA_THIRDPARTY_PKG_MAKE_BLD = $${UROSTRA_THIRDPARTY_PKG}/build/$${UDENTITY_BUILD}/$${BUILD_CONFIG}
UROSTRA_THIRDPARTY_PRJ_MAKE_BLD = $${OTHER_BLD}/$${UROSTRA_THIRDPARTY_PRJ}/build/$${UDENTITY_BUILD}/$${BUILD_CONFIG}
UROSTRA_THIRDPARTY_PKG_BLD = $${UROSTRA_THIRDPARTY_PKG}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
UROSTRA_THIRDPARTY_PRJ_BLD = $${OTHER_BLD}/$${UROSTRA_THIRDPARTY_PRJ}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
UROSTRA_PKG_BLD = $${OTHER_BLD}/$${UROSTRA_PKG}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
UROSTRA_PRJ_BLD = $${OTHER_BLD}/$${UROSTRA_PRJ}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
#UROSTRA_LIB = $${UROSTRA_THIRDPARTY_PKG_MAKE_BLD}/lib
#UROSTRA_LIB = $${UROSTRA_THIRDPARTY_PRJ_MAKE_BLD}/lib
#UROSTRA_LIB = $${UROSTRA_THIRDPARTY_PKG_BLD}/lib
#UROSTRA_LIB = $${UROSTRA_THIRDPARTY_PRJ_BLD}/lib
UROSTRA_LIB = $${UROSTRA_PKG_BLD}/lib
#UROSTRA_LIB = $${UROSTRA_PRJ_BLD}/lib
#UROSTRA_LIB = $${UDENTITY_LIB}
UROSTRA_LIB_NAME = $${UROSTRA_NAME}

# urostra LIBS
#
urostra_LIBS += \
-L$${UROSTRA_LIB}/lib$${UROSTRA_LIB_NAME} \
-l$${UROSTRA_LIB_NAME} \


########################################################################
# unadir
UNADIR_THIRDPARTY_PKG_MAKE_BLD = $${UNADIR_THIRDPARTY_PKG}/build/$${UDENTITY_BUILD}/$${BUILD_CONFIG}
UNADIR_THIRDPARTY_PRJ_MAKE_BLD = $${OTHER_BLD}/$${UNADIR_THIRDPARTY_PRJ}/build/$${UDENTITY_BUILD}/$${BUILD_CONFIG}
UNADIR_THIRDPARTY_PKG_BLD = $${UNADIR_THIRDPARTY_PKG}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
UNADIR_THIRDPARTY_PRJ_BLD = $${OTHER_BLD}/$${UNADIR_THIRDPARTY_PRJ}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
UNADIR_PKG_BLD = $${OTHER_BLD}/$${UNADIR_PKG}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
UNADIR_PRJ_BLD = $${OTHER_BLD}/$${UNADIR_PRJ}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
#UNADIR_LIB = $${UNADIR_THIRDPARTY_PKG_MAKE_BLD}/lib
#UNADIR_LIB = $${UNADIR_THIRDPARTY_PRJ_MAKE_BLD}/lib
#UNADIR_LIB = $${UNADIR_THIRDPARTY_PKG_BLD}/lib
#UNADIR_LIB = $${UNADIR_THIRDPARTY_PRJ_BLD}/lib
UNADIR_LIB = $${UNADIR_PKG_BLD}/lib
#UNADIR_LIB = $${UNADIR_PRJ_BLD}/lib
#UNADIR_LIB = $${UDENTITY_LIB}
UNADIR_LIB_NAME = $${UNADIR_NAME}

# unadir LIBS
#
unadir_LIBS += \
-L$${UNADIR_LIB}/lib$${UNADIR_LIB_NAME} \
-l$${UNADIR_LIB_NAME} \


########################################################################
# ufila
UFILA_THIRDPARTY_PKG_MAKE_BLD = $${UFILA_THIRDPARTY_PKG}/build/$${UDENTITY_BUILD}/$${BUILD_CONFIG}
UFILA_THIRDPARTY_PRJ_MAKE_BLD = $${OTHER_BLD}/$${UFILA_THIRDPARTY_PRJ}/build/$${UDENTITY_BUILD}/$${BUILD_CONFIG}
UFILA_THIRDPARTY_PKG_BLD = $${UFILA_THIRDPARTY_PKG}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
UFILA_THIRDPARTY_PRJ_BLD = $${OTHER_BLD}/$${UFILA_THIRDPARTY_PRJ}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
UFILA_PKG_BLD = $${OTHER_BLD}/$${UFILA_PKG}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
UFILA_PRJ_BLD = $${OTHER_BLD}/$${UFILA_PRJ}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
#UFILA_LIB = $${UFILA_THIRDPARTY_PKG_MAKE_BLD}/lib
#UFILA_LIB = $${UFILA_THIRDPARTY_PRJ_MAKE_BLD}/lib
#UFILA_LIB = $${UFILA_THIRDPARTY_PKG_BLD}/lib
#UFILA_LIB = $${UFILA_THIRDPARTY_PRJ_BLD}/lib
UFILA_LIB = $${UFILA_PKG_BLD}/lib
#UFILA_LIB = $${UFILA_PRJ_BLD}/lib
#UFILA_LIB = $${UDENTITY_LIB}
UFILA_LIB_NAME = $${UFILA_NAME}

# ufila LIBS
#
ufila_LIBS += \
-L$${UFILA_LIB}/lib$${UFILA_LIB_NAME} \
-l$${UFILA_LIB_NAME} \


########################################################################
# ucrono
UCRONO_THIRDPARTY_PKG_MAKE_BLD = $${UCRONO_THIRDPARTY_PKG}/build/$${UDENTITY_BUILD}/$${BUILD_CONFIG}
UCRONO_THIRDPARTY_PRJ_MAKE_BLD = $${OTHER_BLD}/$${UCRONO_THIRDPARTY_PRJ}/build/$${UDENTITY_BUILD}/$${BUILD_CONFIG}
UCRONO_THIRDPARTY_PKG_BLD = $${UCRONO_THIRDPARTY_PKG}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
UCRONO_THIRDPARTY_PRJ_BLD = $${OTHER_BLD}/$${UCRONO_THIRDPARTY_PRJ}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
UCRONO_PKG_BLD = $${OTHER_BLD}/$${UCRONO_PKG}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
UCRONO_PRJ_BLD = $${OTHER_BLD}/$${UCRONO_PRJ}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
#UCRONO_LIB = $${UCRONO_THIRDPARTY_PKG_MAKE_BLD}/lib
#UCRONO_LIB = $${UCRONO_THIRDPARTY_PRJ_MAKE_BLD}/lib
#UCRONO_LIB = $${UCRONO_THIRDPARTY_PKG_BLD}/lib
#UCRONO_LIB = $${UCRONO_THIRDPARTY_PRJ_BLD}/lib
UCRONO_LIB = $${UCRONO_PKG_BLD}/lib
#UCRONO_LIB = $${UCRONO_PRJ_BLD}/lib
#UCRONO_LIB = $${UDENTITY_LIB}
UCRONO_LIB_NAME = $${UCRONO_NAME}

# ucrono LIBS
#
ucrono_LIBS += \
-L$${UCRONO_LIB}/lib$${UCRONO_LIB_NAME} \
-l$${UCRONO_LIB_NAME} \


########################################################################
# ucifra
UCIFRA_THIRDPARTY_PKG_MAKE_BLD = $${UCIFRA_THIRDPARTY_PKG}/build/$${UDENTITY_BUILD}/$${BUILD_CONFIG}
UCIFRA_THIRDPARTY_PRJ_MAKE_BLD = $${OTHER_BLD}/$${UCIFRA_THIRDPARTY_PRJ}/build/$${UDENTITY_BUILD}/$${BUILD_CONFIG}
UCIFRA_THIRDPARTY_PKG_BLD = $${UCIFRA_THIRDPARTY_PKG}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
UCIFRA_THIRDPARTY_PRJ_BLD = $${OTHER_BLD}/$${UCIFRA_THIRDPARTY_PRJ}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
UCIFRA_PKG_BLD = $${OTHER_BLD}/$${UCIFRA_PKG}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
UCIFRA_PRJ_BLD = $${OTHER_BLD}/$${UCIFRA_PRJ}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
#UCIFRA_LIB = $${UCIFRA_THIRDPARTY_PKG_MAKE_BLD}/lib
#UCIFRA_LIB = $${UCIFRA_THIRDPARTY_PRJ_MAKE_BLD}/lib
#UCIFRA_LIB = $${UCIFRA_THIRDPARTY_PKG_BLD}/lib
#UCIFRA_LIB = $${UCIFRA_THIRDPARTY_PRJ_BLD}/lib
UCIFRA_LIB = $${UCIFRA_PKG_BLD}/lib
#UCIFRA_LIB = $${UCIFRA_PRJ_BLD}/lib
#UCIFRA_LIB = $${UDENTITY_LIB}
UCIFRA_LIB_NAME = $${UCIFRA_NAME}

# ucifra LIBS
#
ucifra_LIBS += \
-L$${UCIFRA_LIB}/lib$${UCIFRA_LIB_NAME} \
-l$${UCIFRA_LIB_NAME} \


########################################################################
# ubn
UBN_THIRDPARTY_PKG_MAKE_BLD = $${UBN_THIRDPARTY_PKG}/build/$${UDENTITY_BUILD}/$${BUILD_CONFIG}
UBN_THIRDPARTY_PRJ_MAKE_BLD = $${OTHER_BLD}/$${UBN_THIRDPARTY_PRJ}/build/$${UDENTITY_BUILD}/$${BUILD_CONFIG}
UBN_THIRDPARTY_PKG_BLD = $${UBN_THIRDPARTY_PKG}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
UBN_THIRDPARTY_PRJ_BLD = $${OTHER_BLD}/$${UBN_THIRDPARTY_PRJ}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
UBN_PKG_BLD = $${OTHER_BLD}/$${UBN_PKG}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
UBN_PRJ_BLD = $${OTHER_BLD}/$${UBN_PRJ}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
#UBN_LIB = $${UBN_THIRDPARTY_PKG_MAKE_BLD}/lib
#UBN_LIB = $${UBN_THIRDPARTY_PRJ_MAKE_BLD}/lib
#UBN_LIB = $${UBN_THIRDPARTY_PKG_BLD}/lib
#UBN_LIB = $${UBN_THIRDPARTY_PRJ_BLD}/lib
#UBN_LIB = $${UBN_PKG_BLD}/lib
#UBN_LIB = $${UBN_PRJ_BLD}/lib
#UBN_LIB = $${UDENTITY_LIB}
#UBN_LIB_NAME = $${UBN_NAME}
UBN_LIB = $${UCIFRA_LIB}

# ubn LIBS
#
ubn_LIBS += \
-L$${UBN_LIB}/lib$${UBN_LIB_NAME} \
-l$${UBN_LIB_NAME} \


########################################################################
# ump
UMP_THIRDPARTY_PKG_MAKE_BLD = $${UMP_THIRDPARTY_PKG}/build/$${UDENTITY_BUILD}/$${BUILD_CONFIG}
UMP_THIRDPARTY_PRJ_MAKE_BLD = $${OTHER_BLD}/$${UMP_THIRDPARTY_PRJ}/build/$${UDENTITY_BUILD}/$${BUILD_CONFIG}
UMP_THIRDPARTY_PKG_BLD = $${UMP_THIRDPARTY_PKG}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
UMP_THIRDPARTY_PRJ_BLD = $${OTHER_BLD}/$${UMP_THIRDPARTY_PRJ}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
UMP_PKG_BLD = $${OTHER_BLD}/$${UMP_PKG}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
UMP_PRJ_BLD = $${OTHER_BLD}/$${UMP_PRJ}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
#UMP_LIB = $${UMP_THIRDPARTY_PKG_MAKE_BLD}/lib
#UMP_LIB = $${UMP_THIRDPARTY_PRJ_MAKE_BLD}/lib
#UMP_LIB = $${UMP_THIRDPARTY_PKG_BLD}/lib
#UMP_LIB = $${UMP_THIRDPARTY_PRJ_BLD}/lib
#UMP_LIB = $${UMP_PKG_BLD}/lib
#UMP_LIB = $${UMP_PRJ_BLD}/lib
#UMP_LIB = $${UDENTITY_LIB}
#UMP_LIB_NAME = $${UMP_NAME}
UMP_LIB = $${UCIFRA_LIB}

# ump LIBS
#
ump_LIBS += \
-L$${UMP_LIB}/lib$${UMP_LIB_NAME}z \
-l$${UMP_LIB_NAME}z \
-L$${UMP_LIB}/lib$${UMP_LIB_NAME}n \
-l$${UMP_LIB_NAME}n \
-L$${UMP_LIB}/lib$${UMP_LIB_NAME} \
-l$${UMP_LIB_NAME} \


########################################################################
# urete
URETE_THIRDPARTY_PKG_MAKE_BLD = $${URETE_THIRDPARTY_PKG}/build/$${UDENTITY_BUILD}/$${BUILD_CONFIG}
URETE_THIRDPARTY_PRJ_MAKE_BLD = $${OTHER_BLD}/$${URETE_THIRDPARTY_PRJ}/build/$${UDENTITY_BUILD}/$${BUILD_CONFIG}
URETE_THIRDPARTY_PKG_BLD = $${URETE_THIRDPARTY_PKG}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
URETE_THIRDPARTY_PRJ_BLD = $${OTHER_BLD}/$${URETE_THIRDPARTY_PRJ}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
URETE_PKG_BLD = $${OTHER_BLD}/$${URETE_PKG}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
URETE_PRJ_BLD = $${OTHER_BLD}/$${URETE_PRJ}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
#URETE_LIB = $${URETE_THIRDPARTY_PKG_MAKE_BLD}/lib
#URETE_LIB = $${URETE_THIRDPARTY_PRJ_MAKE_BLD}/lib
#URETE_LIB = $${URETE_THIRDPARTY_PKG_BLD}/lib
#URETE_LIB = $${URETE_THIRDPARTY_PRJ_BLD}/lib
URETE_LIB = $${URETE_PKG_BLD}/lib
#URETE_LIB = $${URETE_PRJ_BLD}/lib
#URETE_LIB = $${UDENTITY_LIB}
URETE_LIB_NAME = $${URETE_NAME}

# urete LIBS
#
urete_LIBS += \
-L$${URETE_LIB}/lib$${URETE_LIB_NAME} \
-l$${URETE_LIB_NAME} \


########################################################################
# ustara
USTARA_THIRDPARTY_PKG_MAKE_BLD = $${USTARA_THIRDPARTY_PKG}/build/$${UDENTITY_BUILD}/$${BUILD_CONFIG}
USTARA_THIRDPARTY_PRJ_MAKE_BLD = $${OTHER_BLD}/$${USTARA_THIRDPARTY_PRJ}/build/$${UDENTITY_BUILD}/$${BUILD_CONFIG}
USTARA_THIRDPARTY_PKG_BLD = $${USTARA_THIRDPARTY_PKG}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
USTARA_THIRDPARTY_PRJ_BLD = $${OTHER_BLD}/$${USTARA_THIRDPARTY_PRJ}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
USTARA_PKG_BLD = $${OTHER_BLD}/$${USTARA_PKG}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
USTARA_PRJ_BLD = $${OTHER_BLD}/$${USTARA_PRJ}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
#USTARA_LIB = $${USTARA_THIRDPARTY_PKG_MAKE_BLD}/lib
#USTARA_LIB = $${USTARA_THIRDPARTY_PRJ_MAKE_BLD}/lib
#USTARA_LIB = $${USTARA_THIRDPARTY_PKG_BLD}/lib
#USTARA_LIB = $${USTARA_THIRDPARTY_PRJ_BLD}/lib
USTARA_LIB = $${USTARA_PKG_BLD}/lib
#USTARA_LIB = $${USTARA_PRJ_BLD}/lib
#USTARA_LIB = $${UDENTITY_LIB}
USTARA_LIB_NAME = $${USTARA_NAME}

# ustara LIBS
#
ustara_LIBS += \
-L$${USTARA_LIB}/lib$${USTARA_LIB_NAME} \
-l$${USTARA_LIB_NAME} \

########################################################################
# utalas
UTALAS_THIRDPARTY_PKG_MAKE_BLD = $${UTALAS_THIRDPARTY_PKG}/build/$${UDENTITY_BUILD}/$${BUILD_CONFIG}
UTALAS_THIRDPARTY_PRJ_MAKE_BLD = $${OTHER_BLD}/$${UTALAS_THIRDPARTY_PRJ}/build/$${UDENTITY_BUILD}/$${BUILD_CONFIG}
UTALAS_THIRDPARTY_PKG_BLD = $${UTALAS_THIRDPARTY_PKG}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
UTALAS_THIRDPARTY_PRJ_BLD = $${OTHER_BLD}/$${UTALAS_THIRDPARTY_PRJ}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
UTALAS_PKG_BLD = $${OTHER_BLD}/$${UTALAS_PKG}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
UTALAS_PRJ_BLD = $${OTHER_BLD}/$${UTALAS_PRJ}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
#UTALAS_LIB = $${UTALAS_THIRDPARTY_PKG_MAKE_BLD}/lib
#UTALAS_LIB = $${UTALAS_THIRDPARTY_PRJ_MAKE_BLD}/lib
#UTALAS_LIB = $${UTALAS_THIRDPARTY_PKG_BLD}/lib
#UTALAS_LIB = $${UTALAS_THIRDPARTY_PRJ_BLD}/lib
UTALAS_LIB = $${UTALAS_PKG_BLD}/lib
#UTALAS_LIB = $${UTALAS_PRJ_BLD}/lib
#UTALAS_LIB = $${UDENTITY_LIB}
UTALAS_LIB_NAME = $${UTALAS_NAME}

# utalas LIBS
#
utalas_LIBS += \
-L$${UTALAS_LIB}/lib$${UTALAS_LIB_NAME} \
-l$${UTALAS_LIB_NAME} \

########################################################################
# udentify
UDENTIFY_THIRDPARTY_PKG_MAKE_BLD = $${UDENTIFY_THIRDPARTY_PKG}/build/$${UDENTITY_BUILD}/$${BUILD_CONFIG}
UDENTIFY_THIRDPARTY_PRJ_MAKE_BLD = $${OTHER_BLD}/$${UDENTIFY_THIRDPARTY_PRJ}/build/$${UDENTITY_BUILD}/$${BUILD_CONFIG}
UDENTIFY_THIRDPARTY_PKG_BLD = $${UDENTIFY_THIRDPARTY_PKG}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
UDENTIFY_THIRDPARTY_PRJ_BLD = $${OTHER_BLD}/$${UDENTIFY_THIRDPARTY_PRJ}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
UDENTIFY_PKG_BLD = $${OTHER_BLD}/$${UDENTIFY_PKG}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
UDENTIFY_PRJ_BLD = $${OTHER_BLD}/$${UDENTIFY_PRJ}/build/$${UDENTITY_BUILD}/QtCreator/$${BUILD_CONFIG}
#UDENTIFY_LIB = $${UDENTIFY_THIRDPARTY_PKG_MAKE_BLD}/lib
#UDENTIFY_LIB = $${UDENTIFY_THIRDPARTY_PRJ_MAKE_BLD}/lib
#UDENTIFY_LIB = $${UDENTIFY_THIRDPARTY_PKG_BLD}/lib
#UDENTIFY_LIB = $${UDENTIFY_THIRDPARTY_PRJ_BLD}/lib
UDENTIFY_LIB = $${UDENTIFY_PKG_BLD}/lib
#UDENTIFY_LIB = $${UDENTIFY_PRJ_BLD}/lib
#UDENTIFY_LIB = $${UDENTITY_LIB}
UDENTIFY_LIB_NAME = $${UDENTIFY_NAME}

# udentify LIBS
#
udentify_LIBS += \
-L$${UDENTIFY_LIB}/lib$${UDENTIFY_LIB_NAME} \
-l$${UDENTIFY_LIB_NAME} \

########################################################################
# udentity

# udentity INCLUDEPATH
#
udentity_INCLUDEPATH += \

# udentity DEFINES
#
udentity_DEFINES += \

# udentity LIBS
#
contains(UDENTITY_OS,macosx|linux) {
udentity_os_LIBS += \
-lpthread \
-ldl
} else {
} # contains(UDENTITY_OS,macosx|linux)

contains(UDENTITY_OS,linux) {
udentity_os_LIBS += \
-lrt
} else {
} # contains(UDENTITY_OS,linux)

udentity_base_LIBS += \
$${udentify_LIBS} \
$${utalas_LIBS} \
$${ustara_LIBS} \
$${urete_LIBS} \
$${ucifra_LIBS} \
$${ucrono_LIBS} \
$${ufila_LIBS} \
$${unadir_LIBS} \
$${urostra_LIBS} \

udentity_LIBS += \
$${udentity_base_LIBS} \
$${build_udentity_LIBS} \
$${udentity_os_LIBS} \

udentity_rsa_LIBS += \
$${udentity_base_LIBS} \
$${ump_LIBS} \
$${ubn_LIBS} \
$${build_udentity_LIBS} \
$${udentity_os_LIBS} \
