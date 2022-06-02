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
#   File: udttpcgi.pro
#
# Author: $author$
#   Date: 6/2/2022
#
# os specific QtCreator project .pro file for framework udentity executable udttpcgi
########################################################################
#
# Debug: udentity/build/os/QtCreator/Debug/bin/udttpcgi
# Release: udentity/build/os/QtCreator/Release/bin/udttpcgi
# Profile: udentity/build/os/QtCreator/Profile/bin/udttpcgi
#
include(../../../../../build/QtCreator/udentity.pri)
include(../../../../QtCreator/udentity.pri)
include(../../udentity.pri)
include(../../../../QtCreator/app/udttpcgi/udttpcgi.pri)

TARGET = $${udttpcgi_TARGET}

########################################################################
# INCLUDEPATH
#
INCLUDEPATH += \
$${udttpcgi_INCLUDEPATH} \

# DEFINES
# 
DEFINES += \
$${udttpcgi_DEFINES} \

########################################################################
# OBJECTIVE_HEADERS
#
OBJECTIVE_HEADERS += \
$${udttpcgi_OBJECTIVE_HEADERS} \

# OBJECTIVE_SOURCES
#
OBJECTIVE_SOURCES += \
$${udttpcgi_OBJECTIVE_SOURCES} \

########################################################################
# HEADERS
#
HEADERS += \
$${udttpcgi_HEADERS} \
$${udttpcgi_OBJECTIVE_HEADERS} \

# SOURCES
#
SOURCES += \
$${udttpcgi_SOURCES} \

########################################################################
# FRAMEWORKS
#
FRAMEWORKS += \
$${udttpcgi_FRAMEWORKS} \

# LIBS
#
LIBS += \
$${udttpcgi_LIBS} \
$${FRAMEWORKS} \

########################################################################

