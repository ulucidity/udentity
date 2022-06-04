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
#   File: udentitycgi.pro
#
# Author: $author$
#   Date: 4/18/2022
#
# os specific QtCreator project .pro file for framework udentity executable udentitycgi
########################################################################
#
# Debug: udentity/build/os/QtCreator/Debug/bin/udentitycgi
# Release: udentity/build/os/QtCreator/Release/bin/udentitycgi
# Profile: udentity/build/os/QtCreator/Profile/bin/udentitycgi
#
include(../../../../../build/QtCreator/udentity.pri)
include(../../../../QtCreator/udentity.pri)
include(../../udentity.pri)
include(../../../../QtCreator/app/udentitycgi/udentitycgi.pri)

TARGET = $${udentitycgi_TARGET}

########################################################################
# INCLUDEPATH
#
INCLUDEPATH += \
$${udentitycgi_INCLUDEPATH} \

# DEFINES
# 
DEFINES += \
$${udentitycgi_DEFINES} \

########################################################################
# OBJECTIVE_HEADERS
#
OBJECTIVE_HEADERS += \
$${udentitycgi_OBJECTIVE_HEADERS} \

# OBJECTIVE_SOURCES
#
OBJECTIVE_SOURCES += \
$${udentitycgi_OBJECTIVE_SOURCES} \

########################################################################
# HEADERS
#
HEADERS += \
$${udentitycgi_HEADERS} \
$${udentitycgi_OBJECTIVE_HEADERS} \

# SOURCES
#
SOURCES += \
$${udentitycgi_SOURCES} \

########################################################################
# FRAMEWORKS
#
FRAMEWORKS += \
$${udentitycgi_FRAMEWORKS} \

# LIBS
#
LIBS += \
$${udentitycgi_LIBS} \
$${FRAMEWORKS} \

########################################################################

