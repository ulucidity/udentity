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
#   File: udtpd.pro
#
# Author: $author$
#   Date: 5/13/2022
#
# os specific QtCreator project .pro file for framework udentity executable udtpd
########################################################################
#
# Debug: udentity/build/os/QtCreator/Debug/bin/udtpd
# Release: udentity/build/os/QtCreator/Release/bin/udtpd
# Profile: udentity/build/os/QtCreator/Profile/bin/udtpd
#
include(../../../../../build/QtCreator/udentity.pri)
include(../../../../QtCreator/udentity.pri)
include(../../udentity.pri)
include(../../../../QtCreator/app/udtpd/udtpd.pri)

TARGET = $${udtpd_TARGET}

########################################################################
# INCLUDEPATH
#
INCLUDEPATH += \
$${udtpd_INCLUDEPATH} \

# DEFINES
# 
DEFINES += \
$${udtpd_DEFINES} \

########################################################################
# OBJECTIVE_HEADERS
#
OBJECTIVE_HEADERS += \
$${udtpd_OBJECTIVE_HEADERS} \

# OBJECTIVE_SOURCES
#
OBJECTIVE_SOURCES += \
$${udtpd_OBJECTIVE_SOURCES} \

########################################################################
# HEADERS
#
HEADERS += \
$${udtpd_HEADERS} \
$${udtpd_OBJECTIVE_HEADERS} \

# SOURCES
#
SOURCES += \
$${udtpd_SOURCES} \

########################################################################
# FRAMEWORKS
#
FRAMEWORKS += \
$${udtpd_FRAMEWORKS} \

# LIBS
#
LIBS += \
$${udtpd_LIBS} \
$${FRAMEWORKS} \

########################################################################

