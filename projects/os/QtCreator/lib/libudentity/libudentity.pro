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
#   File: libudentity.pro
#
# Author: $author$
#   Date: 4/2/2022
#
# os specific QtCreator project .pro file for framework udentity static library libudentity
########################################################################
#
# Debug: udentity/build/os/QtCreator/Debug/lib/libudentity
# Release: udentity/build/os/QtCreator/Release/lib/libudentity
# Profile: udentity/build/os/QtCreator/Profile/lib/libudentity
#
include(../../../../../build/QtCreator/udentity.pri)
include(../../../../QtCreator/udentity.pri)
include(../../udentity.pri)
include(../../../../QtCreator/lib/libudentity/libudentity.pri)

TARGET = $${libudentity_TARGET}
TEMPLATE = $${libudentity_TEMPLATE}
CONFIG += $${libudentity_CONFIG}

########################################################################
# INCLUDEPATH
#
INCLUDEPATH += \
$${libudentity_INCLUDEPATH} \

# DEFINES
# 
DEFINES += \
$${libudentity_DEFINES} \

########################################################################
# OBJECTIVE_HEADERS
#
OBJECTIVE_HEADERS += \
$${libudentity_OBJECTIVE_HEADERS} \

# OBJECTIVE_SOURCES
#
OBJECTIVE_SOURCES += \
$${libudentity_OBJECTIVE_SOURCES} \

########################################################################
# HEADERS
#
HEADERS += \
$${libudentity_HEADERS} \
$${libudentity_OBJECTIVE_HEADERS} \

# SOURCES
#
SOURCES += \
$${libudentity_SOURCES} \

########################################################################

