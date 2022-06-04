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
#   File: udentity.pro
#
# Author: $author$
#   Date: 5/11/2022
#
# os specific QtCreator project .pro file for framework udentity executable udentity
########################################################################
#
# Debug: udentity/build/os/QtCreator/Debug/bin/udentity
# Release: udentity/build/os/QtCreator/Release/bin/udentity
# Profile: udentity/build/os/QtCreator/Profile/bin/udentity
#
include(../../../../../build/QtCreator/udentity.pri)
include(../../../../QtCreator/udentity.pri)
include(../../udentity.pri)
include(../../../../QtCreator/app/udentity/udentity.pri)

TARGET = $${udentity_exe_TARGET}

########################################################################
# INCLUDEPATH
#
INCLUDEPATH += \
$${udentity_exe_INCLUDEPATH} \

# DEFINES
# 
DEFINES += \
$${udentity_exe_DEFINES} \

########################################################################
# OBJECTIVE_HEADERS
#
OBJECTIVE_HEADERS += \
$${udentity_exe_OBJECTIVE_HEADERS} \

# OBJECTIVE_SOURCES
#
OBJECTIVE_SOURCES += \
$${udentity_exe_OBJECTIVE_SOURCES} \

########################################################################
# HEADERS
#
HEADERS += \
$${udentity_exe_HEADERS} \
$${udentity_exe_OBJECTIVE_HEADERS} \

# SOURCES
#
SOURCES += \
$${udentity_exe_SOURCES} \

########################################################################
# FRAMEWORKS
#
FRAMEWORKS += \
$${udentity_exe_FRAMEWORKS} \

# LIBS
#
LIBS += \
$${udentity_exe_LIBS} \
$${FRAMEWORKS} \

########################################################################

