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
#   File: udttpcgicatch.pro
#
# Author: $author$
#   Date: 6/2/2022
#
# os specific QtCreator project .pro file for framework udentity executable udttpcgicatch
########################################################################
#
# Debug: udentity/build/os/QtCreator/Debug/bin/udttpcgicatch
# Release: udentity/build/os/QtCreator/Release/bin/udttpcgicatch
# Profile: udentity/build/os/QtCreator/Profile/bin/udttpcgicatch
#
include(../../../../../build/QtCreator/udentity.pri)
include(../../../../QtCreator/udentity.pri)
include(../../udentity.pri)
include(../../../../QtCreator/app/udttpcgicatch/udttpcgicatch.pri)

TARGET = $${udttpcgicatch_TARGET}

########################################################################
# INCLUDEPATH
#
INCLUDEPATH += \
$${udttpcgicatch_INCLUDEPATH} \

# DEFINES
# 
DEFINES += \
$${udttpcgicatch_DEFINES} \

########################################################################
# OBJECTIVE_HEADERS
#
OBJECTIVE_HEADERS += \
$${udttpcgicatch_OBJECTIVE_HEADERS} \

# OBJECTIVE_SOURCES
#
OBJECTIVE_SOURCES += \
$${udttpcgicatch_OBJECTIVE_SOURCES} \

########################################################################
# HEADERS
#
HEADERS += \
$${udttpcgicatch_HEADERS} \
$${udttpcgicatch_OBJECTIVE_HEADERS} \

# SOURCES
#
SOURCES += \
$${udttpcgicatch_SOURCES} \

########################################################################
# FRAMEWORKS
#
FRAMEWORKS += \
$${udttpcgicatch_FRAMEWORKS} \

# LIBS
#
LIBS += \
$${udttpcgicatch_LIBS} \
$${FRAMEWORKS} \

########################################################################

