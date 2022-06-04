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
#   File: libudentity.pri
#
# Author: $author$
#   Date: 4/2/2022, 5/11/2022
#
# generic QtCreator project .pri file for framework udentity static library libudentity
########################################################################

########################################################################
# libudentity
XOS_LIB_UDENTITY_VERSION_BUILD_DATE = 5/11/2022 #$$system(~/bin/utility/tdate)

# libudentity TARGET
#
libudentity_TARGET = udentity
libudentity_TEMPLATE = lib
libudentity_CONFIG += staticlib

# libudentity INCLUDEPATH
#
libudentity_INCLUDEPATH += \
$${udentity_INCLUDEPATH} \

# libudentity DEFINES
#
libudentity_DEFINES += \
$${udentity_DEFINES} \
DEFAULT_LOGGING_LEVELS_ERROR \
XOS_LIB_UDENTITY_VERSION_BUILD_DATE=$${XOS_LIB_UDENTITY_VERSION_BUILD_DATE} \

########################################################################
# libudentity OBJECTIVE_HEADERS
#
#libudentity_OBJECTIVE_HEADERS += \
#$${UDENTITY_SRC}/xos/lib/udentity/version.hh \

# libudentity OBJECTIVE_SOURCES
#
#libudentity_OBJECTIVE_SOURCES += \
#$${UDENTITY_SRC}/xos/lib/udentity/version.mm \

########################################################################
# libudentity HEADERS
#
libudentity_HEADERS += \
$${UDENTITY_SRC}/xos/lib/udentity/version.hpp \

# libudentity SOURCES
#
libudentity_SOURCES += \
$${UDENTITY_SRC}/xos/lib/udentity/version.cpp \

########################################################################

