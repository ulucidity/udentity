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
#   Date: 5/11/2022
#
# generic QtCreator project .pri file for framework udentity executable udentity
########################################################################

########################################################################
# udentity

# udentity_exe TARGET
#
udentity_exe_TARGET = udentity

# udentity_exe INCLUDEPATH
#
udentity_exe_INCLUDEPATH += \
$${udentity_INCLUDEPATH} \

# udentity_exe DEFINES
#
udentity_exe_DEFINES += \
$${udentity_DEFINES} \
DEFAULT_LOGGING_LEVELS_ERROR \
XOS_CONSOLE_MAIN_MAIN \

########################################################################
# udentity_exe OBJECTIVE_HEADERS
#
#udentity_exe_OBJECTIVE_HEADERS += \
#$${UDENTITY_SRC}/xos/app/console/udentity/version/main.hh \

# udentity_exe OBJECTIVE_SOURCES
#
#udentity_exe_OBJECTIVE_SOURCES += \
#$${UDENTITY_SRC}/xos/app/console/udentity/version/main.mm \

########################################################################
# udentity_exe HEADERS
#
udentity_exe_HEADERS += \
$${UDENTITY_SRC}/xos/app/console/udentity/version/main_opt.hpp \
$${UDENTITY_SRC}/xos/app/console/udentity/version/main.hpp \

# udentity_exe SOURCES
#
udentity_exe_SOURCES += \
$${UDENTITY_SRC}/xos/app/console/udentity/version/main_opt.cpp \
$${UDENTITY_SRC}/xos/app/console/udentity/version/main.cpp \

########################################################################
# udentity_exe FRAMEWORKS
#
udentity_exe_FRAMEWORKS += \
$${udentity_FRAMEWORKS} \

# udentity_exe LIBS
#
udentity_exe_LIBS += \
$${udentity_LIBS} \

########################################################################
# NO Qt
QT -= gui core

