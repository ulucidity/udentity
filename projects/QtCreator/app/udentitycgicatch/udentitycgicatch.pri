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
#   File: udentitycgicatch.pri
#
# Author: $author$
#   Date: 4/18/2022, 7/11/2022
#
# generic QtCreator project .pri file for framework udentity executable udentitycgicatch
########################################################################

########################################################################
# udentitycgicatch

# udentitycgicatch TARGET
#
udentitycgicatch_TARGET = udentitycgicatch

# udentitycgicatch INCLUDEPATH
#
udentitycgicatch_INCLUDEPATH += \
$${udentity_INCLUDEPATH} \

# udentitycgicatch DEFINES
#
udentitycgicatch_DEFINES += \
$${udentity_DEFINES} \
DEFAULT_LOGGING_LEVELS_ERROR \
XOS_CONSOLE_MAIN_MAIN \

########################################################################
# udentitycgicatch OBJECTIVE_HEADERS
#
#udentitycgicatch_OBJECTIVE_HEADERS += \
#$${UDENTITY_SRC}/xos/app/console/udentity/cgi/catcher/main.hh \

# udentitycgicatch OBJECTIVE_SOURCES
#
#udentitycgicatch_OBJECTIVE_SOURCES += \
#$${UDENTITY_SRC}/xos/app/console/udentity/cgi/catcher/main.mm \

########################################################################
# udentitycgicatch HEADERS
#
udentitycgicatch_HEADERS += \
$${UDENTITY_SRC}/xos/app/console/network/protocol/udttp/cgi/catcher/main_opt.hpp \
$${UDENTITY_SRC}/xos/app/console/network/protocol/udttp/cgi/catcher/main.hpp \

# udentitycgicatch SOURCES
#
udentitycgicatch_SOURCES += \
$${UDENTITY_SRC}/xos/app/console/network/protocol/udttp/cgi/catcher/main_opt.cpp \
$${UDENTITY_SRC}/xos/app/console/network/protocol/udttp/cgi/catcher/main.cpp \

########################################################################
# udentitycgicatch FRAMEWORKS
#
udentitycgicatch_FRAMEWORKS += \
$${udentity_FRAMEWORKS} \

# udentitycgicatch LIBS
#
udentitycgicatch_LIBS += \
$${udentity_LIBS} \

########################################################################
# NO Qt
QT -= gui core

