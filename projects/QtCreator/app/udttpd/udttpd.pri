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
#   File: udttpd.pri
#
# Author: $author$
#   Date: 7/13/2022
#
# generic QtCreator project .pri file for framework udentity executable udttpd
########################################################################

########################################################################
# udttpd

# udttpd TARGET
#
udttpd_TARGET = udttpd

# udttpd INCLUDEPATH
#
udttpd_INCLUDEPATH += \
$${udentity_INCLUDEPATH} \

# udttpd DEFINES
#
udttpd_DEFINES += \
$${udentity_DEFINES} \
DEFAULT_LOGGING_LEVELS_ERROR \
XOS_CONSOLE_MAIN_MAIN \

########################################################################
# udttpd OBJECTIVE_HEADERS
#
#udttpd_OBJECTIVE_HEADERS += \
#$${UDENTITY_SRC}/xos/app/console/udttpd/main.hh \

# udttpd OBJECTIVE_SOURCES
#
#udttpd_OBJECTIVE_SOURCES += \
#$${UDENTITY_SRC}/xos/app/console/udttpd/main.mm \

########################################################################
# udttpd HEADERS
#
udttpd_HEADERS += \
$${UDENTITY_SRC}/xos/app/console/network/sockets/protocol/udttp/base/main_opt.hpp \
$${UDENTITY_SRC}/xos/app/console/network/sockets/protocol/udttp/base/main.hpp \
\
$${UDENTITY_SRC}/xos/app/console/network/sockets/protocol/udttp/server/main_opt.hpp \
$${UDENTITY_SRC}/xos/app/console/network/sockets/protocol/udttp/server/main.hpp \

# udttpd SOURCES
#
udttpd_SOURCES += \
$${UDENTITY_SRC}/xos/app/console/network/sockets/protocol/udttp/server/main_opt.cpp \
$${UDENTITY_SRC}/xos/app/console/network/sockets/protocol/udttp/server/main.cpp \

########################################################################
# udttpd FRAMEWORKS
#
udttpd_FRAMEWORKS += \
$${udentity_rsa_FRAMEWORKS} \

# udttpd LIBS
#
udttpd_LIBS += \
$${udentity_rsa_LIBS} \

########################################################################
# NO Qt
QT -= gui core

