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
#   File: udttpcgi.pri
#
# Author: $author$
#   Date: 6/2/2022
#
# generic QtCreator project .pri file for framework udentity executable udttpcgi
########################################################################

########################################################################
# udttpcgi

# udttpcgi TARGET
#
udttpcgi_TARGET = udttpcgi

# udttpcgi INCLUDEPATH
#
udttpcgi_INCLUDEPATH += \
$${udentity_INCLUDEPATH} \

# udttpcgi DEFINES
#
udttpcgi_DEFINES += \
$${udentity_DEFINES} \
DEFAULT_LOGGING_LEVELS_ERROR \
XOS_CONSOLE_MAIN_MAIN \

########################################################################
# udttpcgi OBJECTIVE_HEADERS
#
#udttpcgi_OBJECTIVE_HEADERS += \
#$${UDENTITY_SRC}/xos/app/console/network/protocol/udttp/cgi/main.hh \

# udttpcgi OBJECTIVE_SOURCES
#
#udttpcgi_OBJECTIVE_SOURCES += \
#$${UDENTITY_SRC}/xos/app/console/network/protocol/udttp/cgi/main.mm \

########################################################################
# udttpcgi HEADERS
#
udttpcgi_HEADERS += \
$${UDENTITY_SRC}/xos/app/console/network/protocol/udttp/cgi/main_opt.hpp \
$${UDENTITY_SRC}/xos/app/console/network/protocol/udttp/cgi/main.hpp \

# udttpcgi SOURCES
#
udttpcgi_SOURCES += \
$${UDENTITY_SRC}/xos/app/console/network/protocol/udttp/cgi/main_opt.cpp \
$${UDENTITY_SRC}/xos/app/console/network/protocol/udttp/cgi/main.cpp \

########################################################################
# udttpcgi FRAMEWORKS
#
udttpcgi_FRAMEWORKS += \
$${udentity_rsa_FRAMEWORKS} \

# udttpcgi LIBS
#
udttpcgi_LIBS += \
$${udentity_rsa_LIBS} \

########################################################################
# NO Qt
QT -= gui core

