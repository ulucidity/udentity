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
#   File: udtp.pri
#
# Author: $author$
#   Date: 5/12/2022, 6/20/2022
#
# generic QtCreator project .pri file for framework udentity executable udtp
########################################################################

########################################################################
# udtp

# udtp TARGET
#
udtp_TARGET = udtp

# udtp INCLUDEPATH
#
udtp_INCLUDEPATH += \
$${udentity_INCLUDEPATH} \

# udtp DEFINES
#
udtp_DEFINES += \
$${udentity_DEFINES} \
DEFAULT_LOGGING_LEVELS_ERROR \
XOS_CONSOLE_MAIN_MAIN \

########################################################################
# udtp OBJECTIVE_HEADERS
#
#udtp_OBJECTIVE_HEADERS += \
#$${UDENTITY_SRC}/xos/app/console/protocol/udtp/main.hh \

# udtp OBJECTIVE_SOURCES
#
#udtp_OBJECTIVE_SOURCES += \
#$${UDENTITY_SRC}/xos/app/console/protocol/udtp/main.mm \

########################################################################
# udtp HEADERS
#
udtp_HEADERS += \
$${UTLS_SRC}/xos/protocol/tls/content/type.hpp \
$${UTLS_SRC}/xos/protocol/tls/bulk/cipher/algorithm.hpp \
$${UTLS_SRC}/xos/protocol/tls/hash/algorithm/code.hpp \
$${UTLS_SRC}/xos/protocol/tls/signature/algorithm/code.hpp \
$${UTLS_SRC}/xos/protocol/tls/signature/hash/algorithm/code.hpp \
$${UTLS_SRC}/xos/protocol/tls/encrypted/premaster/secret.hpp \
$${UTLS_SRC}/xos/protocol/tls/key/exchange/algorithm.hpp \
$${UTLS_SRC}/xos/protocol/tls/client/key/exchange/message.hpp \
$${UTLS_SRC}/xos/protocol/tls/server/key/exchange/message.hpp \
\
$${UDENTITY_SRC}/xos/protocol/udtp/base/output.hpp \
$${UDENTITY_SRC}/xos/protocol/udtp/server/output.hpp \
\
$${UDENTITY_SRC}/xos/app/console/protocol/udtp/base/main_opt.hpp \
$${UDENTITY_SRC}/xos/app/console/protocol/udtp/base/main.hpp \
$${UDENTITY_SRC}/xos/app/console/protocol/udtp/server/main_opt.hpp \
$${UDENTITY_SRC}/xos/app/console/protocol/udtp/server/main.hpp \
\
$${UDENTIFY_SRC}/xos/protocol/udtp/client/output.hpp \
\
$${UDENTIFY_SRC}/xos/app/console/protocol/udtp/client/main_opt.hpp \
$${UDENTIFY_SRC}/xos/app/console/protocol/udtp/client/main.hpp \

# udtp SOURCES
#
udtp_SOURCES += \
$${UTLS_SRC}/xos/protocol/tls/content/type.cpp \
$${UTLS_SRC}/xos/protocol/tls/signature/hash/algorithm/code.cpp \
$${UTLS_SRC}/xos/protocol/tls/key/exchange/algorithm.cpp \
$${UTLS_SRC}/xos/protocol/tls/server/key/exchange/message.cpp \
\
$${UDENTIFY_SRC}/xos/protocol/udtp/client/output.cpp \
\
$${UDENTIFY_SRC}/xos/app/console/protocol/udtp/client/main_opt.cpp \
$${UDENTIFY_SRC}/xos/app/console/protocol/udtp/client/main.cpp \

########################################################################
# udtp FRAMEWORKS
#
udtp_FRAMEWORKS += \
$${udentity_FRAMEWORKS} \

# udtp LIBS
#
udtp_LIBS += \
$${udentity_rsa_LIBS} \

########################################################################
# NO Qt
QT -= gui core

