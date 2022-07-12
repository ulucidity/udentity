///////////////////////////////////////////////////////////////////////
/// Copyright (c) 1988-2022 $organization$
///
/// This software is provided by the author and contributors ``as is'' 
/// and any express or implied warranties, including, but not limited to, 
/// the implied warranties of merchantability and fitness for a particular 
/// purpose are disclaimed. In no event shall the author or contributors 
/// be liable for any direct, indirect, incidental, special, exemplary, 
/// or consequential damages (including, but not limited to, procurement 
/// of substitute goods or services; loss of use, data, or profits; or 
/// business interruption) however caused and on any theory of liability, 
/// whether in contract, strict liability, or tort (including negligence 
/// or otherwise) arising in any way out of the use of this software, 
/// even if advised of the possibility of such damage.
///
///   File: default_plain_text.hpp
///
/// Author: $author$
///   Date: 5/20/2022
///////////////////////////////////////////////////////////////////////
#ifndef XOS_PROTOCOL_UDTP_SERVER_MESSAGE_DEFAULT_PLAIN_TEXT_HPP
#define XOS_PROTOCOL_UDTP_SERVER_MESSAGE_DEFAULT_PLAIN_TEXT_HPP

#include "xos/base/base.hpp"

namespace xos {
namespace protocol {
namespace udtp {
namespace server {
namespace message {

const char default_plain_text[] 
= "{\n" \
  "    \"password\": {\n" \
  "        \"user\": \"unknown@unknown.unknown.unknown\",\n" \
  "        \"resource\": \"unknown://unknown.unknown.unknown:unknown/unknown/\",\n" \
  "        \"password\": \"unknown\"\n" \
  "        \"passtoken\": \"unknown\"\n" \
  "        \"passkey\": \"unknown\"\n" \
  "    }\n" \
  "}\n";

} /// namespace message
} /// namespace server
} /// namespace udtp
} /// namespace protocol
} /// namespace xos

#endif /// ndef XOS_PROTOCOL_UDTP_SERVER_MESSAGE_DEFAULT_PLAIN_TEXT_HPP
