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
///   File: messages.hpp
///
/// Author: $author$
///   Date: 3/7/2022
///////////////////////////////////////////////////////////////////////
#ifndef XOS_PROTOCOL_UDTP_CLIENT_HELLO_MESSAGES_HPP
#define XOS_PROTOCOL_UDTP_CLIENT_HELLO_MESSAGES_HPP

#include "xos/protocol/tls/plaintext.hpp"

namespace xos {
namespace protocol {
namespace udtp {
namespace client {
namespace hello {

/// class messagest
template 
<class TPlaintext = xos::protocol::tls::plaintext, 
 class TArrays = ::talas::byte_arrays_t, 
 class TExtends = TArrays, class TImplements = typename TExtends::implements>

class exported messagest: virtual public TImplements, public TExtends {
public:
    typedef TImplements implements;
    typedef TExtends extends;
    typedef messagest derives; 
    
    typedef TPlaintext plaintext_t;
    typedef typename extends::element_t element_t;
    typedef typename extends::what_t what_t;

    /// constructors / destructor
    messagest(const what_t* elements, size_t length): extends(elements, length) {
    }
    messagest(ssize_t length): extends(length) {
    }
    messagest(const messagest& copy): extends(copy) {
    }
    messagest() {
    }
    virtual ~messagest() {
    }

    /// new_instance
    virtual plaintext_t* new_instance() {
        plaintext_t* instance = 0;
        instance = new plaintext_t;
        return instance;
    }

}; /// class messagest
typedef messagest<> messages;

} /// namespace hello
} /// namespace client
} /// namespace udtp
} /// namespace protocol
} /// namespace xos

#endif /// XOS_PROTOCOL_UDTP_CLIENT_HELLO_MESSAGES_HPP
