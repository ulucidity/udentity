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
///   File: output.hpp
///
/// Author: $author$
///   Date: 3/15/2022
///////////////////////////////////////////////////////////////////////
#ifndef XOS_APP_CONSOLE_NETWORK_PROTOCOL_HTTP_CGI_OUTPUT_HPP
#define XOS_APP_CONSOLE_NETWORK_PROTOCOL_HTTP_CGI_OUTPUT_HPP

#include "xos/app/console/network/protocol/http/cgi/main.hpp"
#include "xos/io/output.hpp"

namespace xos {
namespace app {
namespace console {
namespace network {
namespace protocol {
namespace http {
namespace cgi {

/// class outputt
template 
<class TCgiMain = xos::app::console::network::protocol::http::cgi::main,
 class TExtendsOutput = xos::io::extended::output, 
 class TExtends = TExtendsOutput, class TImplements = typename TExtends::implements>

class exported outputt: virtual public TImplements, public TExtends {
public:
    typedef TImplements implements;
    typedef TExtends extends;
    typedef outputt derives; 
    
    typedef TCgiMain cgi_main_t;
    typedef typename extends::output_t output_t;
    typedef typename implements::string_t string_t;
    typedef typename implements::char_t char_t;
    typedef typename implements::end_char_t end_char_t;
    enum { end_char = implements::end_char };

    typedef char_t what_t;
    typedef char_t sized_t;
    
    /// constructors / destructor
    outputt(cgi_main_t& cgi_main): cgi_main_(cgi_main) {
    }
    virtual ~outputt() {
    }
private:
    outputt(const outputt& copy): cgi_main_(copy.cgi_main_) {
        throw exception(exception_unexpected);
    }
public:

    /// out
    using implements::out;
    virtual ssize_t out(const what_t *what, size_t length) {
        ssize_t count = 0;
        const char_t* chars = 0;

        if ((chars = (const char_t*)what) && (length)) {
            cgi_main_t& cgi_main = this->cgi_main();
            int err = 0;
            
            if (!(err = cgi_main.out(chars, length))) {
                count = length;
            }
        }
        return count;
    }

    /// cgi_main
    virtual cgi_main_t& cgi_main() const {
        return (cgi_main_t&)cgi_main_;
    }

protected:
    cgi_main_t &cgi_main_;
}; /// class outputt
typedef outputt<> output;

} /// namespace cgi
} /// namespace http
} /// namespace protocol
} /// namespace network
} /// namespace console
} /// namespace app
} /// namespace xos

#endif /// XOS_APP_CONSOLE_NETWORK_PROTOCOL_HTTP_CGI_OUTPUT_HPP
