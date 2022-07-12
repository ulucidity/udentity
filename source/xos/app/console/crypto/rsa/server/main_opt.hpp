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
///   File: main_opt.hpp
///
/// Author: $author$
///   Date: 5/12/2022
///////////////////////////////////////////////////////////////////////
#ifndef XOS_APP_CONSOLE_CRYPTO_RSA_SERVER_MAIN_OPT_HPP
#define XOS_APP_CONSOLE_CRYPTO_RSA_SERVER_MAIN_OPT_HPP

#include "xos/app/console/crypto/rsa/main.hpp"

namespace xos {
namespace app {
namespace console {
namespace crypto {
namespace rsa {
namespace server {

/// class main_optt
template 
<class TExtends = xos::app::console::crypto::rsa::main, 
 class TImplements = typename TExtends::implements>

class exported main_optt: virtual public TImplements, public TExtends {
public:
    typedef TImplements implements;
    typedef TExtends extends;
    typedef main_optt derives;

    typedef typename extends::char_t char_t;
    typedef typename extends::end_char_t end_char_t;
    enum { end_char = extends::end_char };
    typedef typename extends::string_t string_t;
    typedef typename extends::reader_t reader_t;
    typedef typename extends::writer_t writer_t;
    typedef typename extends::file_t file_t;

    /// constructor / destructor
    main_optt()
    : run_(0), 
      key_pair_define_("XOS_APP_CONSOLE_CRYPTO_RSA_SERVER_KEY_PAIR_CONST_HPP"), 
      public_key_define_("XOS_APP_CONSOLE_CRYPTO_RSA_SERVER_PUBLIC_KEY_CONST_HPP"), 
      private_key_define_("XOS_APP_CONSOLE_CRYPTO_RSA_SERVER_PRIVATE_KEY_CONST_HPP") {
    }
    virtual ~main_optt() {
    }
private:
    main_optt(const main_optt& copy) {
        throw exception(exception_unexpected);
    }

protected:
    typedef typename extends::in_reader_t in_reader_t;
    typedef typename extends::out_writer_t out_writer_t;
    typedef typename extends::err_writer_t err_writer_t;

    /// ...run
    int (derives::*run_)(int argc, char_t** argv, char_t** env);
    virtual int run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        if ((run_)) {
            err = (this->*run_)(argc, argv, env);
        } else {
            err = extends::run(argc, argv, env);
        }
        return err;
    }

    /// ...key_..._define...
    virtual string_t &key_pair_define() const {
        return (string_t &)key_pair_define_;
    }
    virtual string_t &public_key_define() const {
        return (string_t &)public_key_define_;
    }
    virtual string_t &private_key_define() const {
        return (string_t &)private_key_define_;
    }

protected:
    string_t key_pair_define_, public_key_define_, private_key_define_; 
}; /// class main_optt
typedef main_optt<> main_opt;

} /// namespace server
} /// namespace rsa
} /// namespace crypto
} /// namespace console
} /// namespace app
} /// namespace xos

#endif /// ndef XOS_APP_CONSOLE_CRYPTO_RSA_SERVER_MAIN_OPT_HPP
