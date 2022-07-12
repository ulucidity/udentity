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
///   File: main.hpp
///
/// Author: $author$
///   Date: 7/1/2022
///////////////////////////////////////////////////////////////////////
#ifndef XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_HPP
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_HPP

#include "xos/app/console/network/sockets/protocol/udttp/base/main_opt.hpp"
#include "xos/protocol/udtp/base/output.hpp"

#define XOS_NETWORK_SOCKETS_PROTOCOL_UDTTP_PORT 8448

namespace xos {
namespace app {
namespace console {
namespace network {
namespace sockets {
namespace protocol {
namespace udttp {

/// enum sockets_port_t
typedef short sockets_port_t;
enum { 
    sockets_port = XOS_NETWORK_SOCKETS_PROTOCOL_UDTTP_PORT
}; /// enum port_t

namespace base {

/// class maint
template 
<class TOutput = xos::protocol::udtp::base::output, 
 class TExtends = xos::app::console::network::sockets::protocol::udttp::base::main_opt, 
 class TImplements = typename TExtends::implements>

class exported maint: virtual public TImplements, public TExtends {
public:
    typedef TImplements implements;
    typedef TExtends extends;
    typedef maint derives;

    typedef typename extends::char_t char_t;
    typedef typename extends::end_char_t end_char_t;
    enum { end_char = extends::end_char };
    typedef typename extends::string_t string_t;
    typedef typename extends::reader_t reader_t;
    typedef typename extends::writer_t writer_t;
    typedef typename extends::file_t file_t;

    /// constructor / destructor
    maint()
    : run_(0), 
      verbose_output_(false),
      accept_port_(sockets_port), connect_port_(sockets_port) {
    }
    virtual ~maint() {
    }
private:
    maint(const maint& copy) {
        throw exception(exception_unexpected);
    }

protected:
    typedef typename extends::in_reader_t in_reader_t;
    typedef typename extends::out_writer_t out_writer_t;
    typedef typename extends::err_writer_t err_writer_t;

    typedef TOutput output_t;
    typedef typename output_t::output_to_t output_to_t;

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

    /// ...output_..._key_run
    virtual int default_output_client_key_pair_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        output_t& output = this->output(); 
        output.output_client_key_pair();
        return err;
    }
    virtual int default_output_key_pair_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        output_t& output = this->output(); 
        output.output_key_pair();
        return err;
    }
    virtual int default_output_private_key_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        output_t& output = this->output(); 
        output.output_private_key();
        return err;
    }
    virtual int default_output_public_key_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        output_t& output = this->output(); 
        output.output_public_key();
        return err;
    }

    /// ...output_pseudo_random_secret_run
    virtual int default_output_pseudo_random_secret_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        output_t& output = this->output(); 
        output.output_pseudo_random_secret();
        return err;
    }
    virtual int default_output_pseudo_random_seed_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        output_t& output = this->output(); 
        output.output_pseudo_random_seed();
        return err;
    }
    virtual int default_output_master_secret_seed_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        output_t& output = this->output(); 
        output.output_master_secret_seed();
        return err;
    }
    virtual int default_output_key_expansion_seed_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        output_t& output = this->output(); 
        output.output_key_expansion_seed();
        return err;
    }

    /// on...option
    virtual int on_set_rsa_key_pair_option
    (const char_t* optarg, int argc, char_t**argv, char_t**env) {
        int err = 0;
        if ((optarg) && (optarg[0])) {
            output_t& output = this->output(); 
            output.on_set_rsa_key_pair_option(optarg);
        }
        return err;
    }
    virtual int on_set_rsa_private_key_option
    (const char_t* optarg, int argc, char_t**argv, char_t**env) {
        int err = 0;
        if ((optarg) && (optarg[0])) {
            output_t& output = this->output(); 
            output.on_set_rsa_private_key_option(optarg);
        }
        return err;
    }
    virtual int on_set_rsa_public_key_option
    (const char_t* optarg, int argc, char_t**argv, char_t**env) {
        int err = 0;
        if ((optarg) && (optarg[0])) {
            output_t& output = this->output(); 
            output.on_set_rsa_public_key_option(optarg);
        }
        return err;
    }
    virtual int on_file_input_option
    (int optval, const char_t* optarg, const char_t* optname,
     int optind, int argc, char_t**argv, char_t**env) {
        int err = 0;
        output_t& output = this->output(); 
        output.set_on_set_file_literals();
        return err;
    }
    virtual int on_string_input_option
    (int optval, const char_t* optarg, const char_t* optname,
     int optind, int argc, char_t**argv, char_t**env) {
        int err = 0;
        output_t& output = this->output(); 
        output.set_on_set_string_literals();
        return err;
    }
    virtual int on_verbose_option
    (int optval, const char_t* optarg, const char_t* optname,
     int optind, int argc, char_t**argv, char_t**env) {
        int err = 0;
        output_t& output = this->output(); 
        output.set_verbose_output(set_verbose_output(true));
        return err;
    }

    /// ...put
    virtual output_t& output() const {
        return (output_t&)output_;
    }
    virtual bool& set_verbose_output(const bool& to) {
        verbose_output_ = to;
        return verbose_output_;
    }
    virtual bool& verbose_output() const {
        return (bool&)verbose_output_;
    }

    /// ...port
    virtual short& accept_port() const {
        return (short&)accept_port_;
    }
    virtual short& connect_port() const {
        return (short&)connect_port_;
    }

protected:
    output_t output_;
    bool verbose_output_;
    short accept_port_, connect_port_;
}; /// class maint
typedef maint<> main;

} /// namespace base
} /// namespace udttp
} /// namespace protocol
} /// namespace sockets
} /// namespace network
} /// namespace console
} /// namespace app
} /// namespace xos

#endif /// ndef XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_HPP
