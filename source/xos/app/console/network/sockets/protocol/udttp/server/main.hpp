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
#ifndef XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_SERVER_MAIN_HPP
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_SERVER_MAIN_HPP

#include "xos/app/console/network/sockets/protocol/udttp/server/main_opt.hpp"
#include "xos/io/string/output.hpp"

namespace xos {
namespace app {
namespace console {
namespace network {
namespace sockets {
namespace protocol {
namespace udttp {
namespace server {

/// class maint
template 
<class TStringOutput = xos::io::string::output,
 class TExtends = xos::app::console::network::sockets::protocol::udttp::server::main_opt, 
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
    maint(): run_(0), process_response_to_any_(0) {
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

    typedef typename extends::output_t output_t;
    typedef typename extends::output_to_t output_to_t;
    typedef TStringOutput string_output_t;

    typedef typename extends::content_t content_t;
    typedef typename extends::response_t response_t;
    typedef typename extends::request_method_t request_method_t;
    typedef typename extends::request_t request_t;

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

    /// ...process_response_to_any...
    int (derives::*process_response_to_any_)
    (writer_t& writer, response_t& response, 
     request_t& request, reader_t& reader, int argc, char_t** argv, char** env);
    virtual int process_response_to_any
    (writer_t& writer, response_t& response, 
     request_t& request, reader_t& reader, int argc, char_t** argv, char** env) {
        int err = 0;
        if (process_response_to_any_) {
            err = (this->*process_response_to_any_)(writer, response, request, reader, argc, argv, env);
        } else {
            err = extends::process_response_to_any(writer, response, request, reader, argc, argv, env);
        }
        return err;
    }

    /// ...generate_server_hello_process_response_to_any
    virtual int generate_server_hello_process_response_to_any
    (writer_t& writer, response_t& response, 
     request_t& request, reader_t& reader, int argc, char_t** argv, char** env) {
        int err = 0;
        const content_t& request_content = this->request_content();
        const char_t* chars = 0; size_t length = 0;

        if ((chars = request_content.has_chars(length))) {
            output_t& output = this->output();
            const bool output_verbose = output.verbose_output(),
                       verbose_output = this->verbose_output();
            
            output.set_verbose_output(verbose_output);
            output.unset_on_set_file_literals();
            if (!(err = output.on_set_client_hello_option(chars, length))) {
                string_output_t string_output(content_string_);
                output_to_t* old_output = output.set_output_to(&string_output);

                content_string_.clear();
                if (!(err = output.output_client_hello_messages())) {
                    const char_t* chars = 0; size_t length = 0;
                    
                    if ((chars = content_string_.has_chars(length))) {
                        this->all_set_content(chars, argc, argv, env);
                    }
                }
                output.set_output_to(old_output);
            }
            output.set_verbose_output(output_verbose);
        } else {
            err = extends::process_response_to_any(writer, response, request, reader, argc, argv, env);
        }
        return err;
    }
    virtual int set_generate_server_hello_pprocess_response_to_any(int argc, char_t** argv, char_t** env) {
        int err = 0;
        process_response_to_any_ = &derives::generate_server_hello_process_response_to_any;
        return err;
    }

    /// ...server_hello_process_response_to_any
    virtual int server_hello_process_response_to_any
    (writer_t& writer, response_t& response, 
     request_t& request, reader_t& reader, int argc, char_t** argv, char** env) {
        int err = 0;
        output_t &output = this->output();
        string_output_t string_output(content_string_);
        output_to_t* old_output = output.set_output_to(&string_output);

        content_string_.clear();
        if (!(err = output.output_server_hello_messages())) {
            const char_t* chars = 0; size_t length = 0;
            
            if ((chars = content_string_.has_chars(length))) {
                this->all_set_content(chars, argc, argv, env);
            }
        }
        output.set_output_to(old_output);
        return err;
    }
    virtual int set_server_hello_pprocess_response_to_any(int argc, char_t** argv, char_t** env) {
        int err = 0;
        process_response_to_any_ = &derives::server_hello_process_response_to_any;
        return err;
    }

    /// ...client_hello_process_response_to_any
    virtual int client_hello_process_response_to_any
    (writer_t& writer, response_t& response, 
     request_t& request, reader_t& reader, int argc, char_t** argv, char** env) {
        int err = 0;
        err = extends::process_response_to_any(writer, response, request, reader, argc, argv, env);
        return err;
    }
    virtual int set_client_hello_pprocess_response_to_any(int argc, char_t** argv, char_t** env) {
        int err = 0;
        process_response_to_any_ = &derives::client_hello_process_response_to_any;
        return err;
    }

    /// ...output_generate_server_hello_run
    virtual int set_output_generate_server_hello_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        err = set_generate_server_hello_pprocess_response_to_any(argc, argv, env);
        return err;
    }

    /// ...output_server_hello_run
    virtual int set_output_server_hello_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        err = set_server_hello_pprocess_response_to_any(argc, argv, env);
        return err;
    }

    /// ...output_client_hello_run
    virtual int set_output_client_hello_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        err = set_client_hello_pprocess_response_to_any(argc, argv, env);
        return err;
    }

    /// ...option...
    virtual int on_set_server_hello_message_option(const char_t* optarg, int argc, char_t**argv, char_t**env) {
        int err = 0;
        if ((optarg) && (optarg[0])) {
            output_t& output = this->output(); 
            const bool output_verbose = output.verbose_output(), 
                  verbose_output = this->verbose_output(); 

            output.set_verbose_output(verbose_output);
            if (!(err = output.on_set_server_hello_message_option(optarg))) {
            }
            output.set_verbose_output(output_verbose);
        }
        return err;
    }
    virtual int on_set_server_hello_option(const char_t* optarg, int argc, char_t**argv, char_t**env) {
        int err = 0;
        if ((optarg) && (optarg[0])) {
            output_t& output = this->output(); 
            const bool output_verbose = output.verbose_output(), 
                  verbose_output = this->verbose_output(); 

            output.set_verbose_output(verbose_output);
            if (!(err = output.on_set_server_hello_option(optarg))) {
            }
            output.set_verbose_output(output_verbose);
        }
        return err;
    }
    virtual int on_set_client_hello_option(const char_t* optarg, int argc, char_t**argv, char_t**env) {
        int err = 0;
        if ((optarg) && (optarg[0])) {
            output_t& output = this->output(); 
            const bool output_verbose = output.verbose_output(), 
                  verbose_output = this->verbose_output(); 

            output.set_verbose_output(verbose_output);
            if (!(err = output.on_set_client_hello_option(optarg))) {
            }
            output.set_verbose_output(output_verbose);
        }
        return err;
    }
    virtual int on_client_key_exchange_only_option
    (int optval, const char_t* optarg, const char_t* optname,
     int optind, int argc, char_t**argv, char_t**env) {
        int err = 0;
        output_t& output = this->output(); 
        output.set_expect_client_key_exchange_only();
        return err;
    }

protected:
    string_t content_string_;
}; /// class maint
typedef maint<> main;

} /// namespace server
} /// namespace udttp
} /// namespace protocol
} /// namespace sockets
} /// namespace network
} /// namespace console
} /// namespace app
} /// namespace xos

#endif /// ndef XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_SERVER_MAIN_HPP
