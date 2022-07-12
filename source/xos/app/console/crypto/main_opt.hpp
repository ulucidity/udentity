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
///   Date: 7/2/2022, 7/11/2022
///////////////////////////////////////////////////////////////////////
#ifndef XOS_APP_CONSOLE_CRYPTO_MAIN_OPT_HPP
#define XOS_APP_CONSOLE_CRYPTO_MAIN_OPT_HPP

#include "xos/app/console/udentity/version/main.hpp"
#include "xos/io/crypto/output.hpp"

#define XOS_APP_CONSOLE_CRYPTO_MAIN_FILE_INPUT_OPT "file-input"
#define XOS_APP_CONSOLE_CRYPTO_MAIN_FILE_INPUT_OPTARG_REQUIRED MAIN_OPT_ARGUMENT_NONE
#define XOS_APP_CONSOLE_CRYPTO_MAIN_FILE_INPUT_OPTARG_RESULT 0
#define XOS_APP_CONSOLE_CRYPTO_MAIN_FILE_INPUT_OPTARG ""
#define XOS_APP_CONSOLE_CRYPTO_MAIN_FILE_INPUT_OPTUSE "input from literal file"
#define XOS_APP_CONSOLE_CRYPTO_MAIN_FILE_INPUT_OPTVAL_S "f"
#define XOS_APP_CONSOLE_CRYPTO_MAIN_FILE_INPUT_OPTVAL_C 'f'
#define XOS_APP_CONSOLE_CRYPTO_MAIN_FILE_INPUT_OPTION \
   {XOS_APP_CONSOLE_CRYPTO_MAIN_FILE_INPUT_OPT, \
    XOS_APP_CONSOLE_CRYPTO_MAIN_FILE_INPUT_OPTARG_REQUIRED, \
    XOS_APP_CONSOLE_CRYPTO_MAIN_FILE_INPUT_OPTARG_RESULT, \
    XOS_APP_CONSOLE_CRYPTO_MAIN_FILE_INPUT_OPTVAL_C}, \

#define XOS_APP_CONSOLE_CRYPTO_MAIN_STRING_INPUT_OPT "string-input"
#define XOS_APP_CONSOLE_CRYPTO_MAIN_STRING_INPUT_OPTARG_REQUIRED MAIN_OPT_ARGUMENT_NONE
#define XOS_APP_CONSOLE_CRYPTO_MAIN_STRING_INPUT_OPTARG_RESULT 0
#define XOS_APP_CONSOLE_CRYPTO_MAIN_STRING_INPUT_OPTARG ""
#define XOS_APP_CONSOLE_CRYPTO_MAIN_STRING_INPUT_OPTUSE "input from literal string"
#define XOS_APP_CONSOLE_CRYPTO_MAIN_STRING_INPUT_OPTVAL_S "i"
#define XOS_APP_CONSOLE_CRYPTO_MAIN_STRING_INPUT_OPTVAL_C 'i'
#define XOS_APP_CONSOLE_CRYPTO_MAIN_STRING_INPUT_OPTION \
   {XOS_APP_CONSOLE_CRYPTO_MAIN_STRING_INPUT_OPT, \
    XOS_APP_CONSOLE_CRYPTO_MAIN_STRING_INPUT_OPTARG_REQUIRED, \
    XOS_APP_CONSOLE_CRYPTO_MAIN_STRING_INPUT_OPTARG_RESULT, \
    XOS_APP_CONSOLE_CRYPTO_MAIN_STRING_INPUT_OPTVAL_C}, \

#define XOS_APP_CONSOLE_CRYPTO_MAIN_VERBOSE_OPT "verbose"
#define XOS_APP_CONSOLE_CRYPTO_MAIN_VERBOSE_OPTARG_REQUIRED MAIN_OPT_ARGUMENT_NONE
#define XOS_APP_CONSOLE_CRYPTO_MAIN_VERBOSE_OPTARG_RESULT 0
#define XOS_APP_CONSOLE_CRYPTO_MAIN_VERBOSE_OPTARG ""
#define XOS_APP_CONSOLE_CRYPTO_MAIN_VERBOSE_OPTUSE "verbose output"
#define XOS_APP_CONSOLE_CRYPTO_MAIN_VERBOSE_OPTVAL_S "v"
#define XOS_APP_CONSOLE_CRYPTO_MAIN_VERBOSE_OPTVAL_C 'v'
#define XOS_APP_CONSOLE_CRYPTO_MAIN_VERBOSE_OPTION \
   {XOS_APP_CONSOLE_CRYPTO_MAIN_VERBOSE_OPT, \
    XOS_APP_CONSOLE_CRYPTO_MAIN_VERBOSE_OPTARG_REQUIRED, \
    XOS_APP_CONSOLE_CRYPTO_MAIN_VERBOSE_OPTARG_RESULT, \
    XOS_APP_CONSOLE_CRYPTO_MAIN_VERBOSE_OPTVAL_C}, \

#define XOS_APP_CONSOLE_CRYPTO_MAIN_OPTIONS_CHARS_EXTEND \
    XOS_APP_CONSOLE_CRYPTO_MAIN_FILE_INPUT_OPTVAL_S \
    XOS_APP_CONSOLE_CRYPTO_MAIN_STRING_INPUT_OPTVAL_S \
    XOS_APP_CONSOLE_CRYPTO_MAIN_VERBOSE_OPTVAL_S \

#define XOS_APP_CONSOLE_CRYPTO_MAIN_OPTIONS_OPTIONS_EXTEND \
    XOS_APP_CONSOLE_CRYPTO_MAIN_FILE_INPUT_OPTION \
    XOS_APP_CONSOLE_CRYPTO_MAIN_STRING_INPUT_OPTION \
    XOS_APP_CONSOLE_CRYPTO_MAIN_VERBOSE_OPTION \

#define XOS_APP_CONSOLE_CRYPTO_MAIN_OPTIONS_CHARS \
   XOS_APP_CONSOLE_CRYPTO_MAIN_OPTIONS_CHARS_EXTEND \
   XOS_APP_CONSOLE_MAIN_LOGGING_OPTIONS_CHARS

#define XOS_APP_CONSOLE_CRYPTO_MAIN_OPTIONS_OPTIONS \
   XOS_APP_CONSOLE_CRYPTO_MAIN_OPTIONS_OPTIONS_EXTEND \
   XOS_APP_CONSOLE_MAIN_LOGGING_OPTIONS_OPTIONS

#define XOS_APP_CONSOLE_CRYPTO_MAIN_ARGS 0
#define XOS_APP_CONSOLE_CRYPTO_MAIN_ARGV 0,

namespace xos {
namespace app {
namespace console {
namespace crypto {

/// class main_optt
template 
<class TOutput = xos::io::crypto::output, 
 class TExtends = xos::app::console::udentity::version::main, 
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
    main_optt(): run_(0) {
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

    typedef TOutput output_t;
    typedef typename output_t::literal_string_t literal_string_t;
    typedef typename output_t::byte_array_t byte_array_t;
    typedef typename output_t::byte_arrays_t byte_arrays_t;
    typedef typename output_t::hex_read_to_byte_array_t hex_read_to_byte_array_t;
    typedef typename output_t::hex_read_to_byte_arrays_t hex_read_to_byte_arrays_t;

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

    /// ...output_hex_run
    virtual int output_hex_run(const byte_array_t &array, int argc, char_t** argv, char_t** env) {
        int err = 0;
        output_t& output = this->output();
        output.output_hex(array);
        return err;
    }
    virtual int before_output_hex_run(byte_array_t &array, int argc, char_t** argv, char_t** env) {
        int err = 0;
        return err;
    }
    virtual int after_output_hex_run(byte_array_t &array, int argc, char_t** argv, char_t** env) {
        int err = 0;
        return err;
    }
    virtual int all_output_hex_run(byte_array_t &array, int argc, char_t** argv, char_t** env) {
        int err = 0;
        if (!(err = before_output_hex_run(array, argc, argv, env))) {
            int err2 = 0;
            err = output_hex_run(array, argc, argv, env);
            if ((err2 = after_output_hex_run(array, argc, argv, env))) {
                if (!(err)) err = err2;
            }
        }
        return err;
    }

    /// ...on_set_text_literal
    virtual int on_set_text_literal(byte_array_t &array, literal_string_t &literal, int argc, char_t** argv, char_t** env) {
        int err = 0;
        output_t& output = this->output();
        output.on_set_text_literal(array, literal);
        return err;
    }
    virtual int set_on_set_text_string_literal(int argc, char_t** argv, char_t** env) {
        int err = 0;
        output_t& output = this->output();
        output.set_on_set_text_string_literal();
        return err;
    }
    virtual int set_on_set_text_file_literal(int argc, char_t** argv, char_t** env) {
        int err = 0;
        output_t& output = this->output();
        output.set_on_set_text_file_literal();
        return err;
    }

    /// ...on_set_hex_literal
    virtual int on_set_hex_literal(byte_array_t &array, literal_string_t &literal, int argc, char_t** argv, char_t** env) {
        int err = 0;
        output_t& output = this->output();
        output.on_set_hex_literal(array, literal);
        return err;
    }
    virtual int set_on_set_hex_string_literal(int argc, char_t** argv, char_t** env) {
        int err = 0;
        output_t& output = this->output();
        output.set_on_set_hex_string_literal();
        return err;
    }
    virtual int set_on_set_hex_file_literal(int argc, char_t** argv, char_t** env) {
        int err = 0;
        output_t& output = this->output();
        output.set_on_set_hex_file_literal();
        return err;
    }

    /// ...on_set_hex_literal
    virtual int on_set_hex_literal_array(byte_arrays_t &arrays, literal_string_t &literal, int argc, char_t** argv, char_t** env) {
        int err = 0;
        output_t& output = this->output();
        output.on_set_hex_literal_array(arrays, literal);
        return err;
    }
    virtual int set_on_set_hex_string_literal_array(int argc, char_t** argv, char_t** env) {
        int err = 0;
        output_t& output = this->output();
        output.set_on_set_hex_string_literal_array();
        return err;
    }
    virtual int set_on_set_hex_file_literal_array(int argc, char_t** argv, char_t** env) {
        int err = 0;
        output_t& output = this->output();
        output.set_on_set_hex_file_literal_array();
        return err;
    }

    /// ...on_set_hex_literals
    virtual int on_set_hex_literals
    (hex_read_to_byte_arrays_t &to_arrays, 
     literal_string_t &literal, int argc, char_t** argv, char_t** env) {
        int err = 0;
        output_t& output = this->output();
        output.on_set_hex_literals(to_arrays, literal);
        return err;
    }
    virtual int set_on_set_hex_string_literals(int argc, char_t** argv, char_t** env) {
        int err = 0;
        output_t& output = this->output();
        output.set_on_set_hex_string_literals();
        return err;
    }
    virtual int set_on_set_hex_file_literals(int argc, char_t** argv, char_t** env) {
        int err = 0;
        output_t& output = this->output();
        output.set_on_set_hex_file_literals();
        return err;
    }

    /// on_set_hex_literals
    virtual int on_set_hex_literals
    (byte_array_t &a1, byte_array_t &a2, 
     literal_string_t &literal, int argc, char_t** argv, char_t** env) {
        int err = 0;
        output_t& output = this->output();
        output.on_set_hex_literals(a1, a2, literal);
        return err;
    }
    virtual int on_set_hex_literals
    (byte_array_t &a1, byte_array_t &a2, byte_array_t &a3, 
     literal_string_t &literal, int argc, char_t** argv, char_t** env) {
        int err = 0;
        output_t& output = this->output();
        output.on_set_hex_literals(a1, a2, a3, literal);
        return err;
    }
    virtual int on_set_hex_literals
    (byte_array_t &a1, byte_array_t &a2, 
     byte_array_t &a3, byte_array_t &a4, 
     literal_string_t &literal, int argc, char_t** argv, char_t** env) {
        int err = 0;
        output_t& output = this->output();
        output.on_set_hex_literals(a1, a2, a3, a4, literal);
        return err;
    }
    virtual int on_set_hex_literals
    (byte_array_t &a1, byte_array_t &a2, 
     byte_array_t &a3, byte_array_t &a4, byte_array_t &a5, 
     literal_string_t &literal, int argc, char_t** argv, char_t** env) {
        int err = 0;
        output_t& output = this->output();
        output.on_set_hex_literals(a1, a2, a3, a4, a5, literal);
        return err;
    }
    virtual int on_set_hex_literals
    (byte_array_t &a1, byte_array_t &a2, 
     byte_array_t &a3, byte_array_t &a4, 
     byte_array_t &a5, byte_array_t &a6, 
     literal_string_t &literal, int argc, char_t** argv, char_t** env) {
        int err = 0;
        output_t& output = this->output();
        output.on_set_hex_literals(a1, a2, a3, a4, a5, a6, literal);
        return err;
    }
    virtual int on_set_hex_literals
    (byte_array_t &a1, byte_array_t &a2, 
     byte_array_t &a3, byte_array_t &a4, 
     byte_array_t &a5, byte_array_t &a6, byte_array_t &a7, 
     literal_string_t &literal, int argc, char_t** argv, char_t** env) {
        int err = 0;
        output_t& output = this->output();
        output.on_set_hex_literals(a1, a2, a3, a4, a5, a6, a7, literal);
        return err;
    }

    /// ...option...
    virtual int on_file_input_option
    (int optval, const char_t* optarg, const char_t* optname,
     int optind, int argc, char_t**argv, char_t**env) {
        int err = 0;
        if (!(err = set_on_set_hex_file_literal(argc, argv, env))) {
            if (!(err = set_on_set_hex_file_literal_array(argc, argv, env))) {
                if (!(err = set_on_set_hex_file_literals(argc, argv, env))) {
                    if (!(err = set_on_set_text_file_literal(argc, argv, env))) {
                    }
                }
            }
        }
        return err;
    }
    virtual const char_t* file_input_option_usage(const char_t*& optarg, const struct option* longopt) {
        const char_t* chars = XOS_APP_CONSOLE_CRYPTO_MAIN_FILE_INPUT_OPTUSE;
        optarg = XOS_APP_CONSOLE_CRYPTO_MAIN_FILE_INPUT_OPTARG;
        return chars;
    }
    virtual int on_string_input_option
    (int optval, const char_t* optarg, const char_t* optname,
     int optind, int argc, char_t**argv, char_t**env) {
        int err = 0;
        if (!(err = set_on_set_hex_string_literal(argc, argv, env))) {
            if (!(err = set_on_set_hex_string_literal_array(argc, argv, env))) {
                if (!(err = set_on_set_hex_string_literals(argc, argv, env))) {
                    if (!(err = set_on_set_text_string_literal(argc, argv, env))) {
                    }
                }
            }
        }
        return err;
    }
    virtual const char_t* string_input_option_usage(const char_t*& optarg, const struct option* longopt) {
        const char_t* chars = XOS_APP_CONSOLE_CRYPTO_MAIN_STRING_INPUT_OPTUSE;
        optarg = XOS_APP_CONSOLE_CRYPTO_MAIN_STRING_INPUT_OPTARG;
        return chars;
    }
    virtual int on_verbose_option
    (int optval, const char_t* optarg, const char_t* optname,
     int optind, int argc, char_t**argv, char_t**env) {
        int err = 0;
        set_verbose_output(true);
        return err;
    }
    virtual const char_t* verbose_option_usage(const char_t*& optarg, const struct option* longopt) {
        const char_t* chars = XOS_APP_CONSOLE_CRYPTO_MAIN_VERBOSE_OPTUSE;
        optarg = XOS_APP_CONSOLE_CRYPTO_MAIN_VERBOSE_OPTARG;
        return chars;
    }

    /// ...option...
    virtual int on_option
    (int optval, const char_t* optarg, const char_t* optname,
     int optind, int argc, char_t**argv, char_t**env) {
        int err = 0;
        switch(optval) {

        case XOS_APP_CONSOLE_CRYPTO_MAIN_FILE_INPUT_OPTVAL_C:
            err = this->on_file_input_option(optval, optarg, optname, optind, argc, argv, env);
            break;
        case XOS_APP_CONSOLE_CRYPTO_MAIN_STRING_INPUT_OPTVAL_C:
            err = this->on_string_input_option(optval, optarg, optname, optind, argc, argv, env);
            break;

        case XOS_APP_CONSOLE_CRYPTO_MAIN_VERBOSE_OPTVAL_C:
            err = this->on_verbose_option(optval, optarg, optname, optind, argc, argv, env);
            break;

        default:
            err = extends::on_option(optval, optarg, optname, optind, argc, argv, env);
        }
        return err;
    }
    virtual const char_t* option_usage(const char_t*& optarg, const struct option* longopt) {
        const char_t* chars = "";
        switch(longopt->val) {

        case XOS_APP_CONSOLE_CRYPTO_MAIN_FILE_INPUT_OPTVAL_C:
            chars = this->file_input_option_usage(optarg, longopt);
            break;
        case XOS_APP_CONSOLE_CRYPTO_MAIN_STRING_INPUT_OPTVAL_C:
            chars = this->string_input_option_usage(optarg, longopt);
            break;

        case XOS_APP_CONSOLE_CRYPTO_MAIN_VERBOSE_OPTVAL_C:
            chars = this->verbose_option_usage(optarg, longopt);
            break;

        default:
            chars = extends::option_usage(optarg, longopt);
            break;
        }
        return chars;
    }
    virtual const char_t* options(const struct option*& longopts) {
        static const char_t* chars = XOS_APP_CONSOLE_CRYPTO_MAIN_OPTIONS_CHARS;
        static struct option optstruct[]= {
            XOS_APP_CONSOLE_CRYPTO_MAIN_OPTIONS_OPTIONS
            {0, 0, 0, 0}};
        longopts = optstruct;
        return chars;
    }

    /// ...argument...
    virtual const char_t* arguments(const char_t**& argv) {
        static const char_t* _args = XOS_APP_CONSOLE_CRYPTO_MAIN_ARGS;
        static const char_t* _argv[] = {
            XOS_APP_CONSOLE_CRYPTO_MAIN_ARGV
            0};
        argv = _argv;
        return _args;
    }

    /// ...output
    virtual bool& set_verbose_output(const bool& to) {
        output_t& output = this->output();
        bool& verbose_output = this->verbose_output();
        verbose_output = output.set_verbose_output(to);
        return verbose_output;
    }
    virtual bool& verbose_output() const {
        output_t& output = this->output();
        bool& verbose_output = output.verbose_output();
        return (bool&)verbose_output;
    }
    virtual output_t& output() const {
        return (output_t&)output_;
    }

protected:
    bool verbose_output_;
    output_t output_;
}; /// class main_optt
typedef main_optt<> main_opt;

} /// namespace crypto
} /// namespace console
} /// namespace app
} /// namespace xos

#endif /// ndef XOS_APP_CONSOLE_CRYPTO_MAIN_OPT_HPP
