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
///   Date: 7/2/2022
///////////////////////////////////////////////////////////////////////
#ifndef XOS_PROTOCOL_UDTP_BASE_OUTPUT_HPP
#define XOS_PROTOCOL_UDTP_BASE_OUTPUT_HPP

#include "xos/protocol/tls/crypto/output.hpp"

#include "xos/protocol/tls/protocol/version.hpp"

#include "xos/protocol/tls/pseudo/random/reader.hpp"
#include "xos/protocol/tls/gmt/unix/time.hpp"
#include "xos/protocol/tls/random/bytes.hpp"

#include "xos/protocol/tls/hello/random.hpp"
#include "xos/protocol/tls/session/identifier.hpp"
#include "xos/protocol/tls/cipher/suite.hpp"
#include "xos/protocol/tls/cipher/suites.hpp"
#include "xos/protocol/tls/compression/method.hpp"
#include "xos/protocol/tls/compression/methods.hpp"
#include "xos/protocol/tls/client/hello.hpp"

#include "xos/protocol/tls/premaster/secret/random.hpp"
#include "xos/protocol/tls/premaster/secret/message.hpp"
#include "xos/protocol/tls/pkcs1/encoded/message.hpp"
#include "xos/protocol/tls/pkcs1/encoded/premaster/secret.hpp"

#include "xos/protocol/tls/rsa/public_key.hpp"
#include "xos/protocol/tls/rsa/bn/public_key.hpp"
#include "xos/protocol/tls/rsa/gmp/public_key.hpp"
#include "xos/protocol/tls/rsa/implemented/public_key.hpp"
#include "xos/protocol/tls/encrypted/premaster/secret.hpp"

#include "xos/protocol/tls/rsa/private_key.hpp"
#include "xos/protocol/tls/rsa/bn/private_key.hpp"
#include "xos/protocol/tls/rsa/gmp/private_key.hpp"
#include "xos/protocol/tls/rsa/implemented/private_key.hpp"
#include "xos/protocol/tls/decrypted/premaster/secret.hpp"
#include "xos/protocol/tls/pkcs1/decoded/message.hpp"
#include "xos/protocol/tls/pkcs1/decoded/premaster/secret.hpp"
#include "xos/protocol/tls/master/secret.hpp"

#include "xos/protocol/tls/key/exchange/algorithm.hpp"
#include "xos/protocol/tls/client/key/exchange/message.hpp"
#include "xos/protocol/tls/server/key/exchange/message.hpp"

#include "xos/protocol/tls/handshake/message.hpp"
#include "xos/protocol/tls/plaintext.hpp"

#include "xos/protocol/tls/bulk/cipher/algorithm.hpp"
#include "xos/protocol/tls/cipher/type.hpp"
#include "xos/protocol/tls/connection/end.hpp"
#include "xos/protocol/tls/prf/algorithm.hpp"
#include "xos/protocol/tls/mac/algorithm.hpp"
#include "xos/protocol/tls/security/parameters.hpp"
#include "xos/protocol/tls/generic/block/cipher.hpp"

#include "xos/protocol/crypto/random/generator.hpp"
#include "xos/protocol/crypto/random/reader.hpp"
#include "xos/protocol/crypto/pseudo/random/generator.hpp"
#include "xos/protocol/crypto/pseudo/random/reader.hpp"

#include "xos/protocol/tls/pseudo/random/secret.hpp"
#include "xos/protocol/tls/pseudo/random/seed.hpp"
#include "xos/protocol/tls/master/secret/seed.hpp"
#include "xos/protocol/tls/key/expansion/seed.hpp"

#include "xos/app/console/crypto/rsa/client/key_pair.hpp"
#include "xos/app/console/crypto/rsa/server/key_pair.hpp"

#define XOS_PROTOCOL_UDTP_CIPHER_TEXT_SIZE 1024*8

namespace xos {
namespace protocol {
namespace udtp {

/// enum cipher_text_size
enum { 
    cipher_text_size = XOS_PROTOCOL_UDTP_CIPHER_TEXT_SIZE 
}; /// enum cipher_text_size

namespace base {

/// class outputt
template 
<class TExtendsOutput = xos::protocol::tls::crypto::output, 
 class TExtends = TExtendsOutput, class TImplements = typename TExtends::implements>
class exported outputt: virtual public TImplements, public TExtends {
public:
    typedef TImplements implements;
    typedef TExtends extends;
    typedef outputt derives; 
    
    typedef typename extends::char_t char_t;
    typedef typename extends::end_char_t end_char_t;
    enum { end_char = extends::end_char };
    typedef typename extends::string_t string_t;
    typedef typename extends::file_t file_t;

    typedef typename extends::literal_string_t literal_string_t;
    typedef typename extends::byte_array_t byte_array_t;
    typedef typename extends::byte_arrays_t byte_arrays_t;
    typedef typename extends::hex_read_to_byte_array_t hex_read_to_byte_array_t;
    typedef typename extends::hex_read_to_byte_arrays_t hex_read_to_byte_arrays_t;
    typedef typename extends::output_to_t output_to_t;

    typedef xos::protocol::tls::protocol::version protocol_version_t;
    typedef xos::protocol::tls::protocol::version::which_t protocol_version_which_t;
    enum { tls_protocol_version_which = xos::protocol::tls::protocol::version::which };

    typedef xos::protocol::tls::cipher::suite::which_t cipher_suite_which_t;
    enum { tls_cipher_suite_which = xos::protocol::tls::cipher::suite::which };

    typedef xos::protocol::tls::cipher::suite::with_t cipher_suite_with_t;
    enum { tls_cipher_suite_with = xos::protocol::tls::cipher::suite::with };

    typedef xos::protocol::tls::compression::method::which_t compression_method_which_t;
    enum { tls_compression_method_which = xos::protocol::tls::compression::method::which };

    /// struct rsa_key_pair_t
    typedef struct rsa_key_pair_t {
        byte_array_t exponent_, modulus_, p_, q_, dmp1_, dmq1_, iqmp_;
    } rsa_key_pair_t; /// struct rsa_key_pair_t

    /// struct rsa_t
    typedef struct rsa_t {
        rsa_key_pair_t client_, server_;
    } rsa_t; /// struct rsa_t

    /// constructors / destructor
    outputt()
    : protocol_version_which_(tls_protocol_version_which), protocol_version_(protocol_version_which_),
      cipher_suite_which_(tls_cipher_suite_which), cipher_suite_with_(tls_cipher_suite_with),
      compression_method_which_(tls_compression_method_which),
      pseudo_random_secret_string_(xos::protocol::tls::pseudo_random_secret_chars),
      pseudo_random_seed_string_(xos::protocol::tls::pseudo_random_seed_chars),
      master_secret_seed_string_(xos::protocol::tls::master_secret_seed_chars),
      key_expansion_seed_string_(xos::protocol::tls::key_expansion_seed_chars) {
        construct();
    }
    virtual ~outputt() {
    }
private:
    outputt(const outputt& copy) {
        throw exception(exception_unexpected);
    }
    void construct() {
        set_pseudo_random_secret(pseudo_random_secret_string());
        set_pseudo_random_seed(pseudo_random_seed_string());
        set_master_secret_seed(master_secret_seed_string());
        set_key_expansion_seed(key_expansion_seed_string());
    }
public:

    /// ...output_pseudo_random_secret
    ssize_t (derives::*output_pseudo_random_secret_)();
    virtual ssize_t output_pseudo_random_secret() {
        ssize_t count = 0;
        if (output_pseudo_random_secret_) {
            count = (this->*output_pseudo_random_secret_)();
        } else {
            count = default_output_pseudo_random_secret();
        }
        return count;
    }
    virtual ssize_t default_output_pseudo_random_secret() {
        ssize_t count = 0;
        const char_t* chars = 0; size_t length = 0;
        if ((chars = (const char_t*)(this->pseudo_random_secret().has_elements(length)))) {
            count += this->outln(chars, length);
        }
        return count;
    }

    /// ...output_pseudo_random_seed
    ssize_t (derives::*output_pseudo_random_seed_)();
    virtual ssize_t output_pseudo_random_seed() {
        ssize_t count = 0;
        if (output_pseudo_random_seed_) {
            count = (this->*output_pseudo_random_seed_)();
        } else {
            count = default_output_pseudo_random_seed();
        }
        return count;
    }
    virtual ssize_t default_output_pseudo_random_seed() {
        ssize_t count = 0;
        const char_t* chars = 0; size_t length = 0;
        if ((chars = (const char_t*)(this->pseudo_random_seed().has_elements(length)))) {
            count += this->outln(chars, length);
        }
        return count;
    }

    /// ...output_master_secret_seed
    ssize_t (derives::*output_master_secret_seed_)();
    virtual ssize_t output_master_secret_seed() {
        ssize_t count = 0;
        if (output_master_secret_seed_) {
            count = (this->*output_master_secret_seed_)();
        } else {
            count = default_output_master_secret_seed();
        }
        return count;
    }
    virtual ssize_t default_output_master_secret_seed() {
        ssize_t count = 0;
        const char_t* chars = 0; size_t length = 0;
        if ((chars = (const char_t*)(this->master_secret_seed().has_elements(length)))) {
            count += this->outln(chars, length);
        }
        return count;
    }

    /// ...output_key_expansion_seed
    ssize_t (derives::*output_key_expansion_seed_)();
    virtual ssize_t output_key_expansion_seed() {
        ssize_t count = 0;
        if (output_key_expansion_seed_) {
            count = (this->*output_key_expansion_seed_)();
        } else {
            count = default_output_key_expansion_seed();
        }
        return count;
    }
    virtual ssize_t default_output_key_expansion_seed() {
        ssize_t count = 0;
        const char_t* chars = 0; size_t length = 0;
        if ((chars = (const char_t*)(this->key_expansion_seed().has_elements(length)))) {
            count += this->outln(chars, length);
        }
        return count;
    }

    ///
    /// ...output...key...
    /// ...
    /// ...output...key_pair
    ssize_t (derives::*output_client_key_pair_)();
    virtual ssize_t output_client_key_pair() {
        ssize_t count = 0;
        if (output_client_key_pair_) {
            count = (this->*output_client_key_pair_)();
        } else {
            count = output_client_rsa_key_pair();
        }
        return count;
    }
    /// ...output...key_pair
    ssize_t (derives::*output_key_pair_)();
    virtual ssize_t output_key_pair() {
        ssize_t count = 0;
        if (output_key_pair_) {
            count = (this->*output_key_pair_)();
        } else {
            count = output_server_rsa_key_pair();
        }
        return count;
    }
    /// ...output...public_key
    ssize_t (derives::*output_public_key_)();
    virtual ssize_t output_public_key() {
        ssize_t count = 0;
        if (output_public_key_) {
            count = (this->*output_public_key_)();
        } else {
            count = output_server_rsa_public_key();
        }
        return count;
    }
    /// ...output...private_key
    ssize_t (derives::*output_private_key_)();
    virtual ssize_t output_private_key() {
        ssize_t count = 0;
        if (output_private_key_) {
            count = (this->*output_private_key_)();
        } else {
            count = output_server_rsa_private_key();
        }
        return count;
    }
    /// ...
    /// ...output...rsa...key...
    /// 

    ///
    /// ...output...server_rsa...key...
    /// ...
    /// ...output...server_rsa_key_pair
    ssize_t (derives::*output_server_rsa_key_pair_)();
    virtual ssize_t output_server_rsa_key_pair() {
        ssize_t count = 0;
        if (output_server_rsa_key_pair_) {
            count = (this->*output_server_rsa_key_pair_)();
        } else {
            count = default_output_server_rsa_key_pair();
        }
        return count;
    }
    virtual ssize_t default_output_server_rsa_key_pair() {
        ssize_t count = 0;
        size_t length = 0;
        const byte_t *bytes = 0;
        if ((bytes = get_server_exponent(length)) && (length)) {
            count += this->output_x_verbage_sized("server_rsa_exponent", bytes, length);
            if ((bytes = get_server_modulus(length)) && (length)) {
                const byte_t *q = 0, *dmp1 = 0, *dmq1 = 0, *iqmp = 0;
                count += this->output_x_verbage_sized("server_rsa_modulus", bytes, length);
                if ((bytes = get_server_p(q, dmp1, dmq1, iqmp, length)) && (length)) {
                    count += this->output_x_verbage_sized("server_rsa_p", bytes, length);
                    count += this->output_x_verbage_sized("server_rsa_q", q, length);
                    count += this->output_x_verbage_sized("server_rsa_dmp1", dmp1, length);
                    count += this->output_x_verbage_sized("server_rsa_dmq1", dmq1, length);
                    count += this->output_x_verbage_sized("server_rsa_iqmp", iqmp, length);
                }
            }
        }
        return count;
    }
    /// ...output...server_rsa_public_key
    ssize_t (derives::*output_server_rsa_public_key_)();
    virtual ssize_t output_server_rsa_public_key() {
        ssize_t count = 0;
        if (output_server_rsa_public_key_) {
            count = (this->*output_server_rsa_public_key_)();
        } else {
            count = default_output_server_rsa_public_key();
        }
        return count;
    }
    virtual ssize_t default_output_server_rsa_public_key() {
        ssize_t count = 0;
        size_t length = 0;
        const byte_t *bytes = 0;
        if ((bytes = get_server_exponent(length)) && (length)) {
            count += this->output_x_verbage_sized("server_rsa_exponent", bytes, length);
            if ((bytes = get_server_modulus(length)) && (length)) {
                count += this->output_x_verbage_sized("server_rsa_modulus", bytes, length);
            }
        }
        return count;
    }
    /// ...output...server_rsa_private_key
    ssize_t (derives::*output_server_rsa_private_key_)();
    virtual ssize_t output_server_rsa_private_key() {
        ssize_t count = 0;
        if (output_server_rsa_private_key_) {
            count = (this->*output_server_rsa_private_key_)();
        } else {
            count = default_output_server_rsa_private_key();
        }
        return count;
    }
    virtual ssize_t default_output_server_rsa_private_key() {
        ssize_t count = 0;
        size_t length = 0;
        const byte_t *bytes = 0, *q = 0, *dmp1 = 0, *dmq1 = 0, *iqmp = 0;
        if ((bytes = get_server_p(q, dmp1, dmq1, iqmp, length)) && (length)) {
            count += this->output_x_verbage_sized("server_rsa_p", bytes, length);
            count += this->output_x_verbage_sized("server_rsa_q", q, length);
            count += this->output_x_verbage_sized("server_rsa_dmp1", dmp1, length);
            count += this->output_x_verbage_sized("server_rsa_dmq1", dmq1, length);
            count += this->output_x_verbage_sized("server_rsa_iqmp", iqmp, length);
        }
        return count;
    }
    /// ...
    /// ...output...server_rsa...key...
    /// 

    /// 
    /// ...output...client_rsa...key...
    /// ,,,
    /// ...output...client_rsa_key_pair
    ssize_t (derives::*output_client_rsa_key_pair_)();
    virtual ssize_t output_client_rsa_key_pair() {
        ssize_t count = 0;
        if (output_client_rsa_key_pair_) {
            count = (this->*output_client_rsa_key_pair_)();
        } else {
            count = default_output_client_rsa_key_pair();
        }
        return count;
    }
    virtual ssize_t default_output_client_rsa_key_pair() {
        ssize_t count = 0;
        size_t length = 0;
        const byte_t *bytes = 0;
        if ((bytes = get_client_exponent(length)) && (length)) {
            count += this->output_x_verbage_sized("client_rsa_exponent", bytes, length);
            if ((bytes = get_client_modulus(length)) && (length)) {
                const byte_t *q = 0, *dmp1 = 0, *dmq1 = 0, *iqmp = 0;
                count += this->output_x_verbage_sized("client_rsa_modulus", bytes, length);
                if ((bytes = get_client_p(q, dmp1, dmq1, iqmp, length)) && (length)) {
                    count += this->output_x_verbage_sized("client_rsa_p", bytes, length);
                    count += this->output_x_verbage_sized("client_rsa_q", q, length);
                    count += this->output_x_verbage_sized("client_rsa_dmp1", dmp1, length);
                    count += this->output_x_verbage_sized("client_rsa_dmq1", dmq1, length);
                    count += this->output_x_verbage_sized("client_rsa_iqmp", iqmp, length);
                }
            }
        }
        return count;
    }
    /// ...output...client_rsa_public_key
    ssize_t (derives::*output_client_rsa_public_key_)();
    virtual ssize_t output_client_rsa_public_key() {
        ssize_t count = 0;
        if (output_client_rsa_public_key_) {
            count = (this->*output_client_rsa_public_key_)();
        } else {
            count = default_output_client_rsa_public_key();
        }
        return count;
    }
    virtual ssize_t default_output_client_rsa_public_key() {
        ssize_t count = 0;
        size_t length = 0;
        const byte_t *bytes = 0;
        if ((bytes = get_client_exponent(length)) && (length)) {
            count += this->output_x_verbage_sized("client_rsa_exponent", bytes, length);
            if ((bytes = get_client_modulus(length)) && (length)) {
                count += this->output_x_verbage_sized("client_rsa_modulus", bytes, length);
            }
        }
        return count;
    }
    /// ...output...client_rsa_private_key
    ssize_t (derives::*output_client_rsa_private_key_)();
    virtual ssize_t output_client_rsa_private_key() {
        ssize_t count = 0;
        if (output_client_rsa_private_key_) {
            count = (this->*output_client_rsa_private_key_)();
        } else {
            count = default_output_client_rsa_private_key();
        }
        return count;
    }
    virtual ssize_t default_output_client_rsa_private_key() {
        ssize_t count = 0;
        size_t length = 0;
        const byte_t *bytes = 0, *q = 0, *dmp1 = 0, *dmq1 = 0, *iqmp = 0;
        if ((bytes = get_client_p(q, dmp1, dmq1, iqmp, length)) && (length)) {
            count += this->output_x_verbage_sized("client_rsa_p", bytes, length);
            count += this->output_x_verbage_sized("client_rsa_q", q, length);
            count += this->output_x_verbage_sized("client_rsa_dmp1", dmp1, length);
            count += this->output_x_verbage_sized("client_rsa_dmq1", dmq1, length);
            count += this->output_x_verbage_sized("client_rsa_iqmp", iqmp, length);
        }
        return count;
    }
    /// ...
    /// ...output...client_rsa...key...
    /// 

    /// on_set...
    virtual int on_set_rsa_key_pair_option(const char_t* key_pair) {
        int err = 0;
        err = on_set_server_rsa_key_pair_option(key_pair);
        return err;
    }
    virtual int on_set_rsa_public_key_option(const char_t* public_key) {
        int err = 0;
        err = on_set_server_rsa_public_key_option(public_key);
        return err;
    }
    virtual int on_set_rsa_private_key_option(const char_t* private_key) {
        int err = 0;
        err = on_set_server_rsa_private_key_option(private_key);
        return err;
    }
    virtual int on_set_server_rsa_public_key_option(const char_t* key_pair) {
        int err = 0, err2 = 0;
        server_rsa_key_pair_string_.assign(key_pair);
        if (!(err2 = this->on_set_hex_literals
            (rsa_.server_.exponent_, rsa_.server_.modulus_, server_rsa_key_pair_string_))) {
            this->set_get_server_literal_exponent();
            this->set_get_server_literal_modulus();
        }
        return err;
    }
    virtual int on_set_server_rsa_private_key_option(const char_t* key_pair) {
        int err = 0, err2 = 0;
        server_rsa_key_pair_string_.assign(key_pair);
        if (!(err2 = this->on_set_hex_literals
            (rsa_.server_.p_, rsa_.server_.q_, rsa_.server_.dmp1_, 
             rsa_.server_.dmq1_, rsa_.server_.iqmp_, server_rsa_key_pair_string_))) {
            this->set_get_server_literal_p();
        }
        return err;
    }
    virtual int on_set_server_rsa_key_pair_option(const char_t* key_pair) {
        int err = 0, err2 = 0;
        server_rsa_key_pair_string_.assign(key_pair);
        if (!(err2 = this->on_set_hex_literals
            (rsa_.server_.exponent_, rsa_.server_.modulus_, 
             rsa_.server_.p_, rsa_.server_.q_, rsa_.server_.dmp1_, 
             rsa_.server_.dmq1_, rsa_.server_.iqmp_, server_rsa_key_pair_string_))) {
            this->set_get_server_literal_exponent();
            this->set_get_server_literal_modulus();
            this->set_get_server_literal_p();
        }
        return err;
    }
    virtual int on_set_client_rsa_key_pair_option(const char_t* key_pair) {
        int err = 0, err2 = 0;
        client_rsa_key_pair_string_.assign(key_pair);
        if (!(err2 = this->on_set_hex_literals
            (rsa_.client_.exponent_, rsa_.client_.modulus_, 
             rsa_.client_.p_, rsa_.client_.q_, rsa_.client_.dmp1_, 
             rsa_.client_.dmq1_, rsa_.client_.iqmp_, client_rsa_key_pair_string_))) {
            this->set_get_client_literal_exponent();
            this->set_get_client_literal_modulus();
            this->set_get_client_literal_p();
        }
        return err;
    }
    virtual int on_set_pseudo_random_secret_option(const char_t* optarg) {
        int err = 0;
        if ((optarg) && (optarg[0])) {
            literal_string_t& secret_string = this->set_pseudo_random_secret_string(optarg);
            byte_array_t& secret = this->pseudo_random_secret();
            if (!(err = this->on_set_text_literal(secret, secret_string))) {
            }
        }
        return err;
    }
    virtual int on_set_pseudo_random_seed_option(const char_t* optarg) {
        int err = 0;
        if ((optarg) && (optarg[0])) {
            literal_string_t& seed_string = this->set_pseudo_random_seed_string(optarg);
            byte_array_t& seed = this->pseudo_random_seed();
            if (!(err = this->on_set_text_literal(seed, seed_string))) {
            }
        }
        return err;
    }
    virtual int on_set_master_secret_seed_option(const char_t* optarg) {
        int err = 0;
        if ((optarg) && (optarg[0])) {
            literal_string_t& seed_string = this->set_pseudo_random_seed_string(optarg);
            byte_array_t& seed = this->master_secret_seed();
            if (!(err = this->on_set_text_literal(seed, seed_string))) {
            }
        }
        return err;
    }
    virtual int on_set_key_expansion_seed_option(const char_t* optarg) {
        int err = 0;
        if ((optarg) && (optarg[0])) {
            literal_string_t& seed_string = this->set_pseudo_random_seed_string(optarg);
            byte_array_t& seed = this->key_expansion_seed();
            if (!(err = this->on_set_text_literal(seed, seed_string))) {
            }
        }
        return err;
    }

    /// ...
    virtual protocol_version_which_t& protocol_version_which() const {
        return (protocol_version_which_t&)protocol_version_which_;
    }
    virtual protocol_version_t& protocol_version() const {
        return (protocol_version_t&)protocol_version_;
    }
    virtual cipher_suite_which_t& cipher_suite_which() const {
        return (cipher_suite_which_t&)cipher_suite_which_;
    }
    virtual cipher_suite_with_t& cipher_suite_with() const {
        return (cipher_suite_with_t&)cipher_suite_with_;
    }
    virtual compression_method_which_t compression_method_which() const {
        return (compression_method_which_t&)compression_method_which_;
    }

    ///
    /// ...secret / ...seed
    /// ...
    /// ...pseudo_random_secret...
    virtual literal_string_t& set_pseudo_random_secret_string(const char_t* to) {
        if ((to) && (to[0])) {
            pseudo_random_secret_string_.assign(to);
        }
        return (literal_string_t&)pseudo_random_secret_string_;
    }
    virtual literal_string_t& pseudo_random_secret_string() const {
        return (literal_string_t&)pseudo_random_secret_string_;
    }
    virtual byte_array_t& set_pseudo_random_secret(literal_string_t& to) {
        const char_t* chars = 0; size_t length = 0;
        if ((chars = to.has_chars(length))) {
            set_pseudo_random_secret(chars, length);
        }
        return (byte_array_t&)pseudo_random_secret_;
    }
    virtual byte_array_t& set_pseudo_random_secret(const char_t* to, size_t length) {
        const byte_t* bytes = 0;
        if ((bytes = (const byte_t*)to) && (length)) {
            pseudo_random_secret_.assign(bytes, length);
        }
        return (byte_array_t&)pseudo_random_secret_;
    }
    virtual byte_array_t& pseudo_random_secret() const {
        return (byte_array_t&)pseudo_random_secret_;
    }

    /// ...pseudo_random_seed...
    virtual literal_string_t& set_pseudo_random_seed_string(const char_t* to) {
        if ((to) && (to[0])) {
            pseudo_random_seed_string_.assign(to);
        }
        return (literal_string_t&)pseudo_random_seed_string_;
    }
    virtual literal_string_t& pseudo_random_seed_string() const {
        return (literal_string_t&)pseudo_random_seed_string_;
    }
    virtual byte_array_t& set_pseudo_random_seed(literal_string_t& to) {
        const char_t* chars = 0; size_t length = 0;
        if ((chars = to.has_chars(length))) {
            set_pseudo_random_seed(chars, length);
        }
        return (byte_array_t&)pseudo_random_seed_;
    }
    virtual byte_array_t& set_pseudo_random_seed(const char_t* to, size_t length) {
        const byte_t* bytes = 0;
        if ((bytes = (const byte_t*)to) && (length)) {
            pseudo_random_seed_.assign(bytes, length);
        }
        return (byte_array_t&)pseudo_random_seed_;
    }
    virtual byte_array_t& pseudo_random_seed() const {
        return (byte_array_t&)pseudo_random_seed_;
    }

    /// ...master_secret_seed...
    virtual literal_string_t& set_master_secret_seed_string(const char_t* to) {
        if ((to) && (to[0])) {
            master_secret_seed_string_.assign(to);
        }
        return (literal_string_t&)master_secret_seed_string_;
    }
    virtual literal_string_t& master_secret_seed_string() const {
        return (literal_string_t&)master_secret_seed_string_;
    }
    virtual byte_array_t& set_master_secret_seed(literal_string_t& to) {
        const char_t* chars = 0; size_t length = 0;
        if ((chars = to.has_chars(length))) {
            set_master_secret_seed(chars, length);
        }
        return (byte_array_t&)master_secret_seed_;
    }
    virtual byte_array_t& set_master_secret_seed(const char_t* to, size_t length) {
        const byte_t* bytes = 0;
        if ((bytes = (const byte_t*)to) && (length)) {
            master_secret_seed_.assign(bytes, length);
        }
        return (byte_array_t&)master_secret_seed_;
    }
    virtual byte_array_t& master_secret_seed() const {
        return (byte_array_t&)master_secret_seed_;
    }

    /// ...key_expansion_seed...
    virtual literal_string_t& set_key_expansion_seed_string(const char_t* to) {
        if ((to) && (to[0])) {
            key_expansion_seed_string_.assign(to);
        }
        return (literal_string_t&)key_expansion_seed_string_;
    }
    virtual literal_string_t& key_expansion_seed_string() const {
        return (literal_string_t&)key_expansion_seed_string_;
    }
    virtual byte_array_t& set_key_expansion_seed(literal_string_t& to) {
        const char_t* chars = 0; size_t length = 0;
        if ((chars = to.has_chars(length))) {
            set_key_expansion_seed(chars, length);
        }
        return (byte_array_t&)key_expansion_seed_;
    }
    virtual byte_array_t& set_key_expansion_seed(const char_t* to, size_t length) {
        const byte_t* bytes = 0;
        if ((bytes = (const byte_t*)to) && (length)) {
            key_expansion_seed_.assign(bytes, length);
        }
        return (byte_array_t&)key_expansion_seed_;
    }
    virtual byte_array_t& key_expansion_seed() const {
        return (byte_array_t&)key_expansion_seed_;
    }
    /// ...
    /// ...secret / ...seed
    /// 

    ///
    /// get...
    /// ...
    /// get_exponent
    const byte_t* (derives::*get_exponent_)(size_t &length);
    virtual const byte_t* get_exponent(size_t &length) {
        const byte_t* bytes = 0;
        if (get_client_exponent_) {
            bytes = (this->*get_exponent_)(length);
        } else {
            bytes = get_server_exponent(length);
        }
        return bytes;
    }
    /// get_modulus
    const byte_t* (derives::*get_modulus_)(size_t &length);
    virtual const byte_t* get_modulus(size_t &length) {
        const byte_t* bytes = 0;
        if (get_client_modulus_) {
            bytes = (this->*get_modulus_)(length);
        } else {
            bytes = get_server_modulus(length);
        }
        return bytes;
    }
    /// get_p
    const byte_t* (derives::*get_p_)
    (const byte_t *&q, const byte_t *&dmp1, 
     const byte_t *&dmq1, const byte_t *&iqmp, size_t &length);
    virtual const byte_t* get_p
    (const byte_t *&q, const byte_t *&dmp1, 
     const byte_t *&dmq1, const byte_t *&iqmp, size_t &length) {
        const byte_t* bytes = 0;
        if (get_p_) {
            bytes = (this->*get_p_)(q, dmp1, dmq1, iqmp, length);
        } else {
            bytes = get_server_p(q, dmp1, dmq1, iqmp, length);
        }
        return bytes;
    }
    /// ...
    /// get...
    /// 

    ///
    /// client
    /// ...
    /// ...get_client_exponent
    const byte_t* (derives::*get_client_exponent_)(size_t &length);
    virtual const byte_t* get_client_exponent(size_t &length) {
        const byte_t* bytes = 0;
        if (get_client_exponent_) {
            bytes = (this->*get_client_exponent_)(length);
        } else {
            bytes = get_client_test_exponent(length);
        }
        return bytes;
    }
    virtual const byte_t* get_client_test_exponent(size_t &length) {
        const byte_t* bytes = 0;
        length = sizeof(xos::app::console::crypto::rsa::client::rsa_public_exponent);
        bytes = xos::app::console::crypto::rsa::client::rsa_public_exponent;
        return bytes;
    }
    virtual const byte_t* get_client_literal_exponent(size_t &length) {
        const byte_t* bytes = 0;
        length = rsa_.client_.exponent_.length();
        bytes = rsa_.client_.exponent_.elements();
        return bytes;
    }
    virtual int set_get_client_test_exponent() {
        int err = 0;
        get_client_exponent_ = &derives::get_client_literal_exponent;
        return err;
    }
    virtual int set_get_client_literal_exponent() {
        int err = 0;
        get_client_exponent_ = &derives::get_client_literal_exponent;
        return err;
    }

    /// ...get_client_modulus
    const byte_t* (derives::*get_client_modulus_)(size_t &length);
    virtual const byte_t* get_client_modulus(size_t &length) {
        const byte_t* bytes = 0;
        if (get_client_modulus_) {
            bytes = (this->*get_client_modulus_)(length);
        } else {
            bytes = get_client_test_modulus(length);
        }
        return bytes;
    }
    virtual const byte_t* get_client_test_modulus(size_t &length) {
        const byte_t* bytes = 0;
        length = sizeof(xos::app::console::crypto::rsa::client::rsa_public_modulus);
        bytes = xos::app::console::crypto::rsa::client::rsa_public_modulus;
        return bytes;
    }
    virtual const byte_t* get_client_literal_modulus(size_t &length) {
        const byte_t* bytes = 0;
        length = rsa_.client_.modulus_.length();
        bytes = rsa_.client_.modulus_.elements();
        return bytes;;
    }
    virtual int set_get_client_test_modulus() {
        int err = 0;
        get_client_modulus_ = &derives::get_client_test_modulus;
        return err;
    }
    virtual int set_get_client_literal_modulus() {
        int err = 0;
        get_client_modulus_ = &derives::get_client_literal_modulus;
        return err;
    }

    /// ...get_client_p
    const byte_t* (derives::*get_client_p_)
    (const byte_t *&q, const byte_t *&dmp1, 
     const byte_t *&dmq1, const byte_t *&iqmp, size_t &length);
    virtual const byte_t* get_client_p
    (const byte_t *&q, const byte_t *&dmp1, 
     const byte_t *&dmq1, const byte_t *&iqmp, size_t &length) {
        const byte_t* bytes = 0;
        if (get_client_p_) {
            bytes = (this->*get_client_p_)(q, dmp1, dmq1, iqmp, length);
        } else {
            bytes = get_client_test_p(q, dmp1, dmq1, iqmp, length);
        }
        return bytes;
    }
    virtual const byte_t* get_client_test_p
    (const byte_t *&q, const byte_t *&dmp1, 
     const byte_t *&dmq1, const byte_t *&iqmp, size_t &length) {
        const byte_t* bytes = 0;
        length = sizeof(xos::app::console::crypto::rsa::client::rsa_private_p);
        bytes = xos::app::console::crypto::rsa::client::rsa_private_p;
        q = xos::app::console::crypto::rsa::client::rsa_private_q;
        dmp1 = xos::app::console::crypto::rsa::client::rsa_private_dmp1;
        dmq1 = xos::app::console::crypto::rsa::client::rsa_private_dmq1;
        iqmp = xos::app::console::crypto::rsa::client::rsa_private_iqmp;
        return bytes;
    }
    virtual const byte_t* get_client_literal_p
    (const byte_t *&q, const byte_t *&dmp1, 
     const byte_t *&dmq1, const byte_t *&iqmp, size_t &length) {
        const byte_t* bytes = 0;
        length = rsa_.client_.p_.length();
        bytes = rsa_.client_.p_.elements();
        q = rsa_.client_.q_.elements();
        dmp1 = rsa_.client_.dmp1_.elements();
        dmq1 = rsa_.client_.dmq1_.elements();
        iqmp = rsa_.client_.iqmp_.elements();
        return bytes;;
    }
    virtual int set_get_client_test_p() {
        int err = 0;
        get_client_p_ = &derives::get_client_test_p;
        return err;
    }
    virtual int set_get_client_literal_p() {
        int err = 0;
        get_client_p_ = &derives::get_client_literal_p;
        return err;
    }
    /// ...
    /// client
    /// 

    /// 
    /// server
    /// ...
    /// ...get_server_exponent
    const byte_t* (derives::*get_server_exponent_)(size_t &length);
    virtual const byte_t* get_server_exponent(size_t &length) {
        const byte_t* bytes = 0;
        if (get_server_exponent_) {
            bytes = (this->*get_server_exponent_)(length);
        } else {
            bytes = get_server_test_exponent(length);
        }
        return bytes;
    }
    virtual const byte_t* get_server_test_exponent(size_t &length) {
        const byte_t* bytes = 0;
        length = sizeof(xos::app::console::crypto::rsa::server::rsa_public_exponent);
        bytes = xos::app::console::crypto::rsa::server::rsa_public_exponent;
        return bytes;
    }
    virtual const byte_t* get_server_literal_exponent(size_t &length) {
        const byte_t* bytes = 0;
        length = rsa_.server_.exponent_.length();
        bytes = rsa_.server_.exponent_.elements();
        return bytes;
    }
    virtual int set_get_server_test_exponent() {
        int err = 0;
        get_server_exponent_ = &derives::get_server_literal_exponent;
        return err;
    }
    virtual int set_get_server_literal_exponent() {
        int err = 0;
        get_server_exponent_ = &derives::get_server_literal_exponent;
        return err;
    }

    /// ...get_server_modulus
    const byte_t* (derives::*get_server_modulus_)(size_t &length);
    virtual const byte_t* get_server_modulus(size_t &length) {
        const byte_t* bytes = 0;
        if (get_server_modulus_) {
            bytes = (this->*get_server_modulus_)(length);
        } else {
            bytes = get_server_test_modulus(length);
        }
        return bytes;
    }
    virtual const byte_t* get_server_test_modulus(size_t &length) {
        const byte_t* bytes = 0;
        length = sizeof(xos::app::console::crypto::rsa::server::rsa_public_modulus);
        bytes = xos::app::console::crypto::rsa::server::rsa_public_modulus;
        return bytes;
    }
    virtual const byte_t* get_server_literal_modulus(size_t &length) {
        const byte_t* bytes = 0;
        length = rsa_.server_.modulus_.length();
        bytes = rsa_.server_.modulus_.elements();
        return bytes;;
    }
    virtual int set_get_server_test_modulus() {
        int err = 0;
        get_server_modulus_ = &derives::get_server_test_modulus;
        return err;
    }
    virtual int set_get_server_literal_modulus() {
        int err = 0;
        get_server_modulus_ = &derives::get_server_literal_modulus;
        return err;
    }

    /// ...get_server_p
    const byte_t* (derives::*get_server_p_)
    (const byte_t *&q, const byte_t *&dmp1, 
     const byte_t *&dmq1, const byte_t *&iqmp, size_t &length);
    virtual const byte_t* get_server_p
    (const byte_t *&q, const byte_t *&dmp1, 
     const byte_t *&dmq1, const byte_t *&iqmp, size_t &length) {
        const byte_t* bytes = 0;
        if (get_server_p_) {
            bytes = (this->*get_server_p_)(q, dmp1, dmq1, iqmp, length);
        } else {
            bytes = get_server_test_p(q, dmp1, dmq1, iqmp, length);
        }
        return bytes;
    }
    virtual const byte_t* get_server_test_p
    (const byte_t *&q, const byte_t *&dmp1, 
     const byte_t *&dmq1, const byte_t *&iqmp, size_t &length) {
        const byte_t* bytes = 0;
        length = sizeof(xos::app::console::crypto::rsa::server::rsa_private_p);
        bytes = xos::app::console::crypto::rsa::server::rsa_private_p;
        q = xos::app::console::crypto::rsa::server::rsa_private_q;
        dmp1 = xos::app::console::crypto::rsa::server::rsa_private_dmp1;
        dmq1 = xos::app::console::crypto::rsa::server::rsa_private_dmq1;
        iqmp = xos::app::console::crypto::rsa::server::rsa_private_iqmp;
        return bytes;
    }
    virtual const byte_t* get_server_literal_p
    (const byte_t *&q, const byte_t *&dmp1, 
     const byte_t *&dmq1, const byte_t *&iqmp, size_t &length) {
        const byte_t* bytes = 0;
        length = rsa_.server_.p_.length();
        bytes = rsa_.server_.p_.elements();
        q = rsa_.server_.q_.elements();
        dmp1 = rsa_.server_.dmp1_.elements();
        dmq1 = rsa_.server_.dmq1_.elements();
        iqmp = rsa_.server_.iqmp_.elements();
        return bytes;;
    }
    virtual int set_get_server_test_p() {
        int err = 0;
        get_server_p_ = &derives::get_server_test_p;
        return err;
    }
    virtual int set_get_server_literal_p() {
        int err = 0;
        get_server_p_ = &derives::get_server_literal_p;
        return err;
    }
    /// ...
    /// server
    /// 

protected:
    protocol_version_which_t protocol_version_which_;
    protocol_version_t protocol_version_;
    cipher_suite_which_t cipher_suite_which_;
    cipher_suite_with_t cipher_suite_with_;
    compression_method_which_t compression_method_which_;

    literal_string_t pseudo_random_secret_string_, pseudo_random_seed_string_, 
                     master_secret_seed_string_, key_expansion_seed_string_;

    byte_array_t pseudo_random_secret_, pseudo_random_seed_, 
                 master_secret_seed_, key_expansion_seed_;

    literal_string_t server_rsa_key_pair_string_, client_rsa_key_pair_string_;
    
    rsa_t rsa_;
}; /// class outputt
typedef outputt<> output;

} /// namespace base
} /// namespace udtp
} /// namespace protocol
} /// namespace xos

#endif /// ndef XOS_PROTOCOL_UDTP_BASE_OUTPUT_HPP
