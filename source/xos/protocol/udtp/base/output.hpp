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
///   Date: 3/3/2022, 6/2/2022
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

#include "xos/app/console/crypto/rsa/key_pair.hpp"
#include "xos/app/console/crypto/rsa/public_key.hpp"
#include "xos/app/console/crypto/rsa/private_key.hpp"

#define XOS_PROTOCOL_UDTP_CIPHER_TEXT_SIZE 1024*8

namespace xos {
namespace protocol {
namespace udtp {

enum { cipher_text_size = XOS_PROTOCOL_UDTP_CIPHER_TEXT_SIZE };

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
    
    typedef typename extends::output_to_t output_to_t;
    typedef typename extends::byte_arrays_t byte_arrays_t;
    typedef typename extends::byte_array_t byte_array_t;
    typedef typename extends::literal_string_t literal_string_t;

    typedef typename implements::string_t string_t;
    typedef typename implements::char_t char_t;
    typedef typename implements::end_char_t end_char_t;
    enum { end_char = implements::end_char };

    typedef char_t what_t;
    typedef char_t sized_t;

    /// constructors / destructor
private:
    outputt(const outputt& copy) {
        throw exception(exception_unexpected);
    }
public:
    outputt()
    : protocol_version_which_(xos::protocol::tls::protocol::version::which),
      protocol_version_(protocol_version_which_),
      cipher_suite_which_(xos::protocol::tls::cipher::suite::which),
      cipher_suite_with_(xos::protocol::tls::cipher::suite::with),
      compression_method_which_(xos::protocol::tls::compression::method::which),
      pseudo_random_secret_string_(xos::protocol::tls::pseudo_random_secret_chars),
      pseudo_random_seed_string_(xos::protocol::tls::pseudo_random_seed_chars),
      master_secret_seed_string_(xos::protocol::tls::master_secret_seed_chars),
      key_expansion_seed_string_(xos::protocol::tls::key_expansion_seed_chars) {
        set_pseudo_random_secret(pseudo_random_secret_string());
        set_pseudo_random_seed(pseudo_random_seed_string());
        set_master_secret_seed(master_secret_seed_string());
        set_key_expansion_seed(key_expansion_seed_string());
    }
    virtual ~outputt() {
    }

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

    /// ...output_key_pair
    ssize_t (derives::*output_key_pair_)();
    virtual ssize_t output_key_pair() {
        ssize_t count = 0;
        if (output_key_pair_) {
            count = (this->*output_key_pair_)();
        } else {
            count = default_output_key_pair();
        }
        return count;
    }
    virtual ssize_t default_output_key_pair() {
        ssize_t count = 0;
        count = default_output_test_key_pair();
        return count;
    }
    virtual int set_output_test_key_pair() {
        int err = 0;
        output_key_pair_ = &derives::default_output_test_key_pair;
        return err;
    }
    virtual int set_output_get_key_pair() {
        int err = 0;
        output_key_pair_ = &derives::default_output_get_key_pair;
        return err;
    }

    /// ...output_private_key
    ssize_t (derives::*output_private_key_)();
    virtual ssize_t output_private_key() {
        ssize_t count = 0;
        if (output_private_key_) {
            count = (this->*output_private_key_)();
        } else {
            count = default_output_private_key();
        }
        return count;
    }
    virtual ssize_t default_output_private_key() {
        ssize_t count = 0;
        count = default_output_test_private_key();
        return count;
    }
    virtual int set_output_test_private_key() {
        int err = 0;
        output_private_key_ = &derives::default_output_test_private_key;
        return err;
    }
    virtual int set_output_get_private_key() {
        int err = 0;
        output_private_key_ = &derives::default_output_get_private_key;
        return err;
    }

    /// ...output_public_key
    ssize_t (derives::*output_public_key_)();
    virtual ssize_t output_public_key() {
        ssize_t count = 0;
        if (output_public_key_) {
            count = (this->*output_public_key_)();
        } else {
            count = default_output_public_key();
        }
        return count;
    }
    virtual ssize_t default_output_public_key() {
        ssize_t count = 0;
        count = default_output_test_public_key();
        return count;
    }
    virtual int set_output_test_public_key() {
        int err = 0;
        output_public_key_ = &derives::default_output_test_public_key;
        return err;
    }
    virtual int set_output_get_public_key() {
        int err = 0;
        output_public_key_ = &derives::default_output_get_public_key;
        return err;
    }

    /// ...output_get_...
    virtual ssize_t default_output_get_key_pair() {
        ssize_t amount = 0, count = 0;
        if (0 < (amount = default_output_get_public_key())) {
            count += amount;
            if (0 < (amount = default_output_get_private_key())) {
                count += amount;
            }
        }
        return count;
    }
    virtual ssize_t default_output_get_private_key() {
        ssize_t count = 0;
        size_t length = 0;
        const byte_t *bytes = 0;
        const byte_t *q = 0, *dmp1 = 0, *dmq1 = 0, *iqmp = 0;
        if ((bytes = get_p(q, dmp1, dmq1, iqmp, length)) && (length)) {
            count += this->output_x(bytes, length);
            count += this->output_x(q, length);
            count += this->output_x(dmp1, length);
            count += this->output_x(dmq1, length);
            count += this->output_x(iqmp, length);
        }
        return count;
    }
    virtual ssize_t default_output_get_public_key() {
        ssize_t count = 0;
        size_t length = 0;
        const byte_t *bytes = 0;
        if ((bytes = get_exponent(length)) && (length)) {
            count += this->output_x(bytes, length);
            if ((bytes = get_modulus(length)) && (length)) {
                count += this->output_x(bytes, length);
            }
        }
        return count;
    }

    /// ...output_test_...
    virtual ssize_t default_output_test_key_pair() {
        ssize_t amount = 0, count = 0;
        if (0 < (amount = default_output_test_public_key())) {
            count += amount;
            if (0 < (amount = default_output_test_private_key())) {
                count += amount;
            }
        }
        return count;
    }
    virtual ssize_t default_output_test_private_key() {
        ssize_t count = 0;
        count += this->output_x
        (xos::app::console::crypto::rsa::rsa_private_p, 
         sizeof(xos::app::console::crypto::rsa::rsa_private_p));
        count += this->output_x
        (xos::app::console::crypto::rsa::rsa_private_q, 
         sizeof(xos::app::console::crypto::rsa::rsa_private_q));
        count += this->output_x
        (xos::app::console::crypto::rsa::rsa_private_dmp1, 
         sizeof(xos::app::console::crypto::rsa::rsa_private_dmp1));
        count += this->output_x
        (xos::app::console::crypto::rsa::rsa_private_dmq1, 
         sizeof(xos::app::console::crypto::rsa::rsa_private_dmq1));
        count += this->output_x
        (xos::app::console::crypto::rsa::rsa_private_iqmp, 
         sizeof(xos::app::console::crypto::rsa::rsa_private_iqmp));
        return count;
    }
    virtual ssize_t default_output_test_public_key() {
        ssize_t count = 0;
        if ((count += default_output_test_public_exponent())) {
            if ((count += default_output_test_public_modulus())) {
            }
        }
        return count;
    }
    virtual ssize_t default_output_test_public_exponent() {
        ssize_t count = 0;
        count += this->output_x
        (xos::app::console::crypto::rsa::rsa_public_exponent, 
         sizeof(xos::app::console::crypto::rsa::rsa_public_exponent));
        return count;
    }
    virtual ssize_t default_output_test_public_modulus() {
        ssize_t count = 0;
        count += this->output_x
        (xos::app::console::crypto::rsa::rsa_public_modulus, 
         sizeof(xos::app::console::crypto::rsa::rsa_public_modulus));
        return count;
    }

    /// on_set...
    virtual int on_set_pseudo_random_secret(const char_t* optarg) {
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
    virtual int on_set_private_key_option(const char_t* private_key) {
        int err = 0;
        private_string_.assign(private_key);
        err = this->on_set_hex_literals(p_, q_, dmp1_, dmq1_, iqmp_, private_string_);
        err = this->set_get_literal_p();
        err = this->set_output_get_private_key();
        return err;
    }
    virtual int on_set_public_key_option(const char_t* public_key) {
        int err = 0;
        public_string_.assign(public_key);
        err = this->on_set_hex_literals(exponent_, modulus_, public_string_);
        err = this->set_get_literal_exponent();
        err = this->set_get_literal_modulus();
        err = this->set_output_get_public_key();
        return err;
    }

    /// ...
    virtual xos::protocol::tls::protocol::version::which_t& protocol_version_which() const {
        return (xos::protocol::tls::protocol::version::which_t&)protocol_version_which_;
    }
    virtual xos::protocol::tls::protocol::version& protocol_version() const {
        return (xos::protocol::tls::protocol::version&)protocol_version_;
    }
    virtual xos::protocol::tls::cipher::suite::which_t& cipher_suite_which() const {
        return (xos::protocol::tls::cipher::suite::which_t&)cipher_suite_which_;
    }
    virtual xos::protocol::tls::cipher::suite::with_t& cipher_suite_with() const {
        return (xos::protocol::tls::cipher::suite::with_t&)cipher_suite_with_;
    }
    virtual xos::protocol::tls::compression::method::which_t compression_method_which() const {
        return (xos::protocol::tls::compression::method::which_t&)compression_method_which_;
    }

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

    /// ...get_exponent
    const byte_t* (derives::*get_exponent_)(size_t &length);
    virtual const byte_t* get_exponent(size_t &length) {
        const byte_t* bytes = 0;
        if (get_exponent_) {
            bytes = (this->*get_exponent_)(length);
        } else {
            bytes = get_test_exponent(length);
        }
        return bytes;
    }
    virtual const byte_t* get_test_exponent(size_t &length) {
        const byte_t* bytes = 0;
        length = sizeof(xos::app::console::crypto::rsa::rsa_public_exponent);
        bytes = xos::app::console::crypto::rsa::rsa_public_exponent;
        return bytes;
    }
    virtual const byte_t* get_literal_exponent(size_t &length) {
        const byte_t* bytes = 0;
        length = exponent_.length();
        bytes = exponent_.elements();
        return bytes;
    }
    virtual int set_get_test_exponent() {
        int err = 0;
        get_exponent_ = &derives::get_literal_exponent;
        return err;
    }
    virtual int set_get_literal_exponent() {
        int err = 0;
        get_exponent_ = &derives::get_literal_exponent;
        return err;
    }

    /// ...get_modulus
    const byte_t* (derives::*get_modulus_)(size_t &length);
    virtual const byte_t* get_modulus(size_t &length) {
        const byte_t* bytes = 0;
        if (get_modulus_) {
            bytes = (this->*get_modulus_)(length);
        } else {
            bytes = get_test_modulus(length);
        }
        return bytes;
    }
    virtual const byte_t* get_test_modulus(size_t &length) {
        const byte_t* bytes = 0;
        length = sizeof(xos::app::console::crypto::rsa::rsa_public_modulus);
        bytes = xos::app::console::crypto::rsa::rsa_public_modulus;
        return bytes;
    }
    virtual const byte_t* get_literal_modulus(size_t &length) {
        const byte_t* bytes = 0;
        length = modulus_.length();
        bytes = modulus_.elements();
        return bytes;;
    }
    virtual int set_get_test_modulus() {
        int err = 0;
        get_modulus_ = &derives::get_test_modulus;
        return err;
    }
    virtual int set_get_literal_modulus() {
        int err = 0;
        get_modulus_ = &derives::get_literal_modulus;
        return err;
    }

    /// ...get_p
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
            bytes = get_test_p(q, dmp1, dmq1, iqmp, length);
        }
        return bytes;
    }
    virtual const byte_t* get_test_p
    (const byte_t *&q, const byte_t *&dmp1, 
     const byte_t *&dmq1, const byte_t *&iqmp, size_t &length) {
        const byte_t* bytes = 0;
        length = sizeof(xos::app::console::crypto::rsa::rsa_private_p);
        bytes = xos::app::console::crypto::rsa::rsa_private_p;
        q = xos::app::console::crypto::rsa::rsa_private_q;
        dmp1 = xos::app::console::crypto::rsa::rsa_private_dmp1;
        dmq1 = xos::app::console::crypto::rsa::rsa_private_dmq1;
        iqmp = xos::app::console::crypto::rsa::rsa_private_iqmp;
        return bytes;
    }
    virtual const byte_t* get_literal_p
    (const byte_t *&q, const byte_t *&dmp1, 
     const byte_t *&dmq1, const byte_t *&iqmp, size_t &length) {
        const byte_t* bytes = 0;
        length = p_.length();
        bytes = p_.elements();
        q = q_.elements();
        dmp1 = dmp1_.elements();
        dmq1 = dmq1_.elements();
        iqmp = iqmp_.elements();
        return bytes;;
    }
    virtual int set_get_test_p() {
        int err = 0;
        get_p_ = &derives::get_test_p;
        return err;
    }
    virtual int set_get_literal_p() {
        int err = 0;
        get_p_ = &derives::get_literal_p;
        return err;
    }

protected:
    xos::protocol::tls::protocol::version::which_t protocol_version_which_;
    xos::protocol::tls::protocol::version protocol_version_;
    xos::protocol::tls::cipher::suite::which_t cipher_suite_which_;
    xos::protocol::tls::cipher::suite::with_t cipher_suite_with_;
    xos::protocol::tls::compression::method::which_t compression_method_which_;

    literal_string_t pseudo_random_secret_string_, pseudo_random_seed_string_, master_secret_seed_string_, key_expansion_seed_string_;
    byte_array_t pseudo_random_secret_, pseudo_random_seed_, master_secret_seed_, key_expansion_seed_;

    literal_string_t public_string_, private_string_;
    byte_array_t exponent_, modulus_, p_, q_, dmp1_, dmq1_, iqmp_;
}; /// class outputt
typedef outputt<> output;

} /// namespace base
} /// namespace udtp
} /// namespace protocol
} /// namespace xos

#endif /// XOS_PROTOCOL_UDTP_BASE_OUTPUT_HPP
