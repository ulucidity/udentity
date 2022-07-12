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
///   Date: 5/20/2022
///////////////////////////////////////////////////////////////////////
#ifndef XOS_PROTOCOL_UDTP_SERVER_OUTPUT_HPP
#define XOS_PROTOCOL_UDTP_SERVER_OUTPUT_HPP

#include "xos/protocol/udtp/base/output.hpp"
#include "xos/protocol/udtp/plaintext/messages.hpp"

#include "xos/crypto/hash/implemented/sha256.hpp"
#include "xos/crypto/cipher/implemented/aes.hpp"

#include "xos/protocol/udtp/server/message/default_plain_text.hpp"

namespace xos {
namespace protocol {
namespace udtp {
namespace server {

/// class outputt
template 
<class TPlaintextMessages = xos::protocol::udtp::plaintext::messages,
 class TSecurityParameters = xos::protocol::tls::security::parameters, 
 class TExtendsOutput = xos::protocol::udtp::base::output, 
 class TExtends = TExtendsOutput, class TImplements = typename TExtends::implements>

class exported outputt: virtual public TImplements, public TExtends {
public:
    typedef TImplements implements;
    typedef TExtends extends;
    typedef outputt derives; 
    
    typedef typename extends::string_t string_t;
    typedef typename extends::char_t char_t;
    typedef typename extends::end_char_t end_char_t;
    enum { end_char = extends::end_char };

    typedef char_t what_t;
    typedef char_t sized_t;

    typedef typename extends::literal_string_t literal_string_t;
    typedef typename extends::byte_array_t byte_array_t;
    typedef typename extends::byte_arrays_t byte_arrays_t;
    typedef TPlaintextMessages plaintext_messages_t;
    typedef TSecurityParameters security_parameters_t;

    enum { cipher_text_size = udtp::cipher_text_size };
    enum { record_iv_size = xos::crypto::cipher::aes::IVSIZE };
    
    typedef typename extends::output_to_t output_to_t;

    /// constructors / destructor
    outputt()
    : expect_server_key_exchange_(true),
      expecting_server_key_exchange_(false),
      output_hello_message_(false),
      client_hello_messages_size_(0),
      server_hello_messages_size_(0),
      client_decipher_text_size_(cipher_text_size),
      server_plain_text_(message::default_plain_text) {
        construct();
    }
    virtual ~outputt() {
    }
private:
    outputt(const outputt& copy) {
        throw exception(exception_unexpected);
    }
    void construct() {
        client_hello_messages_.set_length(client_hello_messages_size_);
        client_decipher_text_.set_length(client_decipher_text_size_);
        server_hello_messages_.set_length(server_hello_messages_size_);
        encipher_text_.set_length(client_decipher_text_size_);
        security_parameters_.set_record_iv_length_value(record_iv_size);
    }
public:

    ///
    /// ...clent...hello
    /// ...
    /// ...output_client_hello_messages
    virtual int output_client_hello_messages() {
        int err = 0;
        const xos::protocol::tls::byte_arrays_t& client_hello_messages = this->client_hello_messages();
        xos::protocol::tls::byte_array_t*const* arrays = 0; size_t arrays_length = 0;
        
        if ((arrays = client_hello_messages.has_elements(arrays_length))) {
            /*const bool verbose = this->verbose_output();*/

            if ((err = output_client_hello_messages(arrays, arrays_length))) {
            }
            /*for (const xos::protocol::tls::byte_array_t* array = *arrays; arrays_length; --arrays_length, ++arrays, array = *arrays) {
                if ((array)) {
                    xos::protocol::tls::plaintext *is_plaintext = 0;

                    if ((verbose)) {
                        this->outln("byte_array:\\");
                        this->output_hex(*array);
                        this->outln();
                    }
                    if ((is_plaintext = array->is_plaintext())) {
                        xos::protocol::tls::plaintext& plaintext = *is_plaintext;
                        
                        if ((err = output_client_plaintext_message(plaintext))) {
                        }
                    }
                }
            }*/
        }
        return err;
    }
    virtual int output_client_hello_messages(xos::protocol::tls::byte_array_t*const* arrays, size_t arrays_length) {
        int err = 0;

        if ((arrays) && (arrays_length)) {
            const bool verbose = this->verbose_output(), 
                       output_hello_message = this->output_hello_message();
    
            for (const xos::protocol::tls::byte_array_t* array = *arrays; arrays_length; --arrays_length, ++arrays, array = *arrays) {
                if ((array)) {
                    xos::protocol::tls::plaintext *is_plaintext = 0;
    
                    if ((verbose)) {
                        this->outln("byte_array:\\");
                    }
                    if ((output_hello_message)) {
                        this->output_hex(*array);
                        if ((verbose)) {
                            this->outln();
                        }
                    } else {
                        if ((verbose)) {
                            this->output_hex(*array);
                            this->outln();
                        }
                        if ((is_plaintext = array->is_plaintext())) {
                            xos::protocol::tls::plaintext& plaintext = *is_plaintext;
                            
                            if ((err = output_client_plaintext_message(plaintext))) {
                            }
                        }
                    }
                }
            }
        }
        return err;
    }
    /// ...output_client_plaintext_message
    virtual int output_client_plaintext_message(xos::protocol::tls::plaintext& plaintext) {
        int err = 0;
        const bool verbose = this->verbose_output();

        if ((plaintext.separate())) {
            const xos::protocol::tls::plaintext::type_t& content_type = plaintext.type();
            const byte_t* bytes = 0; size_t length = 0;

            if ((bytes = content_type.has_elements(length))) {
                const xos::protocol::tls::protocol::version& protocol_version = plaintext.version();

                if ((verbose)) {
                    this->outln("content_type:\\");
                    this->output_hex(content_type);
                    this->outln();
                }
                if ((bytes = protocol_version.has_elements(length))) {
                    const xos::protocol::tls::plaintext::fragment_length_t& fragment_length = plaintext.fragment_length();

                    if ((verbose)) {
                        this->outln("protocol_version:\\");
                        this->output_hex(protocol_version);
                        this->outln();
                    }
                    if ((bytes = fragment_length.has_elements(length))) {
                        const size_t fragment_length_value = fragment_length.value();
                        const xos::protocol::tls::plaintext::fragment_t& fragment = plaintext.fragment();
                        
                        if ((verbose)) {
                            this->outlln("fragment_length[", unsigned_to_string(fragment_length_value).chars(), "]:\\", null);
                            this->output_hex(fragment_length);
                            this->outln();
                        }
                        if ((bytes = fragment.has_elements(length))) {
                            const xos::protocol::tls::plaintext::type_t::which_t& content_type_which = content_type.is();
                            
                            if ((verbose)) {
                                this->outln("fragment:\\");
                                this->output_hex(fragment);
                                this->outln();
                            }
                            if ((xos::protocol::tls::plaintext::type_t::handshake == content_type_which)) {
                                err = output_client_handshake_message(bytes, length);
                            } else {
                                if ((xos::protocol::tls::plaintext::type_t::application_data == content_type_which)) {
                                    err = output_client_application_data_message(bytes, length);
                                } else {
                                }
                            }
                        }
                    }
                }
            }
        }
        return err;
    }
    /// ...output_client_handshake_message
    virtual int output_client_handshake_message(const byte_t* bytes, size_t length) {
        int err = 0;
        const bool verbose = this->verbose_output();
        
        if ((bytes) && (length)) {
            xos::protocol::tls::handshake::message handshake;
            size_t count = 0;
            
            if ((handshake.separate(count, bytes, length))) {
                xos::protocol::tls::handshake::message::type_t& handshake_type = handshake.type_of();
                xos::protocol::tls::handshake::message::length_t& handshake_length = handshake.length_of();
                xos::protocol::tls::handshake::message::length_t::value_t handshake_length_value = handshake_length.value();
                xos::protocol::tls::handshake::message::content_t& handshake_content = handshake.content_of();
                const byte_t* bytes = 0; size_t length = 0;

                if ((verbose)) {
                    this->outln("handshake_type:\\");
                    this->output_x(&handshake_type, 1);
                    this->outln();
                }
                if ((verbose)) {
                    this->outlln("handshake_length[", unsigned_to_string(handshake_length_value).chars(), "]:\\", null);
                    this->output_hex(handshake_length);
                    this->outln();
                }
                if ((bytes = handshake_content.has_elements(length))) {
                    if ((xos::protocol::tls::handshake::message::type_client_hello == (handshake_type))) {
                        err = output_client_hello(bytes, length);
                    } else {
                        if ((xos::protocol::tls::handshake::message::type_client_key_exchange == (handshake_type))) {
                            err = output_client_key_exchange(bytes, length);
                        } else {
                            if ((xos::protocol::tls::handshake::message::type_server_key_exchange == (handshake_type))) {
                                err = output_server_key_exchange(bytes, length);
                            } else {
                            }
                        }
                    }
                }
            }
        }
        return err;
    }
    /// ...output_client_hello
    virtual int output_client_hello(const byte_t* bytes, size_t length) {
        int err = 0;
        const bool verbose = this->verbose_output();
        
        if ((bytes) && (length)) {
            xos::protocol::tls::client::hello client_hello;
            size_t count = 0;
            
            if ((client_hello.separate(count, bytes, length))) {
                xos::protocol::tls::client::hello::protocol_version_t& client_hello_protocol_version = client_hello.protocol_version();

                if ((bytes = client_hello_protocol_version.has_elements(length))) {
                    xos::protocol::tls::client::hello::hello_random_t& client_hello_random = client_hello.hello_random();

                    if ((verbose)) {
                        this->outln("client_hello_protocol_version:\\");
                        this->output_hex(client_hello_protocol_version);
                        this->outln();
                    }
                    client_hello_protocol_version_.assign(bytes, length);
                    if ((bytes = client_hello_random.has_elements(length))) {
                        xos::protocol::tls::client::hello::hello_random_t::random_bytes_t& client_hello_random_bytes = client_hello_random.random_bytes();

                        if ((verbose)) {
                            this->outln("client_hello_random:\\");
                            this->output_hex(client_hello_random);
                            this->outln();
                        }
                        client_hello_random_.assign(bytes, length);
                        if ((bytes = client_hello_random_bytes.has_elements(length))) {
                            xos::protocol::tls::client::hello::hello_random_t::gmt_unix_time_t& client_hello_gmt_unix_time = client_hello_random.gmt_unix_time();
    
                            if ((verbose)) {
                                this->outln("client_hello_random_bytes:\\");
                                this->output_hex(client_hello_random_bytes);
                                this->outln();
                            }
                            if ((bytes = client_hello_gmt_unix_time.has_elements(length))) {
                                if ((verbose)) {
                                    this->outln("client_hello_gmt_unix_time:\\");
                                    this->output_hex(client_hello_gmt_unix_time);
                                    this->outln();
                                }
                            }
                        }
                    }
                }
            }
        }
        return err;
    }
    /// ...output_client_key_exchange
    virtual int output_client_key_exchange(const byte_t* bytes, size_t length) {
        int err = 0;
        const bool verbose = this->verbose_output();
        const byte_t* p = 0 , *q = 0, *dmp1 = 0, *dmq1 = 0, *iqmp = 0; 
        size_t p_length = 0;
        
        if ((p = this->get_server_p(q, dmp1, dmq1, iqmp, p_length))) {
            size_t modulus_length = p_length*2;

            if ((bytes) && (modulus_length <= length)) {
                size_t amount = 0;
                xos::protocol::tls::rsa::implemented::private_key private_key(p, q, dmp1, dmq1, iqmp, p_length);
                xos::protocol::tls::client::key::exchange::message client_key_exchange;

                if ((client_key_exchange.separate
                     (amount, private_key, bytes, length)) && (modulus_length == amount)) {
                    xos::protocol::tls::client::key::exchange::message::encrypted_pre_master_secret_t& 
                    encrypted_pre_master_secret = client_key_exchange.encrypted_pre_master_secret();

                    if ((bytes = encrypted_pre_master_secret.has_elements(length))) {
                        xos::protocol::tls::decrypted::premaster::secret decrypted_pre_master_secret(private_key, encrypted_pre_master_secret);
                        
                        if ((verbose)) {
                            this->outlln("encrypted_pre_master_secret[", unsigned_to_string(length).chars(), "]:\\", null);
                            this->output_hex(encrypted_pre_master_secret);
                            this->outln();
                        }
                        if ((bytes = decrypted_pre_master_secret.has_elements(length))) {
                            xos::protocol::tls::pkcs1::encoded::premaster::secret encoded_pre_master_secret(decrypted_pre_master_secret);
                            xos::protocol::tls::pkcs1::decoded::premaster::secret decoded_pre_master_secret(encoded_pre_master_secret);

                            if ((verbose)) {
                                this->outlln("decrypted_pre_master_secret[", unsigned_to_string(length).chars(), "]:\\", null);
                                this->output_hex(decrypted_pre_master_secret);
                                this->outln();
                            }
                            if (!(bytes = decoded_pre_master_secret.has_elements(length))) {
                                if ((verbose)) {
                                    this->outln("!decoded_pre_master_secret[]:\\");
                                    this->outln();
                                }
                            } else {
                                byte_array_t& client_pre_master_secret = this->client_pre_master_secret();

                                if ((verbose)) {
                                    this->outlln("decoded_pre_master_secret[", unsigned_to_string(length).chars(), "]:\\", null);
                                    this->output_hex(decoded_pre_master_secret);
                                    this->outln();
                                }
                                client_pre_master_secret.assign(bytes, length);
                                if ((bytes = client_pre_master_secret.has_elements(length))) {
                                    bool &expecting_server_key_exchange = this->expecting_server_key_exchange();

                                    if ((expecting_server_key_exchange = this->expect_server_key_exchange())) {
                                        if ((verbose)) {
                                            this->outln("expecting_server_key_exchange\\");
                                            this->outln();
                                        }                                        
                                    } else {
                                        err = output_master_secret();
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        return err;
    }
    /// ...output_server_key_exchange
    virtual int output_server_key_exchange(const byte_t* bytes, size_t length) {
        int err = 0;
        const bool verbose = this->verbose_output();
        const byte_t* modulus = 0; size_t modulus_length = 0;

        if ((modulus = this->get_client_modulus(modulus_length))) {
            const byte_t* exponent = 0; size_t exponent_length = 0;
            
            if ((exponent = this->get_client_exponent(exponent_length))) {
                
                if ((bytes) && (modulus_length <= length)) {
                    size_t amount = 0;
                    xos::protocol::tls::rsa::implemented::public_key public_key(modulus, modulus_length, exponent, exponent_length);
                    xos::protocol::tls::client::key::exchange::message client_key_exchange;

                    if ((client_key_exchange.separate
                         (amount, public_key, bytes, length)) && (modulus_length == amount)) {
                        xos::protocol::tls::client::key::exchange::message::encrypted_pre_master_secret_t& 
                        encrypted_pre_master_secret = client_key_exchange.encrypted_pre_master_secret();
    
                        if ((bytes = encrypted_pre_master_secret.has_elements(length))) {
                            xos::protocol::tls::decrypted::premaster::secret decrypted_pre_master_secret(public_key, encrypted_pre_master_secret);
                            
                            if ((verbose)) {
                                this->outlln("encrypted_pre_master_secret[", unsigned_to_string(length).chars(), "]:\\", null);
                                this->output_hex(encrypted_pre_master_secret);
                                this->outln();
                            }
                            if ((bytes = decrypted_pre_master_secret.has_elements(length))) {
                                xos::protocol::tls::pkcs1::encoded::premaster::secret encoded_pre_master_secret(decrypted_pre_master_secret);
                                xos::protocol::tls::pkcs1::decoded::premaster::secret decoded_pre_master_secret(encoded_pre_master_secret);
    
                                if ((verbose)) {
                                    this->outlln("decrypted_pre_master_secret[", unsigned_to_string(length).chars(), "]:\\", null);
                                    this->output_hex(decrypted_pre_master_secret);
                                    this->outln();
                                }
                                if ((bytes = decoded_pre_master_secret.has_elements(length))) {
                                    byte_array_t& server_pre_master_secret = this->server_pre_master_secret();
    
                                    if ((verbose)) {
                                        this->outlln("decoded_pre_master_secret[", unsigned_to_string(length).chars(), "]:\\", null);
                                        this->output_hex(decoded_pre_master_secret);
                                        this->outln();
                                    }
                                    server_pre_master_secret.assign(bytes, length);
                                    if ((bytes = server_pre_master_secret.has_elements(length))) {
                                        bool &expecting_server_key_exchange = this->expecting_server_key_exchange();
    
                                        if ((expecting_server_key_exchange)) {
                                            byte_array_t& client_pre_master_secret = this->client_pre_master_secret();
                                            const byte_t* client_bytes = 0; size_t client_length = 0;

                                            if ((client_bytes = client_pre_master_secret.has_elements(client_length))) {
                                                int unequal = decoded_pre_master_secret.compare(client_pre_master_secret);

                                                if ((verbose)) {
                                                    this->outlln((unequal)?("!="):("=="),"client_pre_master_secret[", unsigned_to_string(client_length).chars(), "]:\\", null);
                                                    this->output_hex(client_pre_master_secret);
                                                    this->outln();
                                                }
                                                if (!(unequal)) {
                                                    expecting_server_key_exchange = false;
                                                    err = output_master_secret();
                                                } else {
                                                }
                                            }
                                        } else {
                                            if ((verbose)) {
                                                this->outln("...!expecting_server_key_exchange\\");
                                                this->outln();
                                            }                                        
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        return err;
    }
    /// ...output_master_secret
    virtual int output_master_secret() {
        int err = 0;
        const bool verbose = this->verbose_output();
        const byte_array_t& master_secret_seed = this->master_secret_seed();
        const byte_array_t& client_pre_master_secret = this->client_pre_master_secret();
        const byte_array_t& client_hello_random = this->client_hello_random();
        xos::protocol::tls::master::secret master_secret
        (client_pre_master_secret, master_secret_seed, client_hello_random, client_hello_random);
        const byte_t* bytes = 0; size_t length = 0;

        if ((bytes = master_secret.has_elements(length))) {
            const byte_array_t& key_expansion_seed = this->key_expansion_seed();

            if ((verbose)) {
                this->outln("master_secret:\\");
                this->output_hex(master_secret);
                this->outln();
            }
            if ((bytes = key_expansion_seed.has_elements(length))) {
                xos::protocol::tls::message::part hello_randoms(client_hello_random);
                
                hello_randoms.append(client_hello_random);
                if ((bytes = hello_randoms.has_elements(length))) {
                    xos::protocol::tls::pseudo::random::reader key_material(master_secret, key_expansion_seed, hello_randoms);
                    byte_array_t& write_MAC_key = this->write_MAC_key();
                    byte_t* key = 0; size_t keylen = 0, keysize = 0;
                    
                    write_MAC_key.set_length(keysize = xos::crypto::hash::sha256::KEYMAX);
                    if ((key = write_MAC_key.has_elements(keylen)) && (keysize == keylen)) {
                        
                        if (keylen == (key_material.read(key, keylen))) {
                            byte_array_t& write_key = this->write_key();

                            if ((verbose)) {
                                this->outln("write_MAC_key:\\");
                                this->output_hex(write_MAC_key);
                                this->outln();
                            }
                            write_key.set_length(keysize = xos::crypto::cipher::aes::KEYMAX);
                            if ((key = write_key.has_elements(keylen)) && (keysize == keylen)) {

                                if (keylen == (key_material.read(key, keylen))) {
                                    byte_array_t& write_IV = this->write_IV();

                                    if ((verbose)) {
                                        this->outln("write_key:\\");
                                        this->output_hex(write_key);
                                        this->outln();
                                    }
                                    write_IV.set_length(keysize = xos::crypto::cipher::aes::IVMAX);
                                    if ((key = write_IV.has_elements(keylen)) && (keysize == keylen)) {
                                        if (keylen == (key_material.read(key, keylen))) {
                                            
                                            if ((verbose)) {
                                                this->outln("write_IV:\\");
                                                this->output_hex(write_IV);
                                                this->outln();
                                            }
                                        }
                                    }
                                }
                            }
                        }                        
                    }
                }
            }
        }
        return err;
    }
    /// ...output_client_application_data_message
    virtual int output_client_application_data_message(const byte_t* bytes, size_t length) {
        int err = 0;
        const bool verbose = this->verbose_output();
        
        if ((this->expecting_server_key_exchange())) {
            if ((verbose)) {
                this->outln("expected_server_key_exchange\\");
                this->outln();
            }                                        
        } else{
            if ((bytes) && (length)) {
                xos::protocol::tls::security::parameters& security_parameters = this->security_parameters();
                xos::protocol::tls::security::parameters::length_t::value_t record_iv_length = security_parameters.record_iv_length_value();
                
                if (record_iv_length < (length)) {
                    xos::protocol::tls::generic::block::cipher generic_block_cipher;
                    size_t count = 0;
                    
                    if ((generic_block_cipher.separate(count, record_iv_length, bytes, length))) {
                        const xos::protocol::tls::generic::block::cipher::opaque_t& generic_block_cipher_IV = generic_block_cipher.IV();
                        const xos::protocol::tls::generic::block::cipher::opaque_t& generic_block_cipher_content = generic_block_cipher.content();
                        const xos::protocol::tls::generic::block::cipher::padding_length_t& generic_block_cipher_padding_length = generic_block_cipher.padding_length();
                        xos::protocol::tls::generic::block::cipher::padding_length_t::value_t generic_block_cipher_padding_length_value = generic_block_cipher_padding_length.value();
                        const byte_t* bytes = 0; size_t length = 0;
    
                        if ((verbose)) {
                            this->outln("generic_block_cipher_IV:\\");
                            this->output_hex(generic_block_cipher_IV);
                            this->outln();
                        }
                        if ((verbose)) {
                            this->outln("generic_block_cipher_content:\\");
                            this->output_hex(generic_block_cipher_content);
                            this->outln();
                        }
                        if ((verbose)) {
                            this->outlln("generic_block_cipher_padding_length[", unsigned_to_string(generic_block_cipher_padding_length_value).chars(), "]:\\", null);
                            this->output_hex(generic_block_cipher_padding_length);
                            this->outln();
                        }
                        if ((bytes = generic_block_cipher_content.has_elements(length))) {
                            err = output_client_plain_text(bytes, length);
                        }
                    }
                }
            }
        }
        return err;
    }
    /// ...output_client_plain_text
    virtual int output_client_plain_text(const byte_t* bytes, size_t length) {
        int err = 0;
        const bool verbose = this->verbose_output();
        
        if ((bytes) && (length)) {
            byte_array_t& client_decipher_text = this->client_decipher_text();
            byte_t* out = 0; size_t size = 0;
            
            if ((out = client_decipher_text.has_elements(size))) {
                const byte_array_t& write_key = this->write_key();
                const byte_t* write_key_bytes = 0; size_t write_key_length = 0;
                
                if ((write_key_bytes = write_key.has_elements(write_key_length))) {
                    const byte_array_t& write_IV = this->write_IV();
                    const byte_t* write_IV_bytes = 0; size_t write_IV_length = 0;
                    
                    if ((write_IV_bytes = write_IV.has_elements(write_IV_length))) {
                        xos::crypto::cipher::implemented::aes aes
                        (write_key_bytes, write_key_length, write_IV_bytes, write_IV_length);
                        size_t plain_length = 0;

                        if (0 < (plain_length = aes.decrypt(out, size, bytes, length))) {
                            const char_t* chars = 0;

                            if ((verbose)) {
                                this->outln("client_decipher_text:\\");
                                this->output_x(out, plain_length);
                                this->outln();
                            }
                            if ((chars = ((const char_t*)out))) {
                                literal_string_t& client_plain_text = this->client_plain_text();
                                
                                client_plain_text.assign(chars);
                                if ((chars = client_plain_text.has_chars(length))) {
                                    if ((verbose)) {
                                        this->out("client_plain_text:\"");
                                        this->out(chars, length);
                                        this->outln("\"");
                                    }
                                    err = output_cipher_text();
                                }
                            }
                        }
                    }
                }
            }
        }
        return err;
    }
    /// ...output_cipher_text
    virtual int output_cipher_text() {
        int err = 0;
        const bool verbose = this->verbose_output();
        literal_string_t &client_plain_text = this->client_plain_text(), 
                          &server_plain_text = this->server_plain_text();
        const char_t* chars = 0; size_t length = 0;

        if (!(chars = server_plain_text.has_chars(length))) {
            chars = client_plain_text.has_chars(length);
        } else {
            if ((verbose)) {
                this->out("server_plain_text:\"");
                this->out(chars, length);
                this->outln("\"");
            }
        }
        if ((chars) && (length)) {
            byte_array_t &encipher_text = this->encipher_text(), &cipher_text = this->cipher_text();
            byte_t* out = 0; size_t size = 0;

            if ((out = encipher_text.has_elements(size))) {
                const byte_array_t& write_key = this->write_key();
                const byte_t* write_key_bytes = 0; size_t write_key_length = 0;
                
                if ((write_key_bytes = write_key.has_elements(write_key_length))) {
                    const byte_array_t& write_IV = this->write_IV();
                    const byte_t* write_IV_bytes = 0; size_t write_IV_length = 0;
                    
                    if ((write_IV_bytes = write_IV.has_elements(write_IV_length))) {
                        xos::crypto::cipher::implemented::aes aes
                        (write_key_bytes, write_key_length, write_IV_bytes, write_IV_length);
                        size_t cipher_length = 0;

                        if (0 < (cipher_length = aes.encrypt(out, size, chars, length))) {
                            byte_array_t& write_MAC_key = this->write_MAC_key();
                            uint8_t write_MAC_length = 0, write_MAC_key_length = 0;

                            cipher_text.assign(out, cipher_length);
                            if ((verbose)) {
                                this->outln("cipher_text:\\");
                                this->output_hex(cipher_text);
                                this->outln();
                            }
                            if ((write_MAC_length = xos::crypto::hash::sha256::HASHSIZE) 
                                && (write_MAC_key_length = write_MAC_key.length())) {
                                xos::protocol::crypto::pseudo::random::reader::seed_t random_reader_seed = 0;
                                xos::protocol::crypto::pseudo::random::reader random_reader(random_reader_seed);
                                byte_array_t generic_block_cipher_IV;
                                byte_t* generic_block_cipher_IV_bytes = 0; uint8_t generic_block_cipher_IV_length = 0;
                                
                                generic_block_cipher_IV.set_length(write_IV_length);
                                if ((generic_block_cipher_IV_bytes = generic_block_cipher_IV.has_elements()) 
                                    && (write_IV_length == (generic_block_cipher_IV_length = generic_block_cipher_IV.length()))) {
                                    
                                    if (write_IV_length == (random_reader.read
                                        (generic_block_cipher_IV_bytes, generic_block_cipher_IV_length))) {
                                        xos::protocol::tls::generic::block::cipher generic_block_cipher(generic_block_cipher_IV, cipher_text);
                                        byte_t* generic_block_cipher_bytes = 0; size_t generic_block_cipher_length = 0;
    
                                        if ((verbose)) {
                                            this->outlln("generic_block_cipher_IV[", unsigned_to_string(generic_block_cipher_IV_length).chars(), "]:\\", null);
                                            this->output_hex(generic_block_cipher_IV);
                                            this->outln();
                                        }
                                        if ((verbose)) {
                                            this->outln("generic_block_cipher:\\");
                                            this->output_hex(generic_block_cipher);
                                            this->outln();
                                        }
                                        if ((generic_block_cipher_bytes = generic_block_cipher.has_elements(generic_block_cipher_length))) {
                                            xos::protocol::tls::protocol::version& protocol_version = this->protocol_version();
                                            xos::protocol::tls::content::type content_type(xos::protocol::tls::content::type::application_data);
                                            xos::protocol::tls::ciphertext ciphertext(content_type, protocol_version, generic_block_cipher);
                                            byte_t* ciphertext_bytes = 0; size_t ciphertext_length = 0;
                                            
                                            if ((ciphertext_bytes = ciphertext.has_elements(ciphertext_length))) {
                                                
                                                if ((verbose)) {
                                                    this->outln("cipher_text:\\");
                                                }
                                                this->output_hex(ciphertext);
                                                if ((verbose)) {
                                                    this->outln();
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        return err;
    }
    /// ...
    /// ...client...hello
    /// 

    /// ...output_server_hello_messages
    virtual int output_server_hello_messages() {
        int err = 0;
        const xos::protocol::tls::byte_arrays_t& server_hello_messages = this->server_hello_messages();
        xos::protocol::tls::byte_array_t*const* arrays = 0; size_t arrays_length = 0;
        
        if ((arrays = server_hello_messages.has_elements(arrays_length))) {
            if ((err = output_server_hello_messages(arrays, arrays_length))) {
            }
        }
        return err;
    }
    virtual int output_server_hello_messages(xos::protocol::tls::byte_array_t*const* arrays, size_t arrays_length) {
        int err = 0;

        if ((arrays) && (arrays_length)) {
            const bool verbose = this->verbose_output();

            for (const xos::protocol::tls::byte_array_t* array = *arrays; 
                 (array) && (arrays_length); --arrays_length, ++arrays, array = *arrays) {
                if ((verbose)) {
                    this->outln("byte_array:\\");
                }
                this->output_hex(*array);
                if ((verbose)) {
                    this->outln();
                }
            }
        }
        return err;
    }

    /// ...output_server_hello_message
    virtual int output_server_hello_message() {
        int err = 0;
        const xos::protocol::tls::byte_arrays_t& client_hello_messages = this->client_hello_messages();
        xos::protocol::tls::byte_array_t*const* arrays = 0; size_t arrays_length = 0;
        /*literal_string_t &client_plain_text = this->client_plain_text(), 
                          &server_plain_text = this->server_plain_text();
        const char_t* chars = 0; size_t length = 0;*/

        if ((arrays = client_hello_messages.has_elements(arrays_length))) {
            if ((err = output_client_hello_messages(arrays, arrays_length))) {
            }
        } else {
            literal_string_t &client_plain_text = this->client_plain_text(), 
                              &server_plain_text = this->server_plain_text();
            const char_t* chars = 0; size_t length = 0;
    
            if (!(chars = server_plain_text.has_chars(length))) {
                chars = client_plain_text.has_chars(length);
            }
            if ((err = output_server_hello_message(chars, length))) {
            }
        }
        /*if (!(chars = server_plain_text.has_chars(length))) {
            chars = client_plain_text.has_chars(length);
        }
        if ((chars) && (length)) {
            const bool verbose = this->verbose_output();
    
            if ((verbose)) {
                this->out("server_plain_text:\"");
            }
            this->out(chars, length);
            if ((verbose)) {
                this->outln("\"");
            }
        }*/
        return err;
    }
    virtual int output_server_hello_message(const char_t* chars, size_t length) {
        int err = 0;
 
        if ((chars) && (length)) {
            const bool verbose = this->verbose_output();
    
            if ((verbose)) {
                this->out("server_plain_text:\"");
            }
            this->out(chars, length);
            if ((verbose)) {
                this->outln("\"");
            }
        }
        return err;
    }

    /// ...option...
    virtual int on_set_client_hello_option(const char_t* optarg) {
        int err = 0;
        if ((optarg) && (optarg[0])) {
            client_hello_messages_string_.assign(optarg);
            err = this->on_set_hex_literal_array(client_hello_messages_, client_hello_messages_string_);
        }
        return err;
    }
    virtual int on_set_client_hello_option(const char_t* optarg, size_t length) {
        int err = 0;
        if ((optarg) && (length)) {
            client_hello_messages_string_.assign(optarg, length);
            err = this->on_set_hex_literal_array(client_hello_messages_, client_hello_messages_string_);
        }
        return err;
    }
    virtual int on_set_server_hello_option(const char_t* optarg) {
        int err = 0;
        if ((optarg) && (optarg[0])) {
            server_hello_messages_string_.assign(optarg);
            err = this->on_set_hex_literal_array(server_hello_messages_, server_hello_messages_string_);
        }
        return err;
    }
    virtual int on_set_server_hello_message_option(const char_t* optarg) {
        int err = 0;
        if ((optarg) && (optarg[0])) {
            const byte_t* bytes = 0; size_t length = 0;
            literal_string_.assign(optarg);
            this->on_set_text_literal(literal_, literal_string_);
            if ((bytes = literal_.has_elements(length))) {
                server_plain_text_.assign(((const char_t*)bytes), length);
            }
        }
        return err;
    }

    /// ...expect..._server_key_exchange
    virtual bool& set_expect_client_key_exchange_only(const bool to = true) {
        return set_expect_server_key_exchange(!to);
    }
    virtual bool& set_expect_server_key_exchange(const bool to = true) {
        bool& expect_server_key_exchange = this->expect_server_key_exchange();
        expect_server_key_exchange = to;
        return expect_server_key_exchange;
    }
    virtual bool& expect_server_key_exchange() const {
        return (bool&)expect_server_key_exchange_;
    }
    virtual bool& set_expecting_server_key_exchange(const bool to = true) {
        bool& expecting_server_key_exchange = this->expecting_server_key_exchange();
        expecting_server_key_exchange = to;
        return expecting_server_key_exchange;
    }
    virtual bool& expecting_server_key_exchange() const {
        return (bool&)expecting_server_key_exchange_;
    }

    /// ...hello_messages...
    /// ...client...
    virtual plaintext_messages_t& client_hello_messages() const {
        return (plaintext_messages_t&)client_hello_messages_;
    }
    virtual size_t& client_chello_messages_size() const {
        return (size_t&)client_hello_messages_size_;
    }
    virtual literal_string_t& client_chello_messages_string() const {
        return (literal_string_t&)client_hello_messages_string_;
    }
    /// ...server...
    virtual plaintext_messages_t& server_hello_messages() const {
        return (plaintext_messages_t&)server_hello_messages_;
    }
    virtual size_t& server_chello_messages_size() const {
        return (size_t&)server_hello_messages_size_;
    }
    virtual literal_string_t& server_chello_messages_string() const {
        return (literal_string_t&)server_hello_messages_string_;
    }

    /// ...cipher_text...
    virtual byte_t* client_decipher_text_bytes(size_t& length) const {
        return client_decipher_text_.has_elements(length);
    }
    virtual byte_array_t& client_decipher_text() const {
        return (byte_array_t&)client_decipher_text_;
    }
    virtual size_t& client_decipher_text_size() const {
        return (size_t&)client_decipher_text_size_;
    }

    /// ...plain_text...
    virtual const char_t* client_plain_text_chars(size_t& length) const {
        const literal_string_t& client_plain_text = this->client_plain_text();
        return client_plain_text.has_chars(length);
    }
    virtual literal_string_t& client_plain_text() const {
        return (literal_string_t&)client_plain_text_;
    }
    virtual const char_t* server_plain_text_chars(size_t& length) const {
        const literal_string_t& server_plain_text = this->server_plain_text();
        return server_plain_text.has_chars(length);
    }
    virtual literal_string_t& server_plain_text() const {
        return (literal_string_t&)server_plain_text_;
    }

    /// client...
    virtual byte_array_t& client_hello_protocol_version() const {
        return (byte_array_t&)client_hello_protocol_version_;
    }
    virtual byte_array_t& client_hello_random() const {
        return (byte_array_t&)client_hello_random_;
    }
    virtual byte_array_t& client_pre_master_secret() const {
        return (byte_array_t&)client_pre_master_secret_;
    }
    virtual byte_array_t& server_pre_master_secret() const {
        return (byte_array_t&)server_pre_master_secret_;
    }

    /// ...
    virtual byte_array_t& encipher_text() const {
        return (byte_array_t&)encipher_text_;
    }
    virtual byte_array_t& cipher_text() const {
        return (byte_array_t&)cipher_text_;
    }
    virtual byte_array_t& write_MAC_key() const {
        return (byte_array_t&)write_MAC_key_;
    }
    virtual byte_array_t& write_key() const {
        return (byte_array_t&)write_key_;
    }
    virtual byte_array_t& write_IV() const {
        return (byte_array_t&)write_IV_;
    }
    
    /// security_parameters
    virtual security_parameters_t& security_parameters() const {
        return (security_parameters_t&)security_parameters_;
    }

    /// ...output_hello_message
    virtual bool& set_output_hello_message(const bool to = true) {
        bool& output_hello_message = this->output_hello_message();
        output_hello_message = to;
        return output_hello_message;
    }
    virtual bool& output_hello_message() const {
        return (bool&)output_hello_message_;
    }

protected:
    bool expect_server_key_exchange_, expecting_server_key_exchange_, output_hello_message_;

    size_t client_hello_messages_size_, client_decipher_text_size_, server_hello_messages_size_;
    
    literal_string_t client_hello_messages_string_, server_hello_messages_string_;
    
    plaintext_messages_t client_hello_messages_, server_hello_messages_;
    
    byte_array_t client_hello_protocol_version_, client_hello_random_, 
                 client_pre_master_secret_, server_pre_master_secret_, client_decipher_text_;

    literal_string_t client_plain_text_, server_plain_text_, literal_string_;
    
    byte_array_t encipher_text_, cipher_text_, literal_, 
                 master_secret_, write_MAC_key_, write_key_, write_IV_;

    security_parameters_t security_parameters_;
}; /// class outputt
typedef outputt<> output;

} /// namespace server
} /// namespace udtp
} /// namespace protocol
} /// namespace xos

#endif /// ndef XOS_PROTOCOL_UDTP_SERVER_OUTPUT_HPP
