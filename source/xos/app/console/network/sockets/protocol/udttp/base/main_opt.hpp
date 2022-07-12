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
///   Date: 7/1/2022
///////////////////////////////////////////////////////////////////////
#ifndef XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_OPT_HPP
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_OPT_HPP

#include "xos/app/console/network/sockets/protocol/http/base/main.hpp"
#include "xos/app/console/network/sockets/protocol/http/client/main.hpp"
#include "xos/app/console/network/sockets/protocol/http/server/main.hpp"

#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_KEY_PAIR_OPT "rsa-key-pair"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_KEY_PAIR_OPTARG_REQUIRED MAIN_OPT_ARGUMENT_OPTIONAL
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_KEY_PAIR_OPTARG_RESULT 0
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_KEY_PAIR_OPTARG "[string]"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_KEY_PAIR_OPTUSE "rsa key pair"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_KEY_PAIR_OPTVAL_S "k::"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_KEY_PAIR_OPTVAL_C 'k'
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_KEY_PAIR_OPTION \
   {XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_KEY_PAIR_OPT, \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_KEY_PAIR_OPTARG_REQUIRED, \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_KEY_PAIR_OPTARG_RESULT, \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_KEY_PAIR_OPTVAL_C}, \

#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_CLIENT_RSA_KEY_PAIR_OPT "client-rsa-key-pair"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_CLIENT_RSA_KEY_PAIR_OPTARG_REQUIRED MAIN_OPT_ARGUMENT_OPTIONAL
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_CLIENT_RSA_KEY_PAIR_OPTARG_RESULT 0
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_CLIENT_RSA_KEY_PAIR_OPTARG "[string]"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_CLIENT_RSA_KEY_PAIR_OPTUSE "client rsa key pair"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_CLIENT_RSA_KEY_PAIR_OPTVAL_S "r::"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_CLIENT_RSA_KEY_PAIR_OPTVAL_C 'r'
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_CLIENT_RSA_KEY_PAIR_OPTION \
   {XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_CLIENT_RSA_KEY_PAIR_OPT, \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_CLIENT_RSA_KEY_PAIR_OPTARG_REQUIRED, \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_CLIENT_RSA_KEY_PAIR_OPTARG_RESULT, \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_CLIENT_RSA_KEY_PAIR_OPTVAL_C}, \

/*#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PUBLIC_KEY_OPT "rsa-public-key"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PUBLIC_KEY_OPTARG_REQUIRED MAIN_OPT_ARGUMENT_OPTIONAL
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PUBLIC_KEY_OPTARG_RESULT 0
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PUBLIC_KEY_OPTARG "[string]"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PUBLIC_KEY_OPTUSE "rsa public key"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PUBLIC_KEY_OPTVAL_S "u::"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PUBLIC_KEY_OPTVAL_C 'u'
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PUBLIC_KEY_OPTION \
   {XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PUBLIC_KEY_OPT, \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PUBLIC_KEY_OPTARG_REQUIRED, \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PUBLIC_KEY_OPTARG_RESULT, \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PUBLIC_KEY_OPTVAL_C}, \

#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PRIVATE_KEY_OPT "rsa-private-key"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PRIVATE_KEY_OPTARG_REQUIRED MAIN_OPT_ARGUMENT_OPTIONAL
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PRIVATE_KEY_OPTARG_RESULT 0
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PRIVATE_KEY_OPTARG "[string]"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PRIVATE_KEY_OPTUSE "rsa private key"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PRIVATE_KEY_OPTVAL_S "r::"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PRIVATE_KEY_OPTVAL_C 'r'
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PRIVATE_KEY_OPTION \
   {XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PRIVATE_KEY_OPT, \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PRIVATE_KEY_OPTARG_REQUIRED, \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PRIVATE_KEY_OPTARG_RESULT, \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PRIVATE_KEY_OPTVAL_C}, \*/

#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_PSEUDO_RANDOM_SECRET_OPT "pseudo-random-secret"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_PSEUDO_RANDOM_SECRET_OPTARG_REQUIRED MAIN_OPT_ARGUMENT_OPTIONAL
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_PSEUDO_RANDOM_SECRET_OPTARG_RESULT 0
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_PSEUDO_RANDOM_SECRET_OPTARG "[string]"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_PSEUDO_RANDOM_SECRET_OPTUSE "pseudo random secret"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_PSEUDO_RANDOM_SECRET_OPTVAL_S "s::"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_PSEUDO_RANDOM_SECRET_OPTVAL_C 's'
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_PSEUDO_RANDOM_SECRET_OPTION \
   {XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_PSEUDO_RANDOM_SECRET_OPT, \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_PSEUDO_RANDOM_SECRET_OPTARG_REQUIRED, \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_PSEUDO_RANDOM_SECRET_OPTARG_RESULT, \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_PSEUDO_RANDOM_SECRET_OPTVAL_C}, \

#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_PSEUDO_RANDOM_SEED_OPT "pseudo-random-seed"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_PSEUDO_RANDOM_SEED_OPTARG_REQUIRED MAIN_OPT_ARGUMENT_OPTIONAL
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_PSEUDO_RANDOM_SEED_OPTARG_RESULT 0
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_PSEUDO_RANDOM_SEED_OPTARG "[string]"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_PSEUDO_RANDOM_SEED_OPTUSE "pseudo random seed"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_PSEUDO_RANDOM_SEED_OPTVAL_S "e::"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_PSEUDO_RANDOM_SEED_OPTVAL_C 'e'
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_PSEUDO_RANDOM_SEED_OPTION \
   {XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_PSEUDO_RANDOM_SEED_OPT, \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_PSEUDO_RANDOM_SEED_OPTARG_REQUIRED, \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_PSEUDO_RANDOM_SEED_OPTARG_RESULT, \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_PSEUDO_RANDOM_SEED_OPTVAL_C}, \

#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_MASTER_SECRET_SEED_OPT "master-secret-seed"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_MASTER_SECRET_SEED_OPTARG_REQUIRED MAIN_OPT_ARGUMENT_OPTIONAL
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_MASTER_SECRET_SEED_OPTARG_RESULT 0
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_MASTER_SECRET_SEED_OPTARG "[string]"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_MASTER_SECRET_SEED_OPTUSE "master secret seed"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_MASTER_SECRET_SEED_OPTVAL_S "t::"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_MASTER_SECRET_SEED_OPTVAL_C 't'
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_MASTER_SECRET_SEED_OPTION \
   {XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_MASTER_SECRET_SEED_OPT, \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_MASTER_SECRET_SEED_OPTARG_REQUIRED, \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_MASTER_SECRET_SEED_OPTARG_RESULT, \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_MASTER_SECRET_SEED_OPTVAL_C}, \

#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_KEY_EXPANSION_SEED_OPT "key-expansion-seed"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_KEY_EXPANSION_SEED_OPTARG_REQUIRED MAIN_OPT_ARGUMENT_OPTIONAL
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_KEY_EXPANSION_SEED_OPTARG_RESULT 0
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_KEY_EXPANSION_SEED_OPTARG "[string]"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_KEY_EXPANSION_SEED_OPTUSE "key expansion seed"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_KEY_EXPANSION_SEED_OPTVAL_S "x::"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_KEY_EXPANSION_SEED_OPTVAL_C 'x'
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_KEY_EXPANSION_SEED_OPTION \
   {XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_KEY_EXPANSION_SEED_OPT, \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_KEY_EXPANSION_SEED_OPTARG_REQUIRED, \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_KEY_EXPANSION_SEED_OPTARG_RESULT, \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_KEY_EXPANSION_SEED_OPTVAL_C}, \

#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_FILE_INPUT_OPT "file-input"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_FILE_INPUT_OPTARG_REQUIRED MAIN_OPT_ARGUMENT_NONE
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_FILE_INPUT_OPTARG_RESULT 0
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_FILE_INPUT_OPTARG ""
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_FILE_INPUT_OPTUSE "file input"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_FILE_INPUT_OPTVAL_S "f"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_FILE_INPUT_OPTVAL_C 'f'
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_FILE_INPUT_OPTION \
   {XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_FILE_INPUT_OPT, \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_FILE_INPUT_OPTARG_REQUIRED, \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_FILE_INPUT_OPTARG_RESULT, \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_FILE_INPUT_OPTVAL_C}, \

#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_STRING_INPUT_OPT "string-input"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_STRING_INPUT_OPTARG_REQUIRED MAIN_OPT_ARGUMENT_NONE
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_STRING_INPUT_OPTARG_RESULT 0
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_STRING_INPUT_OPTARG ""
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_STRING_INPUT_OPTUSE "string input"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_STRING_INPUT_OPTVAL_S "i::"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_STRING_INPUT_OPTVAL_C 'i'
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_STRING_INPUT_OPTION \
   {XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_STRING_INPUT_OPT, \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_STRING_INPUT_OPTARG_REQUIRED, \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_STRING_INPUT_OPTARG_RESULT, \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_STRING_INPUT_OPTVAL_C}, \

#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_VERBOSE_OPT "verbose"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_VERBOSE_OPTARG_REQUIRED MAIN_OPT_ARGUMENT_NONE
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_VERBOSE_OPTARG_RESULT 0
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_VERBOSE_OPTARG ""
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_VERBOSE_OPTUSE "verbose output"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_VERBOSE_OPTVAL_S "v"
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_VERBOSE_OPTVAL_C 'v'
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_VERBOSE_OPTION \
   {XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_VERBOSE_OPT, \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_VERBOSE_OPTARG_REQUIRED, \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_VERBOSE_OPTARG_RESULT, \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_VERBOSE_OPTVAL_C}, \

///////////////////////////////////////////////////////////////////////
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_OPTIONS_CHARS_EXTEND \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_KEY_PAIR_OPTVAL_S \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_CLIENT_RSA_KEY_PAIR_OPTVAL_S \
    /*XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PUBLIC_KEY_OPTVAL_S \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PRIVATE_KEY_OPTVAL_S \
    */XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_PSEUDO_RANDOM_SECRET_OPTVAL_S \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_PSEUDO_RANDOM_SEED_OPTVAL_S \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_MASTER_SECRET_SEED_OPTVAL_S \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_KEY_EXPANSION_SEED_OPTVAL_S \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_FILE_INPUT_OPTVAL_S \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_STRING_INPUT_OPTVAL_S \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_VERBOSE_OPTVAL_S \

#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_OPTIONS_OPTIONS_EXTEND \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_KEY_PAIR_OPTION \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_CLIENT_RSA_KEY_PAIR_OPTION \
    /*XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PUBLIC_KEY_OPTION \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PRIVATE_KEY_OPTION \
    */XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_PSEUDO_RANDOM_SECRET_OPTION \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_PSEUDO_RANDOM_SEED_OPTION \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_MASTER_SECRET_SEED_OPTION \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_KEY_EXPANSION_SEED_OPTION \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_FILE_INPUT_OPTION \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_STRING_INPUT_OPTION \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_VERBOSE_OPTION \

///////////////////////////////////////////////////////////////////////
#if defined(XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_CLIENT_MAIN_OPT_HPP)
///
/// client
/// 
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_WHICH_MAIN_OPTIONS_CHARS_EXTEND \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_OPTIONS_CHARS_EXTEND \

#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_WHICH_MAIN_OPTIONS_OPTIONS_EXTEND \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_OPTIONS_OPTIONS_EXTEND \

#elif defined(XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_SERVER_MAIN_OPT_HPP)
///
/// server
/// 
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_WHICH_MAIN_OPTIONS_CHARS_EXTEND \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_KEY_PAIR_OPTVAL_S \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_CLIENT_RSA_KEY_PAIR_OPTVAL_S \
    /*XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PUBLIC_KEY_OPTVAL_S \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PRIVATE_KEY_OPTVAL_S \
    */XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_MASTER_SECRET_SEED_OPTVAL_S \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_KEY_EXPANSION_SEED_OPTVAL_S \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_FILE_INPUT_OPTVAL_S \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_STRING_INPUT_OPTVAL_S \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_VERBOSE_OPTVAL_S \

#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_WHICH_MAIN_OPTIONS_OPTIONS_EXTEND \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_KEY_PAIR_OPTION \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_CLIENT_RSA_KEY_PAIR_OPTION \
    /*XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PUBLIC_KEY_OPTION \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PRIVATE_KEY_OPTION \
    */XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_MASTER_SECRET_SEED_OPTION \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_KEY_EXPANSION_SEED_OPTION \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_FILE_INPUT_OPTION \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_STRING_INPUT_OPTION \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_VERBOSE_OPTION \

#else /// defined(XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_CLIENT_MAIN_OPT_HPP)
///
/// base
/// 
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_WHICH_MAIN_OPTIONS_CHARS_EXTEND \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_OPTIONS_CHARS_EXTEND \

#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_WHICH_MAIN_OPTIONS_OPTIONS_EXTEND \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_OPTIONS_OPTIONS_EXTEND \

#endif /// defined(XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_CLIENT_MAIN_OPT_HPP)

///////////////////////////////////////////////////////////////////////
#if defined(XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_CLIENT_MAIN_OPT_HPP)
///
/// client
/// 
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_XTTP_WHICH_MAIN_OPTIONS_CHARS \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_XTTP_CLIENT_MAIN_QUERY_OPTIONS_CHARS

#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_XTTP_WHICH_MAIN_OPTIONS_OPTIONS \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_XTTP_CLIENT_MAIN_QUERY_OPTIONS_OPTIONS

#elif defined(XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_SERVER_MAIN_OPT_HPP)
///
/// server
/// 
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_XTTP_WHICH_MAIN_OPTIONS_CHARS \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_XTTP_SERVER_MAIN_ACCEPT_OPTIONS_CHARS

#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_XTTP_WHICH_MAIN_OPTIONS_OPTIONS \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_XTTP_SERVER_MAIN_ACCEPT_OPTIONS_OPTIONS

#else /// defined(XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_CLIENT_MAIN_OPT_HPP)
///
/// base
/// 
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_XTTP_WHICH_MAIN_OPTIONS_CHARS \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_XTTP_BASE_MAIN_LOGGING_OPTIONS_CHARS

#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_XTTP_WHICH_MAIN_OPTIONS_OPTIONS \
    XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_XTTP_BASE_MAIN_LOGGING_OPTIONS_OPTIONS

#endif /// defined(XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_CLIENT_MAIN_OPT_HPP)

///////////////////////////////////////////////////////////////////////
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_OPTIONS_CHARS \
   XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_WHICH_MAIN_OPTIONS_CHARS_EXTEND \
   XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_XTTP_WHICH_MAIN_OPTIONS_CHARS

#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_OPTIONS_OPTIONS \
   XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_WHICH_MAIN_OPTIONS_OPTIONS_EXTEND \
   XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_XTTP_WHICH_MAIN_OPTIONS_OPTIONS

#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_ARGS 0
#define XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_ARGV 0,

namespace xos {
namespace app {
namespace console {
namespace network {
namespace sockets {
namespace protocol {
namespace udttp {
namespace base {

/// class main_optt
template 
<class TExtends = xos::app::console::network::sockets::protocol::http::base::main, 
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

    /// ...output_client_key_pair_run
    int (derives::*output_client_key_pair_run_)(int argc, char_t** argv, char_t** env);
    virtual int output_client_key_pair_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        if (output_client_key_pair_run_) {
            err = (this->*output_client_key_pair_run_)(argc, argv, env);
        } else {
            err = default_output_client_key_pair_run(argc, argv, env);
        }
        return err;
    }
    virtual int default_output_client_key_pair_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        return err;
    }
    virtual int before_output_client_key_pair_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        return err;
    }
    virtual int after_output_client_key_pair_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        return err;
    }
    virtual int all_output_client_key_pair_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        if (!(err = before_output_client_key_pair_run(argc, argv, env))) {
            int err2 = 0;
            err = output_client_key_pair_run(argc, argv, env);
            if ((err2 = after_output_client_key_pair_run(argc, argv, env))) {
                if (!(err)) err = err2;
            }
        }
        return err;
    }
    virtual int set_output_client_key_pair_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        run_ = &derives::all_output_client_key_pair_run;
        return err;
    }

    /// ...output_key_pair_run
    int (derives::*output_key_pair_run_)(int argc, char_t** argv, char_t** env);
    virtual int output_key_pair_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        if (output_key_pair_run_) {
            err = (this->*output_key_pair_run_)(argc, argv, env);
        } else {
            err = default_output_key_pair_run(argc, argv, env);
        }
        return err;
    }
    virtual int default_output_key_pair_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        return err;
    }
    virtual int before_output_key_pair_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        return err;
    }
    virtual int after_output_key_pair_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        return err;
    }
    virtual int all_output_key_pair_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        if (!(err = before_output_key_pair_run(argc, argv, env))) {
            int err2 = 0;
            err = output_key_pair_run(argc, argv, env);
            if ((err2 = after_output_key_pair_run(argc, argv, env))) {
                if (!(err)) err = err2;
            }
        }
        return err;
    }
    virtual int set_output_key_pair_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        run_ = &derives::all_output_key_pair_run;
        return err;
    }

    /*/// ...output_private_key_run
    int (derives::*output_private_key_run_)(int argc, char_t** argv, char_t** env);
    virtual int output_private_key_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        if (output_private_key_run_) {
            err = (this->*output_private_key_run_)(argc, argv, env);
        } else {
            err = default_output_private_key_run(argc, argv, env);
        }
        return err;
    }
    virtual int default_output_private_key_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        return err;
    }
    virtual int before_output_private_key_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        return err;
    }
    virtual int after_output_private_key_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        return err;
    }
    virtual int all_output_private_key_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        if (!(err = before_output_private_key_run(argc, argv, env))) {
            int err2 = 0;
            err = output_private_key_run(argc, argv, env);
            if ((err2 = after_output_private_key_run(argc, argv, env))) {
                if (!(err)) err = err2;
            }
        }
        return err;
    }
    virtual int set_output_private_key_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        run_ = &derives::all_output_private_key_run;
        return err;
    }

    /// ...output_public_key_run
    int (derives::*output_public_key_run_)(int argc, char_t** argv, char_t** env);
    virtual int output_public_key_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        if (output_public_key_run_) {
            err = (this->*output_public_key_run_)(argc, argv, env);
        } else {
            err = default_output_public_key_run(argc, argv, env);
        }
        return err;
    }
    virtual int default_output_public_key_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        return err;
    }
    virtual int before_output_public_key_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        return err;
    }
    virtual int after_output_public_key_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        return err;
    }
    virtual int all_output_public_key_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        if (!(err = before_output_public_key_run(argc, argv, env))) {
            int err2 = 0;
            err = output_public_key_run(argc, argv, env);
            if ((err2 = after_output_public_key_run(argc, argv, env))) {
                if (!(err)) err = err2;
            }
        }
        return err;
    }
    virtual int set_output_public_key_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        run_ = &derives::all_output_public_key_run;
        return err;
    }*/

    /// ...output_pseudo_random_secret_run
    int (derives::*output_pseudo_random_secret_run_)(int argc, char_t** argv, char_t** env);
    virtual int output_pseudo_random_secret_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        if (output_pseudo_random_secret_run_) {
            err = (this->*output_pseudo_random_secret_run_)(argc, argv, env);
        } else {
            err = default_output_pseudo_random_secret_run(argc, argv, env);
        }
        return err;
    }
    virtual int default_output_pseudo_random_secret_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        return err;
    }
    virtual int before_output_pseudo_random_secret_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        return err;
    }
    virtual int after_output_pseudo_random_secret_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        return err;
    }
    virtual int all_output_pseudo_random_secret_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        if (!(err = before_output_pseudo_random_secret_run(argc, argv, env))) {
            int err2 = 0;
            err = output_pseudo_random_secret_run(argc, argv, env);
            if ((err2 = after_output_pseudo_random_secret_run(argc, argv, env))) {
                if (!(err)) err = err2;
            }
        }
        return err;
    }
    virtual int set_output_pseudo_random_secret_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        run_ = &derives::all_output_pseudo_random_secret_run;
        return err;
    }

    /// ...output_pseudo_random_seed_run
    int (derives::*output_pseudo_random_seed_run_)(int argc, char_t** argv, char_t** env);
    virtual int output_pseudo_random_seed_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        if (output_pseudo_random_seed_run_) {
            err = (this->*output_pseudo_random_seed_run_)(argc, argv, env);
        } else {
            err = default_output_pseudo_random_seed_run(argc, argv, env);
        }
        return err;
    }
    virtual int default_output_pseudo_random_seed_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        return err;
    }
    virtual int before_output_pseudo_random_seed_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        return err;
    }
    virtual int after_output_pseudo_random_seed_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        return err;
    }
    virtual int all_output_pseudo_random_seed_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        if (!(err = before_output_pseudo_random_seed_run(argc, argv, env))) {
            int err2 = 0;
            err = output_pseudo_random_seed_run(argc, argv, env);
            if ((err2 = after_output_pseudo_random_seed_run(argc, argv, env))) {
                if (!(err)) err = err2;
            }
        }
        return err;
    }
    virtual int set_output_pseudo_random_seed_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        run_ = &derives::all_output_pseudo_random_seed_run;
        return err;
    }

    /// ...output_master_secret_seed_run
    int (derives::*output_master_secret_seed_run_)(int argc, char_t** argv, char_t** env);
    virtual int output_master_secret_seed_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        if (output_master_secret_seed_run_) {
            err = (this->*output_master_secret_seed_run_)(argc, argv, env);
        } else {
            err = default_output_master_secret_seed_run(argc, argv, env);
        }
        return err;
    }
    virtual int default_output_master_secret_seed_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        return err;
    }
    virtual int before_output_master_secret_seed_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        return err;
    }
    virtual int after_output_master_secret_seed_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        return err;
    }
    virtual int all_output_master_secret_seed_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        if (!(err = before_output_master_secret_seed_run(argc, argv, env))) {
            int err2 = 0;
            err = output_master_secret_seed_run(argc, argv, env);
            if ((err2 = after_output_master_secret_seed_run(argc, argv, env))) {
                if (!(err)) err = err2;
            }
        }
        return err;
    }
    virtual int set_output_master_secret_seed_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        run_ = &derives::all_output_master_secret_seed_run;
        return err;
    }

    /// ...output_key_expansion_seed_run
    int (derives::*output_key_expansion_seed_run_)(int argc, char_t** argv, char_t** env);
    virtual int output_key_expansion_seed_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        if (output_key_expansion_seed_run_) {
            err = (this->*output_key_expansion_seed_run_)(argc, argv, env);
        } else {
            err = default_output_key_expansion_seed_run(argc, argv, env);
        }
        return err;
    }
    virtual int default_output_key_expansion_seed_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        return err;
    }
    virtual int before_output_key_expansion_seed_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        return err;
    }
    virtual int after_output_key_expansion_seed_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        return err;
    }
    virtual int all_output_key_expansion_seed_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        if (!(err = before_output_key_expansion_seed_run(argc, argv, env))) {
            int err2 = 0;
            err = output_key_expansion_seed_run(argc, argv, env);
            if ((err2 = after_output_key_expansion_seed_run(argc, argv, env))) {
                if (!(err)) err = err2;
            }
        }
        return err;
    }
    virtual int set_output_key_expansion_seed_run(int argc, char_t** argv, char_t** env) {
        int err = 0;
        run_ = &derives::all_output_key_expansion_seed_run;
        return err;
    }

    /// ...option...
    virtual int on_set_client_rsa_key_pair_option
    (const char_t* optarg, int argc, char_t**argv, char_t**env) {
        int err = 0;
        if ((optarg) && (optarg[0])) {
        }
        return err;
    }
    virtual int on_client_rsa_key_pair_option
    (int optval, const char_t* optarg, const char_t* optname,
     int optind, int argc, char_t**argv, char_t**env) {
        int err = 0;
        if ((optarg) && (optarg[0])) {
            if (!(err = on_set_client_rsa_key_pair_option(optarg, argc, argv, env))) {
            }
        } else {
            if (!(err = set_output_client_key_pair_run(argc, argv, env))) {
            }
        }
        return err;
    }
    virtual const char_t* client_rsa_key_pair_option_usage(const char_t*& optarg, const struct option* longopt) {
        const char_t* chars = XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_CLIENT_RSA_KEY_PAIR_OPTUSE;
        optarg = XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_CLIENT_RSA_KEY_PAIR_OPTARG;
        return chars;
    }
    virtual int on_set_rsa_key_pair_option
    (const char_t* optarg, int argc, char_t**argv, char_t**env) {
        int err = 0;
        if ((optarg) && (optarg[0])) {
        }
        return err;
    }
    virtual int on_rsa_key_pair_option
    (int optval, const char_t* optarg, const char_t* optname,
     int optind, int argc, char_t**argv, char_t**env) {
        int err = 0;
        if ((optarg) && (optarg[0])) {
            if (!(err = on_set_rsa_key_pair_option(optarg, argc, argv, env))) {
            }
        } else {
            if (!(err = set_output_key_pair_run(argc, argv, env))) {
            }
        }
        return err;
    }
    virtual const char_t* rsa_key_pair_option_usage(const char_t*& optarg, const struct option* longopt) {
        const char_t* chars = XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_KEY_PAIR_OPTUSE;
        optarg = XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_KEY_PAIR_OPTARG;
        return chars;
    }
    /*virtual int on_set_rsa_public_key_option
    (const char_t* optarg, int argc, char_t**argv, char_t**env) {
        int err = 0;
        if ((optarg) && (optarg[0])) {
        }
        return err;
    }
    virtual int on_rsa_public_key_option
    (int optval, const char_t* optarg, const char_t* optname,
     int optind, int argc, char_t**argv, char_t**env) {
        int err = 0;
        if ((optarg) && (optarg[0])) {
            if (!(err = on_set_rsa_public_key_option(optarg, argc, argv, env))) {
            }
        } else {
            if (!(err = set_output_public_key_run(argc, argv, env))) {
            }
        }
        return err;
    }
    virtual const char_t* rsa_public_key_option_usage(const char_t*& optarg, const struct option* longopt) {
        const char_t* chars = XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PUBLIC_KEY_OPTUSE;
        optarg = XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PUBLIC_KEY_OPTARG;
        return chars;
    }
    virtual int on_set_rsa_private_key_option
    (const char_t* optarg, int argc, char_t**argv, char_t**env) {
        int err = 0;
        if ((optarg) && (optarg[0])) {
        }
        return err;
    }
    virtual int on_rsa_private_key_option
    (int optval, const char_t* optarg, const char_t* optname,
     int optind, int argc, char_t**argv, char_t**env) {
        int err = 0;
        if ((optarg) && (optarg[0])) {
            if (!(err = on_set_rsa_private_key_option(optarg, argc, argv, env))) {
            }
        } else {
            if (!(err = set_output_private_key_run(argc, argv, env))) {
            }
        }
        return err;
    }
    virtual const char_t* rsa_private_key_option_usage(const char_t*& optarg, const struct option* longopt) {
        const char_t* chars = XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PRIVATE_KEY_OPTUSE;
        optarg = XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PRIVATE_KEY_OPTARG;
        return chars;
    }*/
    virtual int on_set_pseudo_random_secret_option
    (const char_t* optarg, int argc, char_t**argv, char_t**env) {
        int err = 0;
        if ((optarg) && (optarg[0])) {
        } else {
        }
        return err;
    }
    virtual int on_pseudo_random_secret_option
    (int optval, const char_t* optarg, const char_t* optname,
     int optind, int argc, char_t**argv, char_t**env) {
        int err = 0;
        if ((optarg) && (optarg[0])) {
            if (!(err = on_set_pseudo_random_secret_option(optarg, argc, argv, env))) {
            }
        } else {
            if (!(err = set_output_pseudo_random_secret_run(argc, argv, env))) {
            }
        }
        return err;
    }
    virtual const char_t* pseudo_random_secret_option_usage(const char_t*& optarg, const struct option* longopt) {
        const char_t* chars = XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_PSEUDO_RANDOM_SECRET_OPTUSE;
        optarg = XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_PSEUDO_RANDOM_SECRET_OPTARG;
        return chars;
    }
    virtual int on_set_pseudo_random_seed_option
    (const char_t* optarg, int argc, char_t**argv, char_t**env) {
        int err = 0;
        if ((optarg) && (optarg[0])) {
        } else {
        }
        return err;
    }
    virtual int on_pseudo_random_seed_option
    (int optval, const char_t* optarg, const char_t* optname,
     int optind, int argc, char_t**argv, char_t**env) {
        int err = 0;
        if ((optarg) && (optarg[0])) {
            if (!(err = on_set_pseudo_random_seed_option(optarg, argc, argv, env))) {
            }
        } else {
            if (!(err = set_output_pseudo_random_seed_run(argc, argv, env))) {
            }
        }
        return err;
    }
    virtual const char_t* pseudo_random_seed_option_usage(const char_t*& optarg, const struct option* longopt) {
        const char_t* chars = XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_PSEUDO_RANDOM_SEED_OPTUSE;
        optarg = XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_PSEUDO_RANDOM_SEED_OPTARG;
        return chars;
    }
    virtual int on_set_master_secret_seed_option
    (const char_t* optarg, int argc, char_t**argv, char_t**env) {
        int err = 0;
        if ((optarg) && (optarg[0])) {
        } else {
        }
        return err;
    }
    virtual int on_master_secret_seed_option
    (int optval, const char_t* optarg, const char_t* optname,
     int optind, int argc, char_t**argv, char_t**env) {
        int err = 0;
        if ((optarg) && (optarg[0])) {
            if (!(err = on_set_master_secret_seed_option(optarg, argc, argv, env))) {
            }
        } else {
            if (!(err = set_output_master_secret_seed_run(argc, argv, env))) {
            }
        }
        return err;
    }
    virtual const char_t* master_secret_seed_option_usage(const char_t*& optarg, const struct option* longopt) {
        const char_t* chars = XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_MASTER_SECRET_SEED_OPTUSE;
        optarg = XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_MASTER_SECRET_SEED_OPTARG;
        return chars;
    }
    virtual int on_set_key_expansion_seed_option
    (const char_t* optarg, int argc, char_t**argv, char_t**env) {
        int err = 0;
        if ((optarg) && (optarg[0])) {
        } else {
        }
        return err;
    }
    virtual int on_key_expansion_seed_option
    (int optval, const char_t* optarg, const char_t* optname,
     int optind, int argc, char_t**argv, char_t**env) {
        int err = 0;
        if ((optarg) && (optarg[0])) {
            if (!(err = on_set_key_expansion_seed_option(optarg, argc, argv, env))) {
            }
        } else {
            if (!(err = set_output_key_expansion_seed_run(argc, argv, env))) {
            }
        }
        return err;
    }
    virtual const char_t* key_expansion_seed_option_usage(const char_t*& optarg, const struct option* longopt) {
        const char_t* chars = XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_KEY_EXPANSION_SEED_OPTUSE;
        optarg = XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_KEY_EXPANSION_SEED_OPTARG;
        return chars;
    }
    virtual int on_file_input_option
    (int optval, const char_t* optarg, const char_t* optname,
     int optind, int argc, char_t**argv, char_t**env) {
        int err = 0;
        return err;
    }
    virtual const char_t* file_input_option_usage(const char_t*& optarg, const struct option* longopt) {
        const char_t* chars = XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_FILE_INPUT_OPTUSE;
        optarg = XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_FILE_INPUT_OPTARG;
        return chars;
    }
    virtual int on_string_input_option
    (int optval, const char_t* optarg, const char_t* optname,
     int optind, int argc, char_t**argv, char_t**env) {
        int err = 0;
        return err;
    }
    virtual const char_t* string_input_option_usage(const char_t*& optarg, const struct option* longopt) {
        const char_t* chars = XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_STRING_INPUT_OPTUSE;
        optarg = XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_STRING_INPUT_OPTARG;
        return chars;
    }
    virtual int on_verbose_option
    (int optval, const char_t* optarg, const char_t* optname,
     int optind, int argc, char_t**argv, char_t**env) {
        int err = 0;
        return err;
    }
    virtual const char_t* verbose_option_usage(const char_t*& optarg, const struct option* longopt) {
        const char_t* chars = XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_VERBOSE_OPTUSE;
        optarg = XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_VERBOSE_OPTARG;
        return chars;
    }
    virtual int on_option
    (int optval, const char_t* optarg, const char_t* optname,
     int optind, int argc, char_t**argv, char_t**env) {
        int err = 0;
        switch(optval) {

        case XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_KEY_PAIR_OPTVAL_C:
            err = this->on_rsa_key_pair_option(optval, optarg, optname, optind, argc, argv, env);
            break;
        case XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_CLIENT_RSA_KEY_PAIR_OPTVAL_C:
            err = this->on_client_rsa_key_pair_option(optval, optarg, optname, optind, argc, argv, env);
            break;
        /*case XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PUBLIC_KEY_OPTVAL_C:
            err = this->on_rsa_public_key_option(optval, optarg, optname, optind, argc, argv, env);
            break;
        case XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PRIVATE_KEY_OPTVAL_C:
            err = this->on_rsa_private_key_option(optval, optarg, optname, optind, argc, argv, env);
            break;*/

        case XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_PSEUDO_RANDOM_SECRET_OPTVAL_C:
            err = this->on_pseudo_random_secret_option(optval, optarg, optname, optind, argc, argv, env);
            break;
        case XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_PSEUDO_RANDOM_SEED_OPTVAL_C:
            err = this->on_pseudo_random_seed_option(optval, optarg, optname, optind, argc, argv, env);
            break;
        case XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_MASTER_SECRET_SEED_OPTVAL_C:
            err = this->on_master_secret_seed_option(optval, optarg, optname, optind, argc, argv, env);
            break;
        case XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_KEY_EXPANSION_SEED_OPTVAL_C:
            err = this->on_key_expansion_seed_option(optval, optarg, optname, optind, argc, argv, env);
            break;

        case XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_FILE_INPUT_OPTVAL_C:
            err = this->on_file_input_option(optval, optarg, optname, optind, argc, argv, env);
            break;
        case XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_STRING_INPUT_OPTVAL_C:
            err = this->on_string_input_option(optval, optarg, optname, optind, argc, argv, env);
            break;

        case XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_VERBOSE_OPTVAL_C:
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

        case XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_KEY_PAIR_OPTVAL_C:
            chars = this->rsa_key_pair_option_usage(optarg, longopt);
            break;
        case XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_CLIENT_RSA_KEY_PAIR_OPTVAL_C:
            chars = this->client_rsa_key_pair_option_usage(optarg, longopt);
            break;
        /*case XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PUBLIC_KEY_OPTVAL_C:
            chars = this->rsa_public_key_option_usage(optarg, longopt);
            break;
        case XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_RSA_PRIVATE_KEY_OPTVAL_C:
            chars = this->rsa_private_key_option_usage(optarg, longopt);
            break;*/

        case XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_PSEUDO_RANDOM_SECRET_OPTVAL_C:
            chars = this->pseudo_random_secret_option_usage(optarg, longopt);
            break;
        case XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_PSEUDO_RANDOM_SEED_OPTVAL_C:
            chars = this->pseudo_random_seed_option_usage(optarg, longopt);
            break;
        case XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_MASTER_SECRET_SEED_OPTVAL_C:
            chars = this->master_secret_seed_option_usage(optarg, longopt);
            break;
        case XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_KEY_EXPANSION_SEED_OPTVAL_C:
            chars = this->key_expansion_seed_option_usage(optarg, longopt);
            break;

        case XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_FILE_INPUT_OPTVAL_C:
            chars = this->file_input_option_usage(optarg, longopt);
            break;
        case XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_STRING_INPUT_OPTVAL_C:
            chars = this->string_input_option_usage(optarg, longopt);
            break;

        case XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_VERBOSE_OPTVAL_C:
            chars = this->verbose_option_usage(optarg, longopt);
            break;

        default:
            chars = extends::option_usage(optarg, longopt);
            break;
        }
        return chars;
    }
    virtual const char_t* options(const struct option*& longopts) {
        static const char_t* chars = XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_OPTIONS_CHARS;
        static struct option optstruct[]= {
            XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_OPTIONS_OPTIONS
            {0, 0, 0, 0}};
        longopts = optstruct;
        return chars;
    }

    /// ...argument...
    virtual const char_t* arguments(const char_t**& argv) {
        static const char_t* _args = XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_ARGS;
        static const char_t* _argv[] = {
            XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_ARGV
            0};
        argv = _argv;
        return _args;
    }

protected:
}; /// class main_optt
typedef main_optt<> main_opt;

} /// namespace base
} /// namespace udttp
} /// namespace protocol
} /// namespace sockets
} /// namespace network
} /// namespace console
} /// namespace app
} /// namespace xos

#endif /// ndef XOS_APP_CONSOLE_NETWORK_SOCKETS_PROTOCOL_UDTTP_BASE_MAIN_OPT_HPP
