# Release Notes #

<a name="v1.0.0"></a>
## [v1.0.0](https://github.com/OpenIDC/cjose/compare/v1.0.0...v0.6.2.3)  (2025-01-26)
* use OpenSSL 3.x non-deprecated APIs only; closes ##25
* fix memory leak in ECDH-ES JWE encryption/decryption
* fix rsa_q = NULL assignment in jwk.c _RSA_private_fields
* fix memory allocation check (typo) in jwk.c (https://github.com/OpenIDC/cjose/security/code-scanning/2)

<a name="v0.6.2.3"></a>
## [v0.6.2.3](https://github.com/OpenIDC/cjose/compare/v0.6.2.2...v0.6.2.3)  (2024-04-24)
* disable RSA PKCS 1.5 by default ((https://github.com/OpenIDC/cjose/pull/22); thanks @thalman
* avoid using empty prototypes; support Clang 15 and XCode 14.3
* build shared library on Cygwin by adding -no-undefined to LDFLAGS
  (https://github.com/OpenIDC/cjose/pull/20); thanks @fd00

<a name="v0.6.2.2"></a>
## [v0.6.2.2](https://github.com/OpenIDC/cjose/compare/v0.6.2.1...v0.6.2.2)  (2023-07-12)
* use fixed authentication tag length of 16 octets in AES GCM decryption (https://github.com/cisco/cjose/issues/125)
* avoid use of assert (https://github.com/cisco/cjose/issues/123) ; thanks @groovyfeng 
* fix make on srcdir != builddir (https://github.com/OpenIDC/cjose/pull/17) ; thanks @fd00

<a name="v0.6.2.1"></a>
## [v0.6.2.1](https://github.com/zmartzone/cjose/compare/v0.6.2...v0.6.2.1)  (2022-10-24)
* preserve key order in cjose_header_get_raw as well (https://github.com/zmartzone/cjose/pull/16)
* fix a memory leak in cjose_jws_import() for invalid JWS (https://github.com/zmartzone/cjose/pull/14)
* don't use STACK_ALLOC in cjose_concatkdf_derive (https://github.com/zmartzone/cjose/pull/15)

<a name="v0.6.2"></a>
## [v0.6.2](https://github.com/zmartzone/cjose/compare/0.6.1...v0.6.2)  (2022-04-14)

### Update

* add support for A128GCM and A192GCM encryption (https://github.com/zmartzone/cjose/pull/4)
* extract cjose_jwe_encrypt_iv to allow explicit IV (https://github.com/zmartzone/cjose/pull/9) ; thanks @rnapier
* allow compilation against OpenSSL 3 with "#define OPENSSL_API_COMPAT 0x10000000L"

### Fix

* cleanup some warnings about \param lines in header files (https://github.com/zmartzone/cjose/pull/1) ; thanks @jogu
* preserve key order in order to be able to compare serialized JWTs (https://github.com/zmartzone/cjose/pull/2)
* minor updates for conformance (https://github.com/zmartzone/cjose/pull/3) ; thanks @ajishna
* check that JWE object has any CEK at all, return error if it doesn't (https://github.com/zmartzone/cjose/pull/5) ; thanks @veselov
* fix double free on decrypt ek rsa padding failure (https://github.com/zmartzone/cjose/pull/6)
* replace calls to free with cjose_get_dealloc() in _cjose_jws_build_hdr (https://github.com/zmartzone/cjose/pull/7) ; thanks @zachmann
* fix buffer overflow in test_cjose_jwe_multiple_recipients (https://github.com/zmartzone/cjose/pull/10) ; thanks @mpsun
* use fixed size of IV size of 16Byte for AES-CBC (https://github.com/zmartzone/cjose/pull/11) ; thanks @securedimensions
* fix memory leak already addressed in _cjose_jws_build_dig_sha when a jws is reused for a validation (https://github.com/zmartzone/cjose/pull/12) ; thanks @traeak
* compile against older versions of check (https://github.com/cisco/cjose/issues/91) ; thanks @treydock
* rename free() to free_func() in struct key_fntable for memory leak detectors (https://github.com/cisco/cjose/issues/109) ; thanks @marcstern
* check result of cek = cjose_get_alloc()(cek_len) in jwe.c (https://github.com/cisco/cjose/issues/110) ; thanks @marcstern 

<a name="0.6.1"></a>
## [0.6.1](https://github.com/cisco/cjose/0.6.0..0.6.1)  (2018-04-12)

### Update

* Better support for AES-CBC-HMAC with other key management algs ([602555ff3fbd34e875bf0e7b88f4d94dc6000e8b](https://github.com/cisco/cjose/commit/602555ff3fbd34e875bf0e7b88f4d94dc6000e8b))

### Fix

* Explicit defined() usage for CJOSE_OPENSSL_11X ([b6665deae2aec3b68d88edb293b1f6c137e624ce](https://github.com/cisco/cjose/commit/b6665deae2aec3b68d88edb293b1f6c137e624ce))
* Bad JWE crashes _cjose_jwe_set_cek_a256gcm ([fb24d6f264fd83d0228a65c2f06e27dba2495ceb](https://github.com/cisco/cjose/commit/fb24d6f264fd83d0228a65c2f06e27dba2495ceb))

<a name="0.6.0"></a>
## [0.6.0](https://github.com/cisco/cjose/0.5.1..0.6.0)  (2018-02-06)

### Update

* support ECDH-ES  ([1250eff10fa178937aea1924887d114c8ba943c2](https://github.com/cisco/cjose/commit/1250eff10fa178937aea1924887d114c8ba943c2))
* compile with LibreSSL  ([8693c22aabf31313a4002838e124e93879bbb50b](https://github.com/cisco/cjose/commit/8693c22aabf31313a4002838e124e93879bbb50b))
* Support multiple recipients and JSON serialization for JWE  ([e569ee824fd5af8654fb0054952f6c7b9d038ce6](https://github.com/cisco/cjose/commit/e569ee824fd5af8654fb0054952f6c7b9d038ce6))


<a name="0.5.1"></a>
## [0.5.1](https://github.com/cisco/cjose/0.5.0..0.5.1) (2017-05-24)

### Fix

* Crash on non string "alg" ([b5daeb66ad603d40da8c7250d9121ef4cc8060c2](https://github.com/cisco/cjose/commit/b5daeb66ad603d40da8c7250d9121ef4cc8060c2))


<a name="0.5.0"></a>
## [0.5.0](https://github.com/cisco/cjose/0.4.1..0.5.0) (2017-05-05)

### Update

* Unexpected release of JWS resources on failure but not success ([ed3cb39cf2fdaf401fbba9b93fd44e6a50b97f62](https://github.com/cisco/cjose/commit/ed3cb39cf2fdaf401fbba9b93fd44e6a50b97f62))

### Fix

* Bad casting of pointers ([5b7ac9a6dfd08aead145dcef7a46bbc52ffb68de](https://github.com/cisco/cjose/commit/5b7ac9a6dfd08aead145dcef7a46bbc52ffb68de))

### Build
* Support for clang-format ([7d0f5566dff5258f4babb1e843715fcec3b03cbe](https://github.com/cisco/cjose/commit/7d0f5566dff5258f4babb1e843715fcec3b03cbe))
* Improve alloc/realloc/dealloc tests ([f02e19c99de9e7b2621c56f6a88cb2b9eb91e954](https://github.com/cisco/cjose/commit/f02e19c99de9e7b2621c56f6a88cb2b9eb91e954))

<a name="0.4.1"></a>
## [0.4.1](https://github.com/cisco/cjose/0.4.0..0.4.1) (2016-08-04)

### Build

* Compiler warning/error fixes for multiple platforms ([011612e72698dd02249f578fb4ec0145c624c0e0](https://github.com/cisco/cjose/commit/011612e72698dd02249f578fb4ec0145c624c0e0))


<a name="0.4.0"></a>
## [0.4.0](https://github.com/cisco/cjose/compare/0.3.0...0.4.0) (2016-08-02)

### Update

* Support OpenSSL 1.1.x ([9bc8a801a5160952787d4ed2fdc225eb57d471a5](https://github.com/cisco/cjose/commit/9bc8a801a5160952787d4ed2fdc225eb57d471a5))
* Support AES KeyWrap and AES-CBC-HMAC-SHA2 ([b7518799842e1b411d7b900ef8879f51c65584ee](https://github.com/cisco/cjose/commit/b7518799842e1b411d7b900ef8879f51c65584ee))
* Support Elliptic Curve JWS Algorithms (ES256 / ES384 / ES512) ([8206eebb1c69521a90601a3f37f8f1693fb4ec4f](https://github.com/cisco/cjose/commit/8206eebb1c69521a90601a3f37f8f1693fb4ec4f))
* Support RSAES-PKCS1-v1_5 key encryption ([76ae28a299cf207d4373cfd95cd299b6af0cc248](https://github.com/cisco/cjose/commit/76ae28a299cf207d4373cfd95cd299b6af0cc248))
* Support symmetric HMAC "signatures" ([f43f17dd0ff6b513d02db075c728f08031051e43](https://github.com/cisco/cjose/commit/f43f17dd0ff6b513d02db075c728f08031051e43))
* Support unsecured JWS (**IMPORT ONLY**) ([8512cf3a45bea90bbbba2d55c083d3f08ccd25f6](https://github.com/cisco/cjose/commit/8512cf3a45bea90bbbba2d55c083d3f08ccd25f6))
* Support older versions of Jansson ([d9d3d43df91264a59e94eaefd0f7068e2249cbde](https://github.com/cisco/cjose/commit/d9d3d43df91264a59e94eaefd0f7068e2249cbde))

### Fix

* RS256 verify always returned true ([c177b707a4877406bf93f35171bdc8d7f0b74d33](https://github.com/cisco/cjose/commit/c177b707a4877406bf93f35171bdc8d7f0b74d33))
* Replace free() with dealloc() ([8361f3827622232b1d8fa944b4bc3a3938bb9fd6](https://github.com/cisco/cjose/commit/8361f3827622232b1d8fa944b4bc3a3938bb9fd6))
* Remove the use of strdup ([e968f21e6d1ae4bf499e0dd4e8fd628efcada607](https://github.com/cisco/cjose/commit/e968f21e6d1ae4bf499e0dd4e8fd628efcada607))


### Build

* Use CJOSE_VERSION everywhere ([2c58aa1de96f883c23626b05527754c0c7590079](https://github.com/cisco/cjose/commit/2c58aa1de96f883c23626b05527754c0c7590079))
* Use cjose_err.code instead of errno ([5f40fef38725d375f204a16a79beae754d58fc76](https://github.com/cisco/cjose/commit/5f40fef38725d375f204a16a79beae754d58fc76))


<a name="0.3.0"></a>
## [0.3.0](https://github.com/linuxwolf/cjose/compare/0.2.0...0.3.0) (2016-05-26)


### Update

* expose more key information ([16cf34901bbff6791c20aa831c34660e510cc9ee](https://github.com/cisco/cjose/commit/16cf34901bbff6791c20aa831c34660e510cc9ee))

### Fix

* missing 'util.h' in superheader ([02593fb83991651570ec50dd35d89fb4e747ec71](https://github.com/cisco/cjose/commit/02593fb83991651570ec50dd35d89fb4e747ec71))



<a name="0.2.0"></a>
## [0.2.0](https://github.com/cisco/cjose/compare/0.1.2...0.2.0) (2016-05-06)


### Update

* Expose protected header from imported/created JWE and JWS ([6d1d1be838b546cb73f8d24c42a681a0a0e1ec03](https://github.com/cisco/cjose/commit/6d1d1be838b546cb73f8d24c42a681a0a0e1ec03))

### Fix

* incorrect repo in doc ([642e5896798ac84e7035cd489dd12273b914f829](https://github.com/cisco/cjose/commit/642e5896798ac84e7035cd489dd12273b914f829))

### Build

* friendlier dist ([fdff0a6b1f2d94f896b6416471b7f159d143ce06](https://github.com/cisco/cjose/commit/fdff0a6b1f2d94f896b6416471b7f159d143ce06))
* Use RFC6090 Fundamental EC if present ([436264fd83adb536e827f633a47fc023760b27d1](https://github.com/cisco/cjose/commit/436264fd83adb536e827f633a47fc023760b27d1))


<a name="0.1.2"></a>
## 0.1.2 (2016-03-15)

Initial public release
