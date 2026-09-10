/* license: https://mit-license.org
 * ==============================================================================
 * The MIT License (MIT)
 *
 * Copyright (c) 2023 Albert Moky
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * ==============================================================================
 */
import 'dart:typed_data';

import 'package:dimp/crypto.dart';

import 'algorithms.dart';
import 'keys.dart';
import 'rsa_utils.dart';


///  RSA Public Key
///
///      keyInfo format : {
///          algorithm  : "RSA",
///          data       : "..." // base64_encode()
///      }
class RSAPublicKey extends BasePublicKey implements EncryptKey {
  RSAPublicKey([super.dict]);

  // private
  int keySize() {
    // TODO: get from key
    return getInt('keySize') ?? 128;  // 1024 / 8
  }

  // protected
  get rsaPubKey {
    String data = getString('data') ?? '';
    return RSAKeyUtils.decodePublicKey(data);
  }

  @override
  TransportableData get data {
    Uint8List bytes = RSAKeyUtils.encodePublicKeyData(rsaPubKey);
    return PlainData.createWithBytes(bytes);
  }

  @override
  Uint8List encrypt(Uint8List plaintext, [MutableMapping? extra]) {
    if (plaintext.length > keySize() - 11) {
      throw ArgumentError('RSA plain text length error: ${plaintext.length}');
    }
    return RSAKeyUtils.encrypt(plaintext, rsaPubKey);
  }

  @override
  bool verify(Uint8List data, Uint8List signature) {
    try {
      return RSAKeyUtils.verify(data, signature, rsaPubKey);
    } catch (e, st) {
      print('RSA: failed to verify: $e, $st');
      return false;
    }
  }
}

///  RSA Private Key
///
///      keyInfo format : {
///          algorithm  : "RSA",
///          data       : "..." // base64_encode()
///      }
class RSAPrivateKey extends BasePrivateKey implements DecryptKey {
  RSAPrivateKey([super.dict]) {
    // lazy load
    _publicKey = null;
  }

  PublicKey? _publicKey;

  factory RSAPrivateKey.newKey([int sizeInBits = 1024]) {
    final privateKey = RSAKeyUtils.generatePrivateKey(bitLength: sizeInBits);
    final publicKey = RSAKeyUtils.publicKeyFromPrivateKey(privateKey);
    // -----BEGIN PUBLIC KEY-----
    String pkString = RSAKeyUtils.encodePublicKey(publicKey);
    // -----END PUBLIC KEY-----
    // -----BEGIN RSA PRIVATE KEY-----
    String skString = RSAKeyUtils.encodePrivateKey(privateKey);
    // -----END RSA PRIVATE KEY-----
    return RSAPrivateKey(<String, dynamic>{
      'algorithm': AsymmetricAlgorithms.RSA,
      'data': '$pkString\r\n$skString',
      'mode': 'ECB',
      'padding': 'PKCS1',
      'digest': 'SHA256',
    }.asMapping());
  }

  // private
  int keySize() {
    // TODO: get from key
    return getInt('keySize') ?? 128;  // 1024 / 8
  }

  // protected
  get rsaPriKey {
    String data = getString('data') ?? '';
    return RSAKeyUtils.decodePrivateKey(data);
  }

  @override
  TransportableData get data {
    Uint8List bytes = RSAKeyUtils.encodePrivateKeyData(rsaPriKey);
    return PlainData.createWithBytes(bytes);
  }

  @override
  PublicKey get publicKey {
    PublicKey? pubKey = _publicKey;
    if (pubKey == null) {
      final key = RSAKeyUtils.publicKeyFromPrivateKey(rsaPriKey);
      String pem = RSAKeyUtils.encodePublicKey(key);
      Map<String, dynamic> info = {
        'algorithm': algorithm, // AsymmetricAlgorithms.RSA,
        'data': pem,
        'mode': 'ECB',
        'padding': 'PKCS1',
        'digest': 'SHA256',
      };
      pubKey = RSAPublicKey(info.asMapping());
      _publicKey = pubKey;
    }
    return pubKey;
  }

  @override
  Uint8List sign(Uint8List data) {
    return RSAKeyUtils.sign(data, rsaPriKey);
  }

  @override
  Uint8List? decrypt(Uint8List ciphertext, [Mapping? params]) {
    if (ciphertext.length != keySize()) {
      throw ArgumentError('RSA cipher text length error: ${ciphertext.length}');
    }
    try {
      return RSAKeyUtils.decrypt(ciphertext, rsaPriKey);
    } catch (e, st) {
      print('RSA: failed to decrypt: $e, $st');
      return null;
    }
  }

  @override
  bool matchEncryptKey(EncryptKey pKey) {
    return BaseKey.matchEncryptKey(pKey, this);
  }
}

//
//  RSA Key Factories
//

class RSAPublicKeyFactory implements PublicKeyFactory {

  @override
  PublicKey? parsePublicKey(Mapping key) {
    // check 'data', 'algorithm'
    if (key['data'] == null || key['algorithm'] == null) {
      // key.data should not be empty
      // key.algorithm should not be empty
      assert(false, 'RSA key error: $key');
      return null;
    }
    return RSAPublicKey(key);
  }
}

class RSAPrivateKeyFactory implements PrivateKeyFactory {

  @override
  PrivateKey generatePrivateKey() {
    return RSAPrivateKey.newKey();
  }

  @override
  PrivateKey? parsePrivateKey(Mapping key) {
    // check 'data', 'algorithm'
    if (key['data'] == null || key['algorithm'] == null) {
      // key.data should not be empty
      // key.algorithm should not be empty
      assert(false, 'RSA key error: $key');
      return null;
    }
    return RSAPrivateKey(key);
  }
}
