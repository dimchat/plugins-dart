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

import 'rsa_utils.dart';

///  RSA Public Key
///
///      keyInfo format : {
///          algorithm  : "RSA",
///          data       : "..." // base64_encode()
///      }
class RSAPublicKey extends BasePublicKey implements EncryptKey {
  RSAPublicKey([super.dict]);

  // protected
  get rsaPubKey {
    String data = getString('data') ?? '';
    return RSAKeyUtils.decodePublicKey(data);
  }

  @override
  Uint8List get data => RSAKeyUtils.encodePublicKeyData(rsaPubKey);

  @override
  Uint8List encrypt(Uint8List plaintext, [Map? extra]) {
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

  factory RSAPrivateKey.newKey() {
    var privateKey = RSAKeyUtils.generatePrivateKey();
    String pem = RSAKeyUtils.encodeKey(privateKey: privateKey);
    return RSAPrivateKey({
      'algorithm': AsymmetricAlgorithms.RSA,
      'data': pem,
      'mode': 'ECB',
      'padding': 'PKCS1',
      'digest': 'SHA256',
    });
  }

  // protected
  get rsaPriKey {
    String data = getString('data') ?? '';
    return RSAKeyUtils.decodePrivateKey(data);
  }

  @override
  Uint8List get data => RSAKeyUtils.encodePrivateKeyData(rsaPriKey);

  @override
  PublicKey get publicKey {
    PublicKey? pubKey = _publicKey;
    if (pubKey == null) {
      var key = RSAKeyUtils.publicKeyFromPrivateKey(rsaPriKey);
      String pem = RSAKeyUtils.encodeKey(publicKey: key);
      Map info = {
        'algorithm': AsymmetricAlgorithms.RSA,
        'data': pem,
        'mode': 'ECB',
        'padding': 'PKCS1',
        'digest': 'SHA256',
      };
      pubKey = PublicKey.parse(info);
      assert(pubKey != null, 'failed to get RSA public key: $info');
      _publicKey = pubKey;
    }
    return pubKey!;
  }

  @override
  Uint8List sign(Uint8List data) {
    return RSAKeyUtils.sign(data, rsaPriKey);
  }

  @override
  Uint8List? decrypt(Uint8List ciphertext, [Map? params]) {
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
  PublicKey? parsePublicKey(Map key) {
    // check 'data'
    if (key['data'] == null) {
      // key.data should not be empty
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
  PrivateKey? parsePrivateKey(Map key) {
    // check 'data'
    if (key['data'] == null) {
      // key.data should not be empty
      assert(false, 'RSA key error: $key');
      return null;
    }
    return RSAPrivateKey(key);
  }
}
