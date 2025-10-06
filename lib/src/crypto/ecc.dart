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

import 'ecc_utils.dart';

///  ECC Public Key
///
///      keyInfo format : {
///          algorithm  : "ECC",
///          curve      : "secp256k1",
///          data       : "...", // base64_encode(),
///          compressed : 0
///      }
class ECCPublicKey extends BasePublicKey {
  ECCPublicKey([super.dict]);

  bool get compressed => getBool('compressed') ?? false;

  // protected
  get eccPubKey {
    String data = getString('data') ?? '';
    return ECCKeyUtils.decodePublicKey(data);
  }

  @override
  Uint8List get data => ECCKeyUtils.encodePublicKeyData(eccPubKey,
    compressed: compressed,
  );

  @override
  bool verify(Uint8List data, Uint8List signature) {
    try {
      return ECCKeyUtils.verify(data, signature, eccPubKey);
    } catch (e, st) {
      print('ECC: failed to verify: $e, $st');
      return false;
    }
  }
}

///  ECC Private Key
///
///      keyInfo format : {
///          algorithm  : "ECC",
///          curve      : "secp256k1",
///          data       : "..." // base64_encode()
///      }
class ECCPrivateKey extends BasePrivateKey {
  ECCPrivateKey([super.dict]) {
    // lazy load
    _publicKey = null;
  }

  PublicKey? _publicKey;

  factory ECCPrivateKey.newKey() {
    var privateKey = ECCKeyUtils.generatePrivateKey();
    String pem = ECCKeyUtils.encodeKey(privateKey: privateKey);
    return ECCPrivateKey({
      'algorithm': AsymmetricAlgorithms.ECC,
      'data': pem,
      'curve': 'SECP256k1',
      'digest': 'SHA256',
    });
  }

  // protected
  get eccPriKey {
    String data = getString('data') ?? '';
    return ECCKeyUtils.decodePrivateKey(data);
  }

  @override
  Uint8List get data => ECCKeyUtils.encodePrivateKeyData(eccPriKey);

  @override
  PublicKey get publicKey {
    PublicKey? pubKey = _publicKey;
    if (pubKey == null) {
      var key = ECCKeyUtils.publicKeyFromPrivateKey(eccPriKey);
      String pem = ECCKeyUtils.encodeKey(publicKey: key);
      Map info = {
        'algorithm': AsymmetricAlgorithms.ECC,
        'data': pem,
        'curve': 'SECP256k1',
        'digest': 'SHA256',
      };
      pubKey = PublicKey.parse(info);
      assert(pubKey != null, 'failed to get ECC public key: $info');
      _publicKey = pubKey;
    }
    return pubKey!;
  }

  @override
  Uint8List sign(Uint8List data) {
    return ECCKeyUtils.sign(data, eccPriKey);
  }
}

//
//  ECC Key Factories
//

class ECCPublicKeyFactory implements PublicKeyFactory {

  @override
  PublicKey? parsePublicKey(Map key) {
    // check 'data'
    if (key['data'] == null) {
      // key.data should not be empty
      assert(false, 'ECC key error: $key');
      return null;
    }
    return ECCPublicKey(key);
  }
}

class ECCPrivateKeyFactory implements PrivateKeyFactory {

  @override
  PrivateKey generatePrivateKey() {
    return ECCPrivateKey.newKey();
  }

  @override
  PrivateKey? parsePrivateKey(Map key) {
    // check 'data'
    if (key['data'] == null) {
      // key.data should not be empty
      assert(false, 'ECC key error: $key');
      return null;
    }
    return ECCPrivateKey(key);
  }
}
