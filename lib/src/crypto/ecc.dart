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
import 'algorithms.dart';
import 'keys.dart';


///  ECC Public Key
///
///  keyInfo format: {
///      algorithm  : "ECC",
///      curve      : "secp256k1",
///      data       : "...", // base64_encode(),
///      compressed : 0
///  }
class ECCPublicKey extends BasePublicKey {
  ECCPublicKey([super.dict]);

  /// Whether the public key data is encoded in compressed format.
  ///
  /// The value is read from the 'compressed' field of the key info,
  /// default is false (uncompressed).
  bool get compressed => getBool('compressed') ?? false;

  /// Get the native ECC public key object.
  ///
  /// The key data (PEM encoded) is decoded by [ECCKeyUtils].
  // protected
  get eccPubKey {
    String data = getString('data') ?? '';
    return ECCKeyUtils.decodePublicKey(data);
  }

  @override
  TransportableData get data {
    Uint8List bytes = ECCKeyUtils.encodePublicKeyData(eccPubKey,
      compressed: compressed,
    );
    return PlainData.createWithBytes(bytes);
  }

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

  /// Generate a random ECC key pair.
  ///
  /// The private key is stored in the key info as PEM data,
  /// with 'curve' and 'digest' fields for the parameters.
  ///
  /// [curveName] - name of the elliptic curve,
  ///               default is "secp256k1".
  ///
  /// Returns a new [ECCPrivateKey] instance.
  factory ECCPrivateKey.newKey([String curveName = 'secp256k1']) {
    final privateKey = ECCKeyUtils.generatePrivateKey(curve: curveName);
    String pem = ECCKeyUtils.encodePrivateKey(privateKey);
    return ECCPrivateKey(<String, dynamic>{
      'algorithm': AsymmetricAlgorithms.ECC,
      'data': pem,
      'curve': curveName,
      'digest': 'SHA256',
    }.asMapping());
  }

  /// Get the curve name of this key.
  ///
  /// The value is read from the 'curve' field of the key info,
  /// default is "secp256k1".
  // private
  String get curveName => getString('curve') ?? 'secp256k1';

  /// Get the native ECC private key object.
  ///
  /// The key data (PEM encoded) is decoded by [ECCKeyUtils].
  // protected
  get eccPriKey {
    String data = getString('data') ?? '';
    return ECCKeyUtils.decodePrivateKey(data);
  }

  @override
  TransportableData get data {
    Uint8List bytes = ECCKeyUtils.encodePrivateKeyData(eccPriKey);
    return PlainData.createWithBytes(bytes);
  }

  @override
  PublicKey get publicKey {
    PublicKey? pubKey = _publicKey;
    if (pubKey == null) {
      final key = ECCKeyUtils.publicKeyFromPrivateKey(eccPriKey);
      String pem = ECCKeyUtils.encodePublicKey(key);
      Map<String, dynamic> info = {
        'algorithm': algorithm, // AsymmetricAlgorithms.ECC,
        'data': pem,
        'curve': curveName,
        'digest': 'SHA256',
      };
      pubKey = ECCPublicKey(info.asMapping());
      _publicKey = pubKey;
    }
    return pubKey;
  }

  @override
  Uint8List sign(Uint8List data) {
    return ECCKeyUtils.sign(data, eccPriKey);
  }
}

//
//  ECC Key Factories
//

/// ECC Public Key Factory
///
/// Parses a dictionary into an [ECCPublicKey] instance.
class ECCPublicKeyFactory implements PublicKeyFactory {

  @override
  PublicKey? parsePublicKey(Mapping key) {
    // check 'data', 'algorithm'
    if (key['data'] == null || key['algorithm'] == null) {
      // key.data should not be empty
      // key.algorithm should not be empty
      assert(false, 'ECC key error: $key');
      return null;
    }
    return ECCPublicKey(key);
  }
}

/// ECC Private Key Factory
///
/// Generates a new [ECCPrivateKey] or parses a dictionary
/// into an [ECCPrivateKey] instance.
class ECCPrivateKeyFactory implements PrivateKeyFactory {

  @override
  PrivateKey generatePrivateKey() {
    return ECCPrivateKey.newKey();
  }

  @override
  PrivateKey? parsePrivateKey(Mapping key) {
    // check 'data', 'algorithm'
    if (key['data'] == null || key['algorithm'] == null) {
      // key.data should not be empty
      // key.algorithm should not be empty
      assert(false, 'ECC key error: $key');
      return null;
    }
    return ECCPrivateKey(key);
  }
}
