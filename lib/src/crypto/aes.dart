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
import 'dart:math';
import 'dart:typed_data';

import 'package:encrypt/encrypt.dart';

import 'package:dimp/crypto.dart';

import '../format/base64_data.dart';

import 'algorithms.dart';
import 'keys.dart';


///  AES Key
///
///  keyInfo format: {
///      algorithm: "AES",
///      keySize  : 32,                // optional
///      data     : "{BASE64_ENCODE}}" // key data
///  }
class AESKey extends BaseSymmetricKey {
  AESKey([super.dict]) {
    // TODO: check algorithm parameters
    // 1. check mode = 'CBC'
    // 2. check padding = 'PKCS7Padding'

    // lazy load
    _keyData = null;
  }

  // ignore: constant_identifier_names
  static const String AES_CBC_PKCS7 = "AES/CBC/PKCS7Padding";

  TransportableData? _keyData;

  /// Generate a random AES key with the given size (bytes).
  ///
  /// The key data is stored as a base64 encoded string in the 'data' field.
  ///
  /// [size] - key size in bytes, default is 32 (256 bits).
  ///
  /// Returns a new [AESKey] instance.
  factory AESKey.newKey([int size = 32]) {
    final data = _randomData(size);
    final ted = Base64Data.createWithBytes(data);
    final key = AESKey(<String, dynamic>{
      'algorithm': SymmetricAlgorithms.AES,
      'data': ted.serialize(),
      // 'mod': 'CBC',
      // 'padding': 'PKCS7',
    }.asMapping());
    key._keyData = ted;
    return key;
  }

  /// Get key size (bytes).
  ///
  /// The size is read from the 'keySize' field of the key info,
  /// default is 32 bytes (256 bits).
  // protected
  int getKeySize() {
    // TODO: get from key data
    return getInt('keySize') ?? 32;
  }

  /// Get the default block size of AES (16 bytes).
  ///
  /// The block size is used to generate the IV data.
  // protected
  int getDefaultBlockSize() {
    // TODO: get from cipher instance
    return 16;
  }

  /// Get block size for IV.
  ///
  /// The size is read from the 'blockSize' field of the key info,
  /// default is the [getDefaultBlockSize] (16 bytes).
  // protected
  int getBlockSize() {
    // TODO: get from iv data
    return getInt('blockSize') ?? getDefaultBlockSize();
  }

  @override
  TransportableData get data {
    var ted = _keyData;
    if (ted == null) {
      final base64 = this['data'];
      assert(base64 != null, 'key data not found: $this');
      ted = _keyData = TransportableData.parse(base64);
      assert(ted != null, 'key data error: $base64');
    }
    return ted!;
  }

  /// Get the AES cipher key.
  ///
  /// Returns the raw key data as a [Key] for the encrypt package.
  // protected
  Key getCipherKey() => Key(data.bytes!);

  /// Get the IV data from params.
  ///
  /// The IV is read from the 'IV'/'iv' field of [params],
  /// or from the 'iv'/'IV' field of the key info (for compatibility).
  ///
  /// [params] - extra parameters containing the encoded IV,
  ///            should not be null for AES.
  ///
  /// Returns null if no IV data found.
  // protected
  IV? getInitVector(Mapping? params) {
    // get base64 encoded IV from params
    String? base64;
    if (params == null) {
      assert(false, 'params must provided to fetch IV for AES');
    } else {
      base64 = params['IV'];
      base64 ??= params['iv'];
    }
    if (base64 == null) {
      // compatible with old version
      base64 = getString('iv');
      base64 ??= getString('IV');
    }
    // decode IV data
    final ted = TransportableData.parse(base64);
    Uint8List? ivData = ted?.bytes;
    if (ivData == null || ivData.isEmpty) {
      assert(base64 == null, 'IV data error: $base64');
      return null;
    }
    return IV(ivData);
  }

  /// Get an empty (zero) IV with the block size.
  // protected
  IV zeroInitVector() {
    // zero IV
    int blockSize = getBlockSize();
    Uint8List ivData = Uint8List(blockSize);
    return IV(ivData);
  }

  /// Generate a random IV and store it into [extra] as 'IV'.
  ///
  /// [extra] - mutable extra params to store the encoded IV data,
  ///           should not be null for AES encryption.
  ///
  /// Returns the random IV data.
  // protected
  IV newInitVector(MutableMapping? extra) {
    // random IV data
    int blockSize = getBlockSize();
    Uint8List ivData = _randomData(blockSize);
    // put encoded IV into extra
    if (extra == null) {
      assert(false, 'extra dict must provided to store IV for AES');
    } else {
      final ted = Base64Data.createWithBytes(ivData);
      extra['IV'] = ted.serialize();
    }
    // OK
    return IV(ivData);
  }

  @override
  Uint8List encrypt(Uint8List plaintext, [MutableMapping? extra]) {
    // 1. if 'IV' not found in extra params, new a random 'IV'
    IV? iv = getInitVector(extra);
    iv ??= newInitVector(extra);
    // 2. get cipher key
    Key key = getCipherKey();
    // 3. try to encrypt
    Encrypter cipher = Encrypter(AES(key, mode: AESMode.cbc));
    return cipher.encryptBytes(plaintext, iv: iv).bytes;
  }

  @override
  Uint8List? decrypt(Uint8List ciphertext, [Mapping? params]) {
    // 1. if 'IV' not found in extra params, use an empty 'IV'
    IV? iv = getInitVector(params);
    iv ??= zeroInitVector();
    // 2. get cipher key
    Key key = getCipherKey();
    // 3. try to decrypt
    try {
      Encrypter cipher = Encrypter(AES(key, mode: AESMode.cbc));
      List<int> result = cipher.decryptBytes(Encrypted(ciphertext), iv: iv);
      return Uint8List.fromList(result);
    } catch (e, st) {
      print('AES: failed to decrypt: $e, ${params?["IV"]}');
      print('AES: failed to decrypt: $e, $st');
      return null;
    }
  }

}

Uint8List _randomData(int size) {
  Uint8List data = Uint8List(size);
  Random r = Random();
  for (int i = 0; i < size; ++i) {
    data[i] = r.nextInt(256);
  }
  return data;
}

/// AES Key Factory
///
/// Generates a random [AESKey] or parses a dictionary
/// into an [AESKey] instance.
class AESKeyFactory implements SymmetricKeyFactory {

  @override
  SymmetricKey generateSymmetricKey() {
    return AESKey.newKey();
  }

  @override
  SymmetricKey? parseSymmetricKey(Mapping key) {
    // check 'data', 'algorithm'
    if (key['data'] == null || key['algorithm'] == null) {
      // key.data should not be empty
      // key.algorithm should not be empty
      assert(false, 'AES key error: $key');
      return null;
    }
    return AESKey(key);
  }

}
