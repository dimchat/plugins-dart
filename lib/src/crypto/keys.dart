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
import 'package:dimp/crypto.dart';
import 'package:dimp/ext.dart';

///
/// Base Keys
///

/// Provides common helper methods for key comparison and algorithm
/// detection, shared by all key types (symmetric/asymmetric).
abstract class BaseKey extends Dictionary implements CryptographyKey {
  BaseKey([super.dict]);

  @override
  String get algorithm => getKeyAlgorithm(toMap());

  //
  //  Conveniences
  //

  /// Get algorithm name from key info.
  ///
  /// The key algorithm is detected by the registered [CryptoKeyHandler],
  /// which parses the key data to figure out the algorithm name
  /// (e.g. "AES", "ECC", "RSA", ...).
  static String getKeyAlgorithm(Mapping key) {
    final handler = sharedCryptoExtensions.handler;
    return handler!.getKeyAlgorithm(key) ?? '';
  }

  /// Check whether [pKey] can encrypt data for [sKey] to decrypt.
  ///
  /// Returns true if they are a matched symmetric key pair
  /// (i.e. both keys are equal).
  static bool matchEncryptKey(EncryptKey pKey, DecryptKey sKey) {
    return CryptoKeyHandler.matchSymmetricKeys(pKey, sKey);
  }

  /// Check whether [sKey] can sign data for [pKey] to verify.
  ///
  /// Returns true if they are a matched asymmetric key pair
  /// (i.e. the private key matches the public key).
  static bool matchSignKey(SignKey sKey, VerifyKey pKey) {
    return CryptoKeyHandler.matchAsymmetricKeys(sKey, pKey);
  }

  /// Compare two symmetric keys.
  ///
  /// Returns true if [a] and [b] are the same object,
  /// or they can encrypt/decrypt data for each other.
  static bool symmetricKeyEquals(SymmetricKey a, SymmetricKey b) {
    if (identical(a, b)) {
      // same object
      return true;
    }
    // compare by encryption
    return matchEncryptKey(a, b);
  }

  /// Compare two private keys.
  ///
  /// Returns true if [a] and [b] are the same object,
  /// or their public keys are matched by signature.
  static bool privateKeyEquals(PrivateKey a, PrivateKey b) {
    if (identical(a, b)) {
      // same object
      return true;
    }
    // compare by signature
    return matchSignKey(a, b.publicKey);
  }
}


///
/// Symmetric Key
///

/// Base class for symmetric keys (e.g. AES, Plain),
/// which use the same key for both encryption and decryption.
abstract class BaseSymmetricKey extends Dictionary implements SymmetricKey {
  BaseSymmetricKey([super.dict]);

  @override
  bool operator ==(Object other) {
    if (other is Mapper) {
      if (identical(this, other)) {
        // same object
        return true;
      } else if (other is SymmetricKey) {
        return BaseKey.symmetricKeyEquals(other, this);
      }
      // compare with inner map
      other = other.toMap();
    }
    return other is Map && Comparator.mapEquals(other, toMap().asMap());
  }

  @override
  int get hashCode => toMap().hashCode;

  @override
  String get algorithm => BaseKey.getKeyAlgorithm(toMap());

  @override
  bool matchEncryptKey(EncryptKey pKey) => BaseKey.matchEncryptKey(pKey, this);
}


///
/// Asymmetric Keys
///

/// Base classes for asymmetric key pairs (private key & public key),
/// which are used for signing/verifying and encrypting/decrypting.
abstract class BaseAsymmetricKey extends Dictionary implements AsymmetricKey {
  BaseAsymmetricKey([super.dict]);

  @override
  String get algorithm => BaseKey.getKeyAlgorithm(toMap());
}


/// Base class for private keys (e.g. ECC, RSA),
/// which can decrypt data and sign messages.
abstract class BasePrivateKey extends Dictionary implements PrivateKey {
  BasePrivateKey([super.dict]);

  @override
  bool operator ==(Object other) {
    if (other is Mapper) {
      if (identical(this, other)) {
        // same object
        return true;
      } else if (other is PrivateKey) {
        return BaseKey.privateKeyEquals(other, this);
      }
      // compare with inner map
      other = other.toMap();
    }
    return other is Map && Comparator.mapEquals(other, toMap().asMap());
  }

  @override
  int get hashCode => toMap().hashCode;

  @override
  String get algorithm => BaseKey.getKeyAlgorithm(toMap());
}


/// Base class for public keys (e.g. ECC, RSA),
/// which can encrypt data and verify signatures.
abstract class BasePublicKey extends Dictionary implements PublicKey {
  BasePublicKey([super.dict]);

  @override
  String get algorithm => BaseKey.getKeyAlgorithm(toMap());

  @override
  bool matchSignKey(SignKey sKey) => BaseKey.matchSignKey(sKey, this);
}
