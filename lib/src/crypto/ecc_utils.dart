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

import 'package:basic_utils/basic_utils.dart';
import 'package:pointycastle/asn1.dart';
import 'package:pointycastle/export.dart' as pc;

import 'package:dimp/crypto.dart' as dim;


/// ECC Key Utils
///
/// Utility class for ECC key operations:
/// - Generate key pair / derive public key from private key
/// - Sign data and verify signatures
/// - Encode/decode keys between PEM text and native objects
final class ECCKeyUtils {
  ECCKeyUtils._();

  /// Verify [signature] of [data] with the [publicKey].
  ///
  /// Returns true if the signature is valid.
  static bool verify(Uint8List data, Uint8List signature, ECPublicKey publicKey) {
    final params = pc.PublicKeyParameter(publicKey);
    final signer = pc.Signer('SHA-256/ECDSA')..init(false, params);
    final elements = ASN1Sequence.fromBytes(signature).elements!;
    BigInt? r = (elements[0] as ASN1Integer).integer;
    BigInt? s = (elements[1] as ASN1Integer).integer;
    return signer.verifySignature(data, pc.ECSignature(r!, s!));
  }

  /// Sign [data] with the [privateKey].
  ///
  /// Returns the ECDSA signature (r, s encoded as ASN.1).
  static Uint8List sign(Uint8List data, ECPrivateKey privateKey) {
    final params = pc.PrivateKeyParameter(privateKey);
    final paramsWithRandom = pc.ParametersWithRandom(params, getSecureRandom());
    final signer = pc.Signer('SHA-256/ECDSA')..init(true, paramsWithRandom);
    final signature = signer.generateSignature(data) as pc.ECSignature;
    // encode the two signature values in a common format
    return ASN1Sequence(elements: [
      ASN1Integer(signature.r),
      ASN1Integer(signature.s),
    ]).encode();
  }

  /// Get a seeded secure random generator.
  ///
  /// [name]   - algorithm name of the secure random, default is "Fortuna".
  /// [length] - seed length in bytes, default is 32.
  ///
  /// Returns a [pc.SecureRandom] instance seeded with random bytes.
  static pc.SecureRandom getSecureRandom({String name = 'Fortuna', int length = 32}) {
    final random = Random.secure();
    List<int> seeds = List<int>.generate(32, (_) => random.nextInt(256));
    final secureRandom = pc.SecureRandom(name);
    secureRandom.seed(pc.KeyParameter(Uint8List.fromList(seeds)));
    return secureRandom;
  }

  /// Generate ECC private key
  static ECPrivateKey generatePrivateKey({String curve = 'secp256k1'}) {
    final domainParams = pc.ECDomainParameters("secp256k1");
    final params = pc.ECKeyGeneratorParameters(domainParams);
    final paramsWithRandom = pc.ParametersWithRandom(params, getSecureRandom());
    final generator = pc.ECKeyGenerator()..init(paramsWithRandom);
    final keypair = generator.generateKeyPair();
    return keypair.privateKey as ECPrivateKey;
  }

  /// Calculate ECC public key from private key
  static ECPublicKey publicKeyFromPrivateKey(ECPrivateKey privateKey) {
    pc.ECDomainParameters params = privateKey.parameters!;
    return ECPublicKey(params.G * privateKey.d, params);
  }

  //
  //  PEM
  //

  /// Decode ECC public key from PEM text
  static ECPublicKey decodePublicKey(String pem) {
    if (pem.length == 130 || pem.length == 66) {
      // hex(4 + Q.x + Q.y)
      // hex(3 + Q.x)
      // hex(2 + Q.x)
      final data = dim.Hex.decode(pem);
      final domainParams = pc.ECDomainParameters("secp256k1");
      final Q = domainParams.curve.decodePoint(data!);
      return ECPublicKey(Q, domainParams);
    }
    return CryptoUtils.ecPublicKeyFromPem(pem);
  }

  /// Decode ECC private key from PEM text
  static ECPrivateKey decodePrivateKey(String pem) {
    if (pem.length == 64) {
      // hex(s)
      final d = BigInt.parse(pem, radix: 16);
      final domainParams = pc.ECDomainParameters("secp256k1");
      return ECPrivateKey(d, domainParams);
    }
    return CryptoUtils.ecPrivateKeyFromPem(pem);
  }

  /// Encode ECC public key to PEM format (X.509)
  static String encodePublicKey(ECPublicKey publicKey) {
    return CryptoUtils.encodeEcPublicKeyToPem(publicKey);
  }

  /// Encode ECC private key to PEM format (PKCS#8)
  static String encodePrivateKey(ECPrivateKey privateKey) {
    return CryptoUtils.encodePrivateEcdsaKeyToPkcs8(privateKey);
  }

  /// Encode ECC private key
  static Uint8List encodePrivateKeyData(ECPrivateKey privateKey) {
    String hex = privateKey.d!.toRadixString(16);
    if (hex.length < 64) {
      // make sure it's 32 bytes
      hex = hex.padLeft(64, '0');
    }
    return dim.Hex.decode(hex)!;
  }

  /// Encode ECC public key to raw bytes.
  ///
  /// [compressed] - whether to use the compressed point format,
  ///                 default is true.
  ///
  /// Returns the encoded key point data.
  static Uint8List encodePublicKeyData(ECPublicKey publicKey, {bool compressed = true}) {
    return publicKey.Q!.getEncoded(compressed);
  }
}
