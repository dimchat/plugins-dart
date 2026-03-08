/* license: https://mit-license.org
 * ==============================================================================
 * The MIT License (MIT)
 *
 * Copyright (c) 2026 Albert Moky
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

import 'crypto/aes.dart';
import 'crypto/ecc.dart';
import 'crypto/plain.dart';
import 'crypto/rsa.dart';


mixin CryptoPlugins {

  void registerAESKeyFactory() {

    /// AES
    var aes = AESKeyFactory();
    SymmetricKey.setFactory(SymmetricAlgorithms.AES, aes);
    SymmetricKey.setFactory(AESKey.AES_CBC_PKCS7, aes);
    // SymmetricKey.setFactory('AES/CBC/PKCS7Padding', aes);

  }

  void registerPlainKeyFactory() {

    /// Plain
    SymmetricKey.setFactory(SymmetricAlgorithms.PLAIN, PlainKeyFactory());

  }

  void registerRSAKeyFactories() {

    /// RSA
    var rsaPub = RSAPublicKeyFactory();
    PublicKey.setFactory(AsymmetricAlgorithms.RSA, rsaPub);
    PublicKey.setFactory('SHA256withRSA', rsaPub);
    PublicKey.setFactory('RSA/ECB/PKCS1Padding', rsaPub);

    var rsaPri = RSAPrivateKeyFactory();
    PrivateKey.setFactory(AsymmetricAlgorithms.RSA, rsaPri);
    PrivateKey.setFactory('SHA256withRSA', rsaPri);
    PrivateKey.setFactory('RSA/ECB/PKCS1Padding', rsaPri);

  }

  void registerECCKeyFactories() {

    /// ECC
    var eccPub = ECCPublicKeyFactory();
    PublicKey.setFactory(AsymmetricAlgorithms.ECC, eccPub);
    PublicKey.setFactory('SHA256withECDSA', eccPub);

    var eccPri = ECCPrivateKeyFactory();
    PrivateKey.setFactory(AsymmetricAlgorithms.ECC, eccPri);
    PrivateKey.setFactory('SHA256withECDSA', eccPri);

  }

}
