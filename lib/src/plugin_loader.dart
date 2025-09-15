/* license: https://mit-license.org
 * ==============================================================================
 * The MIT License (MIT)
 *
 * Copyright (c) 2024 Albert Moky
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
import 'package:dimp/dimp.dart';

import 'crypto/aes.dart';
import 'crypto/digest.dart';
import 'crypto/ecc.dart';
import 'crypto/plain.dart';
import 'crypto/rsa.dart';
import 'format/coders.dart';
import 'format/pnf.dart';
import 'format/ted.dart';

import 'mkm/address.dart';
import 'mkm/identifier.dart';
import 'mkm/meta.dart';
import 'mkm/document.dart';


class PluginLoader {

  void load() {
    /// Register plugins

    registerCoders();
    registerDigesters();

    registerSymmetricKeyFactories();
    registerAsymmetricKeyFactories();

    registerEntityFactories();

  }

  // protected
  void registerCoders() {
    ///  Data coders

    registerBase58Coder();
    registerBase64Coder();
    registerHexCoder();

    registerUTF8Coder();
    registerJSONCoder();

    registerPNFFactory();
    registerTEDFactory();

  }
  // protected
  void registerBase58Coder() {
    /// Base58 coding
    Base58.coder = Base58Coder();
  }
  // protected
  void registerBase64Coder() {
    /// Base64 coding
    Base64.coder = Base64Coder();
  }
  // protected
  void registerHexCoder() {
    /// HEX coding
    Hex.coder = HexCoder();
  }
  // protected
  void registerUTF8Coder() {
    /// UTF8
    UTF8.coder = UTF8Coder();
  }
  // protected
  void registerJSONCoder() {
    /// JSON
    JSON.coder = JSONCoder();
  }
  // protected
  void registerPNFFactory() {
    /// PNF
    PortableNetworkFile.setFactory(BaseNetworkFileFactory());
  }
  // protected
  void registerTEDFactory() {
    /// TED
    var tedFactory = Base64DataFactory();
    TransportableData.setFactory(EncodeAlgorithms.BASE_64, tedFactory);
    // TransportableData.setFactory(EncodeAlgorithms.DEFAULT, tedFactory);
    TransportableData.setFactory('*', tedFactory);
  }

  // protected
  ///  Message digesters
  void registerDigesters() {

    registerSHA256Digester();

    registerKECCAK256Digester();

    registerRIPEMD160Digester();

  }
  // protected
  void registerSHA256Digester() {
    /// SHA256
    SHA256.digester = SHA256Digester();
  }
  // protected
  void registerKECCAK256Digester() {
    /// Keccak256
    KECCAK256.digester = KECCAK256Digester();
  }
  // protected
  void registerRIPEMD160Digester() {
    /// RIPEMD160
    RIPEMD160.digester = RIPEMD160Digester();
  }

  // protected
  ///  Symmetric key parsers
  void registerSymmetricKeyFactories() {

    registerAESKeyFactory();

    registerPlainKeyFactory();

  }
  // protected
  void registerAESKeyFactory() {
    /// AES
    var aes = AESKeyFactory();
    SymmetricKey.setFactory(SymmetricAlgorithms.AES, aes);
    SymmetricKey.setFactory(AESKey.AES_CBC_PKCS7, aes);
    // SymmetricKey.setFactory('AES/CBC/PKCS7Padding', aes);
  }
  // protected
  void registerPlainKeyFactory() {
    /// Plain
    SymmetricKey.setFactory(SymmetricAlgorithms.PLAIN, PlainKeyFactory());
  }

  // protected
  ///  Asymmetric key parsers
  void registerAsymmetricKeyFactories() {

    registerRSAKeyFactories();

    registerECCKeyFactories();

  }
  // protected
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
  // protected
  void registerECCKeyFactories() {
    /// ECC
    var eccPub = ECCPublicKeyFactory();
    PublicKey.setFactory(AsymmetricAlgorithms.ECC, eccPub);
    PublicKey.setFactory('SHA256withECDSA', eccPub);

    var eccPri = ECCPrivateKeyFactory();
    PrivateKey.setFactory(AsymmetricAlgorithms.ECC, eccPri);
    PrivateKey.setFactory('SHA256withECDSA', eccPri);
  }

  // protected
  ///  ID, Address, Meta, Document parsers
  void registerEntityFactories() {

    registerIDFactory();
    registerAddressFactory();
    registerMetaFactories();
    registerDocumentFactories();

  }
  // protected
  void registerIDFactory() {
    ID.setFactory(IdentifierFactory());
  }
  // protected
  void registerAddressFactory() {
    Address.setFactory(BaseAddressFactory());
  }
  // protected
  void registerMetaFactories() {
    setMetaFactory(MetaType.MKM, 'mkm');
    setMetaFactory(MetaType.BTC, 'btc');
    setMetaFactory(MetaType.ETH, 'eth');
  }
  // protected
  void setMetaFactory(String type, String alias, {MetaFactory? factory}) {
    factory ??= BaseMetaFactory(type);
    Meta.setFactory(type, factory);
    Meta.setFactory(alias, factory);
  }
  // protected
  void registerDocumentFactories() {
    setDocumentFactory('*');
    setDocumentFactory(DocumentType.VISA);
    setDocumentFactory(DocumentType.PROFILE);
    setDocumentFactory(DocumentType.BULLETIN);
  }
  // protected
  void setDocumentFactory(String type, {DocumentFactory? factory}) {
    factory ??= GeneralDocumentFactory(type);
    Document.setFactory(type, factory);
  }

}
