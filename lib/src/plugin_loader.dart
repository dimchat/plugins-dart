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
import 'crypto/digest.dart';
import 'format/coders.dart';
import 'format/trans.dart';

import 'plugin_entity.dart';
import 'plugin_keys.dart';


class PluginLoader with CoderPlugins, TransportablePlugins, DigestPlugins, CryptoPlugins, EntityPlugins {

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
  ///  Message digesters
  void registerDigesters() {

    registerSHA256Digester();

    registerKECCAK256Digester();

    registerRIPEMD160Digester();

  }

  // protected
  ///  Symmetric key parsers
  void registerSymmetricKeyFactories() {

    registerAESKeyFactory();

    registerPlainKeyFactory();

  }

  // protected
  ///  Asymmetric key parsers
  void registerAsymmetricKeyFactories() {

    registerRSAKeyFactories();

    registerECCKeyFactories();

  }

  // protected
  ///  ID, Address, Meta, Document parsers
  void registerEntityFactories() {

    registerIDFactory();

    registerAddressFactory();

    registerMetaFactories();

    registerDocumentFactories();

  }

}
