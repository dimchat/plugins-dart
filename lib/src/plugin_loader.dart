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

import 'plugin_core.dart';
import 'plugin_format.dart';
import 'plugin_keys.dart';


/// Core Plugins Loader
///
/// Loads all plugins of the DimPlugins library by registering
/// the data coders, message digesters, key factories and
/// TED/PNF factories into the corresponding extension holders.
class PluginLoader with CorePlugins, CoderPlugins, DigestPlugins, FormatPlugins, CryptoPlugins {

  /// Register plugins
  void load() {

    loadCorePlugins();

    loadDigestPlugins();
    loadCoderPlugins();
    loadFormatPlugins();

    loadCryptoPlugins();

  }

  ///  Core extensions
  // protected
  void loadCorePlugins() {

    registerFormatHelpers();

    registerCryptoHelpers();

  }

  ///  Data coders
  // protected
  void loadCoderPlugins() {

    registerBase58Coder();
    registerBase64Coder();
    registerHexCoder();

    registerUTF8Coder();
    registerJSONCoder();

  }

  ///  Message digesters
  // protected
  void loadDigestPlugins() {

    registerSHA256Digester();

    registerKECCAK256Digester();

    registerRIPEMD160Digester();

  }

  /// Load the format plugins.
  // protected
  void loadFormatPlugins() {

    registerTEDFactory();

    registerPNFFactory();
    registerPNFWrapperFactory();

  }

  ///  Crypto key parsers
  // protected
  void loadCryptoPlugins() {

    // Symmetric keys
    registerAESKeyFactory();
    registerPlainKeyFactory();

    // Asymmetric keys
    registerRSAKeyFactories();
    registerECCKeyFactories();

  }

}
