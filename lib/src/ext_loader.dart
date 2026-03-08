/* license: https://mit-license.org
 * =============================================================================
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
 * =============================================================================
 */
import 'package:dimp/dimp.dart';

import 'dkd/factory.dart';

import 'ext/account.dart';
import 'ext/command.dart';
import 'ext/crypto.dart';
import 'ext/format.dart';
import 'ext/message.dart';
import 'ext_content.dart';


/// Core Extensions Loader
/// ~~~~~~~~~~~~~~~~~~~~~~
class ExtensionLoader with ContentFactoryPlugins {

  /// Register core factories
  void load() {

    registerCoreHelpers();

    registerMessageFactories();

    registerContentFactories();
    registerCommandFactories();

  }

  ///  Core extensions
  // protected
  void registerCoreHelpers() {

    registerCryptoHelpers();
    registerFormatHelpers();

    registerAccountHelpers();

    registerMessageHelpers();
    registerCommandHelpers();

  }
  void registerCryptoHelpers() {
    // crypto
    var cryptoHelper = CryptoKeyGeneralFactory();
    sharedCryptoExtensions.symmetricHelper = cryptoHelper;
    sharedCryptoExtensions.privateHelper   = cryptoHelper;
    sharedCryptoExtensions.publicHelper    = cryptoHelper;
    sharedCryptoExtensions.helper          = cryptoHelper;
  }
  void registerFormatHelpers() {
    // format
    var formatHelper = FormatGeneralFactory();
    sharedFormatExtensions.pnfHelper = formatHelper;
    sharedFormatExtensions.tedHelper = formatHelper;
  }
  void registerAccountHelpers() {
    // mkm
    var accountHelper = AccountGeneralFactory();
    sharedAccountExtensions.addressHelper = accountHelper;
    sharedAccountExtensions.idHelper      = accountHelper;
    sharedAccountExtensions.metaHelper    = accountHelper;
    sharedAccountExtensions.docHelper     = accountHelper;
    sharedAccountExtensions.helper        = accountHelper;
  }
  void registerMessageHelpers() {
    // dkd
    var msgHelper = MessageGeneralFactory();
    sharedMessageExtensions.contentHelper  = msgHelper;
    sharedMessageExtensions.envelopeHelper = msgHelper;
    sharedMessageExtensions.instantHelper  = msgHelper;
    sharedMessageExtensions.secureHelper   = msgHelper;
    sharedMessageExtensions.reliableHelper = msgHelper;
    sharedMessageExtensions.helper         = msgHelper;
  }
  void registerCommandHelpers() {
    // cmd
    var cmdHelper = CommandGeneralFactory();
    sharedMessageExtensions.cmdHelper     = cmdHelper;
    sharedMessageExtensions.commandHelper = cmdHelper;
  }

  ///  Message factories
  // protected
  void registerMessageFactories() {

    // Envelope factory
    MessageFactory factory = MessageFactory();
    Envelope.setFactory(factory);

    // Message factories
    InstantMessage.setFactory(factory);
    SecureMessage.setFactory(factory);
    ReliableMessage.setFactory(factory);

  }

}
