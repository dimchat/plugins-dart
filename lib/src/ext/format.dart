/* license: https://mit-license.org
 *
 *  Ming-Ke-Ming : Decentralized User Identity Authentication
 *
 *                                Written in 2023 by Moky <albert.moky@gmail.com>
 *
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
import 'dart:typed_data';

import 'package:dimp/crypto.dart';
import 'package:dimp/ext.dart';

import '../format/uri.dart';

/// Format GeneralFactory
/// ~~~~~~~~~~~~~~~~~~~~~
class FormatGeneralFactory implements GeneralFormatHelper,
                                      PortableNetworkFileHelper,
                                      TransportableDataHelper {

  final Map<String, TransportableDataFactory> _tedFactories = {};

  PortableNetworkFileFactory? _pnfFactory;

  @override
  String? getFormatAlgorithm(Map ted, [String? defaultValue]) {
    return Converter.getString(ted['algorithm'], defaultValue);
  }

  ///
  ///   TED - Transportable Encoded Data
  ///

  @override
  void setTransportableDataFactory(String algorithm, TransportableDataFactory factory) {
    _tedFactories[algorithm] = factory;
  }

  @override
  TransportableDataFactory? getTransportableDataFactory(String algorithm) {
    return _tedFactories[algorithm];
  }

  @override
  TransportableData createTransportableData(Uint8List data, String? algorithm) {
    algorithm ??= EncodeAlgorithms.DEFAULT;
    TransportableDataFactory? factory = getTransportableDataFactory(algorithm);
    assert(factory != null, 'TED algorithm not support: $algorithm');
    return factory!.createTransportableData(data);
  }

  @override
  TransportableData? parseTransportableData(Object? ted) {
    if (ted == null) {
      return null;
    } else if (ted is TransportableData) {
      return ted;
    }
    // unwrap
    Map? info = parseData(ted);
    if (info == null) {
      // assert(false, 'TED error: $ted');
      return null;
    }
    String? algo = getFormatAlgorithm(info);
    // assert(algo != null, 'TED error: $ted');
    var factory = algo == null ? null : getTransportableDataFactory(algo);
    if (factory == null) {
      // unknown algorithm, get default factory
      factory = getTransportableDataFactory('*');  // unknown
      assert(factory != null, 'default TED factory not found');
    }
    return factory?.parseTransportableData(info);
  }

  ///
  ///   PNF - Portable Network File
  ///

  @override
  void setPortableNetworkFileFactory(PortableNetworkFileFactory factory) {
    _pnfFactory = factory;
  }

  @override
  PortableNetworkFileFactory? getPortableNetworkFileFactory() {
    return _pnfFactory;
  }

  @override
  PortableNetworkFile createPortableNetworkFile(TransportableData? data, String? filename,
      Uri? url, DecryptKey? password) {
    PortableNetworkFileFactory? factory = getPortableNetworkFileFactory();
    assert(factory != null, 'PNF factory not ready');
    return factory!.createPortableNetworkFile(data, filename, url, password);
  }

  @override
  PortableNetworkFile? parsePortableNetworkFile(Object? pnf) {
    if (pnf == null) {
      return null;
    } else if (pnf is PortableNetworkFile) {
      return pnf;
    }
    // unwrap
    Map? info = parseURL(pnf);
    if (info == null) {
      // assert(false, 'PNF error: $pnf');
      return null;
    }
    PortableNetworkFileFactory? factory = getPortableNetworkFileFactory();
    assert(factory != null, 'PNF factory not ready');
    return factory?.parsePortableNetworkFile(info);
  }

  //
  //  Convenience
  //

  ///  Parse PNF
  // protected
  Map? parseURL(Object? pnf) {
    Map? info = getMap(pnf);
    if (info == null) {
      // parse data URI from text string
      String? text = Converter.getString(pnf);
      info = parseDataURI(text);
      if (info != null) {
        // data URI
        assert(text?.contains('://') != true, 'PNF data error: $pnf');
        // if (text?.contains('://') == true) {
        //   info['URI'] = text;
        // }
      } else if (text?.contains('://') == true) {
        // [URL]
        info = {
          'URL': text,
        };
      }
    }
    return info;
  }

  ///  Parse TED
  // protected
  Map? parseData(Object? ted) {
    Map? info = getMap(ted);
    if (info == null) {
      // parse data URI from text string
      String? text = Converter.getString(ted);
      info = parseDataURI(text);
      if (info == null) {
        assert(text?.contains('://') != true, 'TED data error: $ted');
        // [TEXT]
        info = {
          'data': text,
        };
      }
    }
    return info;
  }

  // protected
  Map? getMap(Object? value) {
    if (value == null) {
      return null;
    } else if (value is Mapper) {
      return value.toMap();
    } else if (value is Map) {
      return value;
    }
    String? text = Converter.getString(value);
    if (text == null || text.length < 8) {
      return null;
    } else if (text.startsWith('{') && text.endsWith('}')) {
      // from JSON string
      return JSONMap.decode(text);
    } else {
      return null;
    }
  }

  // protected
  Map? parseDataURI(String? text) {
    DataURI? uri = DataURI.parse(text);
    return uri?.toMap();
  }

}
