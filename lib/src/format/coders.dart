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
import 'dart:convert';
import 'dart:typed_data';

import 'package:fast_base58/fast_base58.dart';

import 'package:dimp/crypto.dart';


/// UTF-8 string coder.
///
/// Encodes a string into UTF-8 bytes, and decodes bytes back
/// to a string (returns null if the bytes are not valid UTF-8).
class UTF8Coder implements StringCoder {

  @override
  Uint8List encode(String string) {
    final array = utf8.encode(string);
    return Uint8List.fromList(array);
  }

  @override
  String? decode(Uint8List data) {
    try {
      return utf8.decode(data);
    } on FormatException {
      return null;
    }
  }
}

/// JSON object coder.
///
/// Serializes an object to a JSON string, and parses a JSON string
/// back to a dynamic object.
class JSONCoder implements ObjectCoder<dynamic> {

  @override
  String encode(dynamic object) {
    return json.encode(object);
  }

  @override
  dynamic decode(String string) {
    return json.decode(string);
  }
}

/// Hexadecimal data coder.
///
/// Encodes bytes to a hex string (lowercase), and decodes a hex string
/// back to bytes. An odd-length hex string is treated as a leading
/// nibble (e.g. "abc" -> [0x0a, 0xbc]).
class HexCoder implements DataCoder {

  @override
  String encode(Uint8List data) {
    StringBuffer sb = StringBuffer();
    int item;
    for (int i = 0; i < data.lengthInBytes; ++i) {
      item = data[i];
      if (item < 16) {
        sb.write('0');
      }
      sb.write(item.toRadixString(16));
    }
    return sb.toString();
  }

  @override
  Uint8List? decode(String string) {
    Uint8List data;
    String item;
    int offset;
    bool odd = string.length & 1 == 1;
    if (odd) {
      data = Uint8List((string.length ~/ 2) + 1);
      item = string.substring(0, 1);
      data.add(int.parse(item, radix: 16));
      // data[0] = int.parse(item, radix: 16);
      offset = 1;
    } else {
      data = Uint8List(string.length ~/ 2);
      offset = 0;
    }
    int? value;
    for (int i = offset; i < string.length; i += 2, offset += 1) {
      item = string.substring(i, i + 2);
      value = int.tryParse(item, radix: 16);
      if (value == null) {
        return null;
      }
      data[offset] = value;
    }
    return data;
  }
}

/// Base-58 data coder.
///
/// Encodes bytes to a Base-58 string, and decodes a Base-58 string
/// back to bytes.
class Base58Coder implements DataCoder {

  @override
  String encode(Uint8List data) {
    return Base58Encode(data);
  }

  @override
  Uint8List? decode(String string) {
    return Uint8List.fromList(Base58Decode(string));
  }
}

/// Base-64 data coder.
///
/// Encodes bytes to a Base-64 string, and decodes a Base-64 string
/// back to bytes.
class Base64Coder implements DataCoder {

  @override
  String encode(Uint8List data) {
    return base64.encode(data);
  }

  @override
  Uint8List? decode(String string) {
    return base64.decode(string);
  }
}


/// Coder Plugins
///
/// Registers the data coders (UTF-8, JSON, Hex, Base-58,
/// Base-64) into the global coder holders.
mixin CoderPlugins {

  /// set UTF-8 coder
  // protected
  void registerUTF8Coder() {

    UTF8.coder = UTF8Coder();

  }

  /// set JSON coder
  // protected
  void registerJSONCoder() {

    JSON.coder = JSONCoder();

  }

  /// set HEX coder
  // protected
  void registerHexCoder() {

    Hex.coder = HexCoder();

  }

  /// set Base-58 coder
  // protected
  void registerBase58Coder() {

    Base58.coder = Base58Coder();

  }

  /// set Base-64 coder
  // protected
  void registerBase64Coder() {

    Base64.coder = Base64Coder();

  }

}
