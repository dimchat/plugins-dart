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
import 'dart:typed_data';

import 'package:dimp/crypto.dart';

import '../crypto/algorithms.dart';


///
///  Base-64 encoding
///

///  A [TransportableData] wrapper whose encoded string is
///  a Base-64 encoded text.
class Base64Data extends BaseData {
  Base64Data(super.encoded, super.bytes);

  // /// Create a Base-64 data with both the encoded string and the bytes.
  // factory Base64Data.create(String encoded, Uint8List bytes)=>
  //     Base64Data(encoded, bytes);

  /// Create a Base-64 data from the encoded string only.
  ///
  /// The binary data will be decoded lazily when accessed.
  factory Base64Data.createWithString(String encoded) =>
      Base64Data(encoded, null);

  /// Create a Base-64 data from the binary bytes only.
  ///
  /// The encoded string will be generated lazily when accessed.
  factory Base64Data.createWithBytes(Uint8List bytes) =>
      Base64Data('', bytes);

  //
  //  TransportableData
  //

  @override
  String? get encoding => EncodeAlgorithms.BASE_64;

  @override
  Uint8List? get bytes {
    Uint8List? bin = binary;
    if (bin == null) {
      String base64 = string;
      bin = Base64.decode(base64);
      binary = bin;
      assert(bin != null, 'failed to decode base64 string: $base64');
    }
    return bin;
  }


  @override
  String toString() {
    String base64 = string;
    if (base64 == '') {
      Uint8List? bin = binary;
      if (bin != null) {
        base64 = Base64.encode(bin);
        string = base64;
      }
      assert(base64.isNotEmpty, 'failed to encode base64 data: ${bin?.length} byte(s)');
    }
    return base64;
  }

}
