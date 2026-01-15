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


///  "data:image/png;base64,{BASE64_ENCODE}"
class DataURI {
  DataURI(this.body, {this.encoding, this.mimeType});

  final String? mimeType;
  final String? encoding;
  final String body;

  Map toMap() {
    Map info = {
      'data': body,
    };
    // 'mime-type'
    var mime = mimeType;
    if (mime != null) {
      info['mime-type'] = mime;
    }
    // 'encoding'
    var algorithm = encoding;
    if (algorithm != null) {
      info['algorithm'] = algorithm;
    }
    return info;
  }

  ///  Split text string for data URI
  ///
  ///      0. "{TEXT}", or "{URL}"
  ///      1. "base64,{BASE64_ENCODE}"
  ///      2. "data:image/png;base64,{BASE64_ENCODE}"
  static DataURI? parse(String? text) {
    if (text == null || text.isEmpty) {
      return null;
    }
    int pos;
    if (text.startsWith('data:')) {
      // "data:image/png;base64,{BASE64_ENCODE}"
      text = text.substring(5);
      pos = text.indexOf(',');
      if (pos < 0) {
        assert(false, 'data URI error: $text');
        return null;
      }
    } else {
      // "base64,{BASE64_ENCODE}"
      pos = text.indexOf(',');
      if (pos < 0 || pos > 8) {
        // "{TEXT}", or "{URL}"
        return null;
      }
    }
    String body = text.substring(pos + 1);
    String head = text.substring(0, pos);
    // split for 'mime-type' + 'encoding'
    pos = head.indexOf(';');
    if (pos < 0) {
      // "base64,{BASE64_ENCODE}"
      return DataURI(body, encoding: head);
    }
    assert(pos > 0, 'data URI error: $text');
    // "data:image/png;base64,{BASE64_ENCODE}"
    String mimeType = head.substring(0, pos);
    String encoding = head.substring(pos + 1);
    return DataURI(body, encoding: encoding, mimeType: mimeType);
  }

  ///  Build data URI
  ///
  ///      format: "data:image/png;base64,{BASE64_ENCODE}"
  ///
  static String? build(Map info) {
    //
    //  1. check encoded data & content type
    //
    var data = info['data'];
    var mime = info['mime-type'];
    if (data == null || mime == null) {
      // params not matched
      return null;
    } else {
      assert(data is String && mime is String, 'params error: $info');
    }
    //
    //  2. check extra params
    //
    int count = info.length;
    if (info.containsKey('filename')) {
      count -= 1;
    }
    var algorithm = info['algorithm'];
    if (algorithm == null) {
      algorithm = EncodeAlgorithms.BASE_64;
    } else {
      assert(algorithm is String, 'params error: $info');
      count -= 1;
    }
    if (count != 2) {
      // extra params exist, cannot build data URI
      return null;
    }
    //
    //  3. build string: 'data:...;...,...'
    //
    return 'data:$mime;$algorithm,$data';
  }

}
