/* license: https://mit-license.org
 * ==============================================================================
 * The MIT License (MIT)
 *
 * Copyright (c) 2025 Albert Moky
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

import 'package:pointycastle/api.dart';
import 'package:pointycastle/digests/md5.dart';
import 'package:pointycastle/digests/sha1.dart';

import 'package:dimp/crypto.dart';


class MD5 {

  static Uint8List digest(Uint8List data) {
    return digester!.digest(data);
  }

  static MessageDigester? digester;
}

class SHA1 {

  static Uint8List digest(Uint8List data) {
    return digester!.digest(data);
  }

  static MessageDigester? digester;
}


/// Implementation


Uint8List _hash(Uint8List data, Digest digester) {
  digester.reset();
  return digester.process(data);
}


class MD5Digester implements MessageDigester {

  @override
  Uint8List digest(Uint8List data) {
    return _hash(data, MD5Digest());
  }
}

class SHA1Digester implements MessageDigester {

  @override
  Uint8List digest(Uint8List data) {
    return _hash(data, SHA1Digest());
  }
}
