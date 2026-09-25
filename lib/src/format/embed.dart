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


///  Data URI for embed image/audio.
///
///  RFC 2397: https://www.rfc-editor.org/rfc/rfc2397
///
///      data:[<mime type>][;charset=<charset>][;<encoding>],<encoded data>

///  The encoded string is a data URI which embeds the binary data
///  with its mime-type, charset and encoding parameters.
class EmbedData extends BaseData {
  EmbedData(super.encoded, super.bytes);

  UriData? _dataUri;

  // data uri headers
  String? _mimeType;  // default is "text/plain"
  Map<String, String>? _parameters;

  /// Create an EmbedData with the encoded string and optional headers.
  ///
  /// [encoded]    - the data URI string (may be empty to encode later).
  /// [bytes]      - the binary data (may be null to decode later).
  /// [uri]        - the parsed data URI, if available.
  /// [mimeType]   - the mime type header, default is "text/plain".
  /// [parameters] - extra URI parameters (charset, filename, ...).
  EmbedData.from(String? encoded, Uint8List? bytes, {
    UriData? uri,
    String? mimeType,
    Map<String, String>? parameters,
  }) : super(encoded ?? '', bytes) {
    _dataUri = uri;
    _mimeType = mimeType;
    _parameters = parameters ?? uri?.parameters;
  }

  /// Create an EmbedData with the data URI string and the bytes.
  factory EmbedData.create(String dataUri, Uint8List bytes, {UriData? uri}) =>
      EmbedData.from(dataUri, bytes,
        uri: uri,
        mimeType: uri?.mimeType,
        parameters: uri?.parameters,
      );

  /// Create an EmbedData from a parsed data URI.
  factory EmbedData.createWithUri(UriData uri) =>
      EmbedData.from(uri.toString(), null,
        uri: uri,
        mimeType: uri.mimeType,
        parameters: uri.parameters,
      );

  /// Create an EmbedData from the data URI string only.
  ///
  /// The binary data will be decoded lazily when accessed.
  factory EmbedData.createWithString(String dataUri) =>
      EmbedData.from(dataUri, null);

  /// Create an EmbedData from the binary bytes with a mime type.
  ///
  /// [bytes]    - the binary data.
  /// [mimeType] - the mime type header (e.g. "image/jpeg").
  /// [filename] - optional filename parameter.
  factory EmbedData.createWithBytes(Uint8List bytes, {
    required String mimeType,
    String? filename,
  }) {
    if (filename == null || filename.isEmpty) {
      return EmbedData.from('', bytes, mimeType: mimeType);
    }
    return EmbedData.from('', bytes, mimeType: mimeType, parameters: {
      'filename': filename,
    });
  }

  //
  //  Data URI:
  //
  //      "data:image/jpg;base64,{BASE64_ENCODE}"
  //      "data:audio/mp4;base64,{BASE64_ENCODE}"
  //

  /// Create an image EmbedData (mime type "image/jpeg").
  ///
  /// [jpeg]     - the JPEG image data.
  /// [filename] - optional filename parameter.
  factory EmbedData.image(Uint8List jpeg, {String? filename}) =>
      EmbedData.createWithBytes(jpeg, mimeType: 'image/jpeg', filename: filename);

  /// Create an audio EmbedData (mime type "audio/mp4").
  ///
  /// [mp4]      - the MP4 audio data.
  /// [filename] - optional filename parameter.
  factory EmbedData.audio(Uint8List mp4, {String? filename}) =>
      EmbedData.createWithBytes(mp4, mimeType: 'audio/mp4', filename: filename);

  //
  //  Uri Headers
  //

  /// Get a header value by name.
  ///
  /// Returns the URI parameter with the exact [name] first, then
  /// falls back to the standard headers: "encoding", "mime-type"
  /// and "content-type".
  String? getHeader(String name) {
    String? value = parameters?[name];
    if (value != null) {
      // charset
      // filename
      return value;
    }
    switch (name.toLowerCase()) {
      case 'encoding':
        return encoding;
      case 'mime-type':
        return mimeType;
      case 'content-type':
        return mimeType;
    }
    return null;
  }

  /// Get all URI parameters.
  Map<String, String>? get parameters => _parameters ?? (dataUri?.parameters);

  /// Get the mime type header, default is "text/plain".
  String? get mimeType => _mimeType ?? (dataUri?.mimeType);
  /// Get the charset header, default is "us-ascii".
  String? get charset => parameters?['charset'] ?? (dataUri?.charset);
  /// Get the filename parameter, e.g. "avatar.png".
  String? get filename => parameters?['filename'];

  //
  //  Build Data URI: "data:.../...;base64,..."
  //
  /// If the encoded string is empty, encode the binary data lazily
  /// to build the URI with the mime type and parameters.
  UriData? get dataUri {
    UriData? uri = _dataUri;
    if (uri != null) {
      return uri;
    }
    // check encoded data uri
    String txt = string;
    if (txt.isEmpty) {
      // encode data to build uri
      Uint8List? bin = binary;
      if (bin == null/* || bin.isEmpty*/) {
        return null;
      }
      assert(bin.isNotEmpty, 'embed data empty');
      // encode body
      String body = Base64.encode(bin);
      assert(body.isNotEmpty, 'failed to encode ${bin.length} byte(s)');
      // make sure 'mime-type' is the first header
      String mimeType = _mimeType ?? 'text/plain';
      // build header
      String header = mimeType;
      _parameters?.forEach((key, value) {
        header += ';$key=$value';
      });
      txt = 'data:$header;base64,$body';
      // string = txt;
    }
    uri = UriData.parse(txt);
    _dataUri = uri;
    return uri;
  }

  //
  //  TransportableData
  //

  @override
  String? get encoding {
    final uri = dataUri;
    if (uri == null) {
      assert(false, 'data uri error');
      return null;
    } else if (uri.isBase64) {
      return EncodeAlgorithms.BASE_64;
    }
    // plaintext
    return '';
  }

  @override
  Uint8List? get bytes {
    Uint8List? bin = binary;
    if (bin == null) {
      final uri = dataUri;
      if (uri != null) {
        bin = uri.contentAsBytes();
        binary = bin;
      }
      assert(uri != null, 'failed to decode data uri');
    }
    return bin;
  }


  @override
  String toString() {
    String txt = string;
    if (txt == '') {
      final uri = dataUri;
      if (uri != null) {
        txt = uri.toString();
        string = txt;
      }
      assert(uri != null, 'failed to encode data uri');
    }
    return txt;
  }

}
