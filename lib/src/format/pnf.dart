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
import 'package:dimp/crypto.dart';


///  PNF - Portable Network File
///
///  A file which can be transmitted over the network, containing
///  any one (or more) of:
///  - file data (embedded as data URI)
///  - file name
///  - download URL (CDN)
///  - password (decrypt key for the data downloaded from CDN)
///
///  It is serialized as a string (URI) when possible, or as a
///  dictionary otherwise.
class PortableNetworkFile extends Dictionary implements TransportableFile {
  /// Create a PNF with the content dictionary and optional properties.
  PortableNetworkFile(Mapping? content, {
    TransportableData? data,
    String? filename,
    Uri? url,
    DecryptKey? password,
    TransportableFileWrapper? wrapper,
  }) : super(content) {
    _wrapper = wrapper ?? TransportableFileWrapper.create(super.toMap(),
      data: data, filename: filename, url: url, password: password,
    );
  }

  late TransportableFileWrapper _wrapper;

  /// Create a PNF with the raw properties directly.
  PortableNetworkFile.from(TransportableData? data, String? filename,
      Uri? url, DecryptKey? password) {
    _wrapper = TransportableFileWrapper.create(super.toMap(),
      data: data, filename: filename, url: url, password: password,
    );
  }

  /// Create a PNF with the file [data] and optional [filename].
  factory PortableNetworkFile.createWithData(TransportableData data, String? filename) =>
      PortableNetworkFile.from(data, filename, null, null);

  /// Create a PNF with a download [url] and the [password] to decrypt it.
  factory PortableNetworkFile.createWithURL(Uri url, DecryptKey? password) =>
      PortableNetworkFile.from(null, null, url, password);

  /// Serialize this PNF into a URI string.
  ///
  /// Returns the data URI / URL string if this PNF can be represented
  /// by a single URI, otherwise returns an empty string.
  // protected
  String get uriString {
    // serialize
    MutableMapping dict = _wrapper.toMap();
    // check 'URL'
    Uri? remote = url;
    if (remote != null) {
      int count = dict.length;
      if (count == 1) {
        // this PNF info contains 'URL' only,
        // so return the URI string here.
        return remote.toString();
      } else if (count == 2 && containsKey('filename')) {
        // ignore 'filename'
        return remote.toString();
      }
      // this PNF info contains other params,
      // cannot serialize it as a string.
      return '';
    }
    // check data
    String? text = getString('data');
    if (text != null && text.startsWith('data:')) {
      int count = dict.length;
      if (count == 1) {
        // this PNF info contains 'data' only,
        // and it is a data URI,
        // so return the URI string here.
        return text;
      } else if (count == 2 && containsKey('filename')) {
        // check 'filename'
        String? filename = getString('filename');
        if (filename == null || filename.isEmpty) {
          // nothing changed
          return text;
        }
        // add 'filename' to data URI
        text = newDataURI(text, filename);
        return text;
      }
      // this PNF info contains other params,
      // cannot serialize it as a string.
      return '';
    }
    // the file data was saved into local storage,
    // so there is just a 'filename' here,
    // cannot build URI string
    return '';
  }

  /// Build a new data URI by updating the 'filename' parameter.
  ///
  /// [text]     - the original data URI string.
  /// [filename] - the new filename to set (empty to remove it).
  ///
  /// Returns the rebuilt data URI.
  // protected
  String newDataURI(String text, String filename) {
    UriData uri = UriData.parse(text);
    // copy extra values
    Map<String, String> extra = Map.of(uri.parameters);
    if (filename.isEmpty) {
      // erase 'filename'
      extra.remove('filename');
    } else {
      // update 'filename'
      extra['filename'] = filename;
    }
    // build header
    String mimeType = uri.mimeType;
    if (mimeType.isEmpty) {
      // make sure 'mime-type' is the first header
      mimeType = 'text/plain';
    }
    String header = mimeType;
    extra.forEach((name, value) {
      header += ';$name=$value';
    });
    if (uri.isBase64) {
      header += ';base64';
    }
    // build new data URI
    int pos = text.indexOf(',');
    String body = text.substring(pos + 1);
    return 'data:$header,$body';
  }

  @override
  String toString() {
    final uri = uriString;
    if (uri.isNotEmpty) {
      return uri;
    }
    // return JSON string
    final dict = _wrapper.toMap();
    return JSONMap.encode(dict);
  }

  @override
  MutableMapping toMap() {
    // call wrapper to serialize 'data' & 'key"
    return _wrapper.toMap();
  }

  @override
  Object serialize() {
    final uri = uriString;
    if (uri.isNotEmpty) {
      return uri;
    }
    // return inner map
    return _wrapper.toMap();
  }

  ///  file data

  @override
  TransportableData? get data => _wrapper.data;

  @override
  set data(TransportableData? ted) => _wrapper.data = ted;

  ///  file name

  @override
  String? get filename => _wrapper.filename;

  @override
  set filename(String? name) => _wrapper.filename = name;

  ///  download URL

  @override
  Uri? get url => _wrapper.url;

  @override
  set url(Uri? remote) => _wrapper.url = remote;

  ///  decrypt key

  @override
  DecryptKey? get password => _wrapper.password;

  @override
  set password(DecryptKey? key) => _wrapper.password = key;

}
