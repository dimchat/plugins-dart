/* license: https://mit-license.org
 *
 *  Ming-Ke-Ming : Decentralized User Identity Authentication
 *
 *                                Written in 2023 by Moky <albert.moky@gmail.com>
 *
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
import 'package:dimp/mkm.dart';
import 'package:dimp/ext.dart';


///
/// General Document Factory
///
class GeneralDocumentFactory implements DocumentFactory {
  GeneralDocumentFactory(this.type);

  // protected
  final String type;

  @override
  Document createDocument({String? data, TransportableData? signature}) {
    String docType = type;
    if (data == null || data.isEmpty) {
      assert(signature == null, 'document error: $data, signature: $signature');
      // 1. create empty document
    } else {
      assert(signature != null, 'document error: $data, signature: $signature');
      // 2. create document with data & signature from local storage
    }
    Document out;
    switch (docType) {

      case DocumentType.VISA:
        out = BaseVisa.fromData(data: data, signature: signature);
        break;

      case DocumentType.BULLETIN:
        out = BaseBulletin.fromData(data: data, signature: signature);
        break;

      default:
        out = BaseDocument.fromType(docType, data: data, signature: signature);
    }
    assert(data == null || out.isValid, 'document error: $out');
    return out;
  }

  @override
  Document? parseDocument(Map doc) {
    // check 'did', 'data', 'signature'
    if (doc['data'] == null || doc['signature'] == null) {
      // doc.data should not be empty
      // doc.signature should not be empty
      assert(false, 'document error: $doc');
      return null;
    // } else if (doc['did'] == null) {
    //   // doc.did should not be empty
    //   assert(false, 'document error: $doc');
    //   return null;
    }

    // create document for type
    var ext = SharedAccountExtensions();
    String? docType = ext.helper?.getDocumentType(doc, null);
    switch (docType) {

      case DocumentType.VISA:
        return BaseVisa(doc);

      case DocumentType.BULLETIN:
        return BaseBulletin(doc);

      default:
        return BaseDocument(doc);
    }
  }

}
