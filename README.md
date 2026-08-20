# DIM Algorithm Plugins (Dart)

[![License](https://img.shields.io/github/license/dimchat/plugins-dart)](https://github.com/dimchat/plugins-dart/blob/main/LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/dimchat/plugins-dart/pulls)
[![Platform](https://img.shields.io/badge/Platform-Dart%203-brightgreen.svg)](https://github.com/dimchat/plugins-dart/wiki)
[![Issues](https://img.shields.io/github/issues/dimchat/plugins-dart)](https://github.com/dimchat/plugins-dart/issues)
[![Repo Size](https://img.shields.io/github/repo-size/dimchat/plugins-dart)](https://github.com/dimchat/plugins-dart/archive/refs/heads/main.zip)
[![Tags](https://img.shields.io/github/tag/dimchat/plugins-dart)](https://github.com/dimchat/plugins-dart/tags)
[![Version](https://img.shields.io/pub/v/dimap)](https://pub.dev/packages/dimap)

[![Watchers](https://img.shields.io/github/watchers/dimchat/plugins-dart)](https://github.com/dimchat/plugins-dart/watchers)
[![Forks](https://img.shields.io/github/forks/dimchat/plugins-dart)](https://github.com/dimchat/plugins-dart/forks)
[![Stars](https://img.shields.io/github/stars/dimchat/plugins-dart)](https://github.com/dimchat/plugins-dart/stargazers)
[![Followers](https://img.shields.io/github/followers/dimchat)](https://github.com/orgs/dimchat/followers)

## Dependencies

* Latest Versions

| Name | Version | Description |
|------|---------|-------------|
| [Ming Ke Ming (名可名)](https://github.com/dimchat/mkm-dart) | [![Version](https://img.shields.io/pub/v/mkm)](https://pub.dev/packages/mkm) | Decentralized User Identity Authentication |
| [Dao Ke Dao (道可道)](https://github.com/dimchat/dkd-dart) | [![Version](https://img.shields.io/pub/v/dkd)](https://pub.dev/packages/dkd) | Universal Message Module |
| [DIMP (去中心化通讯协议)](https://github.com/dimchat/core-dart) | [![Version](https://img.shields.io/pub/v/dimp)](https://pub.dev/packages/dimp) | Decentralized Instant Messaging Protocol |

## Plugins

1. Data Coding
   * Base-58
   * Base-64
   * Hex
   * UTF-8
   * JsON
   * PNF _(Portable Network File)_
   * TED _(Transportable Encoded Data)_
2. Digest Digest
   * SHA-256
   * Keccak-256
   * RipeMD-160
3. Cryptography
   * AES-256 _(AES/CBC/PKCS7Padding)_
   * RSA-1024 _(RSA/ECB/PKCS1Padding)_, _(SHA256withRSA)_
   * ECC _(Secp256k1)_

### Plugin Loader

```dart
import 'dart:typed_data';

import 'package:dimp/dimp.dart';
import 'package:dimap/dimap.dart';


class CompatiblePluginLoader extends PluginLoader {

  @override
  void registerBase64Coder() {

    /// Base64 coding
    Base64.coder = _PatchBase64Coder();

  }

}

/// Base-64
class _PatchBase64Coder extends Base64Coder {

  @override
  Uint8List? decode(String string) {
    string = trimBase64String(string);
    return super.decode(string);
  }

  static String trimBase64String(String b64) {
    if (b64.contains('\n')) {
      b64 = b64.replaceAll('\n', '');
      b64 = b64.replaceAll('\r', '');
      b64 = b64.replaceAll('\t', '');
      b64 = b64.replaceAll(' ', '');
    }
    return b64.trim();
  }
}
```

This library is primarily designed to implement various algorithms in a plug-in manner, allowing you to further develop additional algorithms tailored to your specific applications.

----

Copyright &copy; 2023-2026 Albert Moky
[![Followers](https://img.shields.io/github/followers/moky)](https://github.com/moky?tab=followers)
