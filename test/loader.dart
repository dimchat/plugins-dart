import 'dart:typed_data';

import 'package:dim_plugins/dimp.dart';
import 'package:dim_plugins/crypto.dart';
import 'package:dim_plugins/loader.dart';

import 'address.dart';
import 'digest.dart';


class ClientPluginLoader extends PluginLoader {

  @override
  void registerDigesters() {
    super.registerDigesters();

    registerMD5Digester();
    registerSHA1Digester();
  }
  // protected
  void registerMD5Digester() {
    /// MD5
    MD5.digester = MD5Digester();
  }
  // protected
  void registerSHA1Digester() {
    /// SHA1
    SHA1.digester = SHA1Digester();
  }

  @override
  void registerAddressFactory() {
    Address.setFactory(CompatibleAddressFactory());
  }

  @override
  void registerBase64Coder() {
    /// Base64 coding
    Base64.coder = PatchBase64Coder();
  }

}

/// Base-64
class PatchBase64Coder extends Base64Coder {

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


class LibraryLoader {
  LibraryLoader({ExtensionLoader? extensionLoader, PluginLoader? pluginLoader}) {
    this.extensionLoader = extensionLoader ?? ExtensionLoader();
    this.pluginLoader = pluginLoader ?? ClientPluginLoader();
  }

  late final ExtensionLoader extensionLoader;
  late final PluginLoader pluginLoader;

  bool _loaded = false;

  void run() {
    if (_loaded) {
      // no need to load it again
      return;
    } else {
      // mark it to loaded
      _loaded = true;
    }
    // try to load all plugins
    load();
  }

  // protected
  void load() {
    extensionLoader.load();
    pluginLoader.load();
  }

}
