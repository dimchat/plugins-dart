import 'package:dimap/crypto.dart';
import 'package:dimap/ext.dart';

import 'base64.dart';
import 'digest.dart';


/// Plugins Loader
/// ~~~~~~~~~~~~~~
class CommonPluginLoader extends PluginLoader {

  @override
  void loadDigesters() {
    super.loadDigesters();

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
  void registerBase64Coder() {
    /// Base64 coding
    Base64.coder = PatchBase64Coder();
  }

}
