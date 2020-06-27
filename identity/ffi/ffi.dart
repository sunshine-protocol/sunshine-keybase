/// bindings for `libidentity`

import 'package:ffi/ffi.dart' as ffi;
import 'dart:ffi';
import 'dart:io';

// ignore_for_file: unused_import, camel_case_types, non_constant_identifier_names
final DynamicLibrary _dl = _open();
DynamicLibrary _open() {
  if (Platform.isAndroid) return DynamicLibrary.open('libidentity.so');
  if (Platform.isIOS) return DynamicLibrary.executable();
  throw UnsupportedError('This platform is not supported.');
}

/// <p class="para-brief"> Add new paperkey from the current account</p>
int client_add_paperkey(
  int port,
) {
  return _client_add_paperkey(port);
}
final _client_add_paperkey_Dart _client_add_paperkey = _dl.lookupFunction<_client_add_paperkey_C, _client_add_paperkey_Dart>('client_add_paperkey');
typedef _client_add_paperkey_C = Int32 Function(
  Int64 port,
);
typedef _client_add_paperkey_Dart = int Function(
  int port,
);

/// <p class="para-brief"> Check if the current client has a device key already or not</p>
int client_has_device_key(
  int port,
) {
  return _client_has_device_key(port);
}
final _client_has_device_key_Dart _client_has_device_key = _dl.lookupFunction<_client_has_device_key_C, _client_has_device_key_Dart>('client_has_device_key');
typedef _client_has_device_key_C = Int32 Function(
  Int64 port,
);
typedef _client_has_device_key_Dart = int Function(
  int port,
);

/// <p class="para-brief"> Get the a list that contains all the client identity data</p>
int client_identity(
  int port,
  Pointer<ffi.Utf8> uid,
) {
  return _client_identity(port, uid);
}
final _client_identity_Dart _client_identity = _dl.lookupFunction<_client_identity_C, _client_identity_Dart>('client_identity');
typedef _client_identity_C = Int32 Function(
  Int64 port,
  Pointer<ffi.Utf8> uid,
);
typedef _client_identity_Dart = int Function(
  int port,
  Pointer<ffi.Utf8> uid,
);

/// <p class="para-brief"> Setup the Sunshine identity client using the provided path as the base path</p><p> ### Safety This assumes that the path is non-null c string.</p>
int client_init(
  int port,
  Pointer<ffi.Utf8> path,
) {
  return _client_init(port, path);
}
final _client_init_Dart _client_init = _dl.lookupFunction<_client_init_C, _client_init_Dart>('client_init');
typedef _client_init_C = Int32 Function(
  Int64 port,
  Pointer<ffi.Utf8> path,
);
typedef _client_init_Dart = int Function(
  int port,
  Pointer<ffi.Utf8> path,
);

/// <p class="para-brief"> Set a new Key for this device if not already exist. you should call `client_has_device_key` first to see if you have already a key.</p><p> suri is used for testing only. phrase is used to restore a backup</p>
int client_key_set(
  int port,
  Pointer<ffi.Utf8> suri,
  Pointer<ffi.Utf8> password,
  Pointer<ffi.Utf8> phrase,
) {
  return _client_key_set(port, suri, password, phrase);
}
final _client_key_set_Dart _client_key_set = _dl.lookupFunction<_client_key_set_C, _client_key_set_Dart>('client_key_set');
typedef _client_key_set_C = Int32 Function(
  Int64 port,
  Pointer<ffi.Utf8> suri,
  Pointer<ffi.Utf8> password,
  Pointer<ffi.Utf8> phrase,
);
typedef _client_key_set_Dart = int Function(
  int port,
  Pointer<ffi.Utf8> suri,
  Pointer<ffi.Utf8> password,
  Pointer<ffi.Utf8> phrase,
);

/// <p class="para-brief"> Lock the client</p>
int client_lock(
  int port,
) {
  return _client_lock(port);
}
final _client_lock_Dart _client_lock = _dl.lookupFunction<_client_lock_C, _client_lock_Dart>('client_lock');
typedef _client_lock_C = Int32 Function(
  Int64 port,
);
typedef _client_lock_Dart = int Function(
  int port,
);

/// <p class="para-brief"> Prove the account identity for the provided service and there id</p><p> Current Avalibale Services Github = 1</p>
int client_prove_identity(
  int port,
  int service,
  Pointer<ffi.Utf8> id,
) {
  return _client_prove_identity(port, service, id);
}
final _client_prove_identity_Dart _client_prove_identity = _dl.lookupFunction<_client_prove_identity_C, _client_prove_identity_Dart>('client_prove_identity');
typedef _client_prove_identity_C = Int32 Function(
  Int64 port,
  Int32 service,
  Pointer<ffi.Utf8> id,
);
typedef _client_prove_identity_Dart = int Function(
  int port,
  int service,
  Pointer<ffi.Utf8> id,
);

/// <p class="para-brief"> Get the UID of identifier as String (if any)</p>
int client_resolve_uid(
  int port,
  Pointer<ffi.Utf8> identifier,
) {
  return _client_resolve_uid(port, identifier);
}
final _client_resolve_uid_Dart _client_resolve_uid = _dl.lookupFunction<_client_resolve_uid_C, _client_resolve_uid_Dart>('client_resolve_uid');
typedef _client_resolve_uid_C = Int32 Function(
  Int64 port,
  Pointer<ffi.Utf8> identifier,
);
typedef _client_resolve_uid_Dart = int Function(
  int port,
  Pointer<ffi.Utf8> identifier,
);

/// <p class="para-brief"> Get account id</p>
int client_signer_account_id(
  int port,
) {
  return _client_signer_account_id(port);
}
final _client_signer_account_id_Dart _client_signer_account_id = _dl.lookupFunction<_client_signer_account_id_C, _client_signer_account_id_Dart>('client_signer_account_id');
typedef _client_signer_account_id_C = Int32 Function(
  Int64 port,
);
typedef _client_signer_account_id_Dart = int Function(
  int port,
);

/// <p class="para-brief"> UnLock the client</p>
int client_unlock(
  int port,
  Pointer<ffi.Utf8> password,
) {
  return _client_unlock(port, password);
}
final _client_unlock_Dart _client_unlock = _dl.lookupFunction<_client_unlock_C, _client_unlock_Dart>('client_unlock');
typedef _client_unlock_C = Int32 Function(
  Int64 port,
  Pointer<ffi.Utf8> password,
);
typedef _client_unlock_Dart = int Function(
  int port,
  Pointer<ffi.Utf8> password,
);

/// C function `error_message_utf8`.
int error_message_utf8(
  Pointer<ffi.Utf8> buf,
  int length,
) {
  return _error_message_utf8(buf, length);
}
final _error_message_utf8_Dart _error_message_utf8 = _dl.lookupFunction<_error_message_utf8_C, _error_message_utf8_Dart>('error_message_utf8');
typedef _error_message_utf8_C = Int32 Function(
  Pointer<ffi.Utf8> buf,
  Int32 length,
);
typedef _error_message_utf8_Dart = int Function(
  Pointer<ffi.Utf8> buf,
  int length,
);

/// C function `last_error_length`.
int last_error_length() {
  return _last_error_length();
}
final _last_error_length_Dart _last_error_length = _dl.lookupFunction<_last_error_length_C, _last_error_length_Dart>('last_error_length');
typedef _last_error_length_C = Int32 Function();
typedef _last_error_length_Dart = int Function();

/// C function `store_dart_post_cobject`.
void store_dart_post_cobject(
  Pointer<NativeFunction<Int8 Function(Int64, Pointer<Dart_CObject>)>> ptr,
) {
  _store_dart_post_cobject(ptr);
}
final _store_dart_post_cobject_Dart _store_dart_post_cobject = _dl.lookupFunction<_store_dart_post_cobject_C, _store_dart_post_cobject_Dart>('store_dart_post_cobject');
typedef _store_dart_post_cobject_C = Void Function(
  Pointer<NativeFunction<Int8 Function(Int64, Pointer<Dart_CObject>)>> ptr,
);
typedef _store_dart_post_cobject_Dart = void Function(
  Pointer<NativeFunction<Int8 Function(Int64, Pointer<Dart_CObject>)>> ptr,
);
