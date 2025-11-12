import 'dart:convert';
import 'dart:js_interop';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

void main() => runApp(const MyApp());

// Use relative path when accessed through Caddy (port 8080)
// Use direct backend URL when running Flutter dev server directly (port 5000)
String get _apiBase {
  final origin = Uri.base;
  // If accessing through Caddy on port 8080, use relative path
  if (origin.port == 8080) {
    return '/api';
  }
  // When running Flutter dev server directly, connect to backend on port 8000
  return 'http://${origin.host}:8000/api';
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) => MaterialApp(
        debugShowCheckedModeBanner: false,
        title: 'FIDO2 Demo',
        themeMode: ThemeMode.dark,
        darkTheme: ThemeData(
          useMaterial3: true,
          colorScheme: ColorScheme.fromSeed(
            seedColor: Colors.blueAccent,
            brightness: Brightness.dark,
          ),
          scaffoldBackgroundColor: const Color(0xFF121212),
          cardColor: const Color(0xFF1E1E1E),
          inputDecorationTheme: const InputDecorationTheme(
            filled: true,
            fillColor: Color(0xFF2A2A2A),
            border: OutlineInputBorder(),
          ),
        ),
        home: const Home(),
      );
}

@JS('webauthn.createFromJson')
external JSPromise<JSString> _webauthnCreateFromJson(JSString optionsJson);

@JS('webauthn.getFromJson')
external JSPromise<JSString> _webauthnGetFromJson(JSString optionsJson);

Future<Map<String, dynamic>> _webauthn(String kind, Map<String, dynamic> options) async {
  final optionsJson = jsonEncode(options).toJS;
  final jsPromise =
      kind == 'create' ? _webauthnCreateFromJson(optionsJson) : _webauthnGetFromJson(optionsJson);
  final jsStr = await jsPromise.toDart;
  final dartStr = jsStr.toDart;
  return jsonDecode(dartStr) as Map<String, dynamic>;
}

class Home extends StatefulWidget {
  const Home({super.key});
  @override
  State<Home> createState() => _HomeState();
}

class _HomeState extends State<Home> {
  final _usernameCtrl = TextEditingController();
  final _passwordCtrl = TextEditingController();
  final _passwordConfirmCtrl = TextEditingController();
  String? _token;
  String _status = '';
  String _authMethod = 'fido2'; // fido2, password, totp
  bool _isRegistering = false;
  bool _showPasswordFields = false;
  String? _totpSecret;
  String? _qrCodeData;
  List<String>? _backupCodes;
  final _totpCodeCtrl = TextEditingController();

  Future<void> _register() async {
    final username = _usernameCtrl.text.trim();
    if (username.isEmpty) return;
    
    setState(() {
      _status = 'Starting registration…';
      _isRegistering = true;
    });

    try {
      if (_authMethod == 'fido2') {
        await _registerFIDO2(username);
      } else if (_authMethod == 'password') {
        await _registerPassword(username);
      } else if (_authMethod == 'totp') {
        await _registerPassword(username); // TOTP requires password first
      }
    } finally {
      setState(() => _isRegistering = false);
    }
  }

  Future<void> _registerFIDO2(String username) async {
    final startRes = await http.post(
      Uri.parse('$_apiBase/v1/register/start'),
      headers: {'content-type': 'application/json'},
      body: jsonEncode({'username': username, 'displayName': username}),
    );
    if (startRes.statusCode != 200) {
      setState(() => _status = 'Start failed: ${startRes.body}');
      return;
    }

    final options = jsonDecode(startRes.body) as Map<String, dynamic>;
    final credential = await _webauthn('create', options);

    final finishRes = await http.post(
      Uri.parse('$_apiBase/v1/register/finish'),
      headers: {'content-type': 'application/json'},
      body: jsonEncode({'username': username, ...credential}),
    );

    setState(() => _status =
        finishRes.statusCode == 200 ? '✅ Registration successful!' : '❌ Failed: ${finishRes.body}');
  }

  Future<void> _registerPassword(String username) async {
    final password = _passwordCtrl.text;
    final passwordConfirm = _passwordConfirmCtrl.text;
    
    if (password.isEmpty) {
      setState(() => _status = '❌ Password required');
      return;
    }
    
    if (password != passwordConfirm) {
      setState(() => _status = '❌ Passwords do not match');
      return;
    }

    final res = await http.post(
      Uri.parse('$_apiBase/v1/password/register'),
      headers: {'content-type': 'application/json'},
      body: jsonEncode({
        'username': username,
        'password': password,
        'display_name': username,
      }),
    );

    if (res.statusCode == 200) {
      if (_authMethod == 'totp') {
        // Setup TOTP after password registration
        await _setupTOTP(username, password);
      } else {
        setState(() => _status = '✅ Registration successful!');
      }
    } else {
      final body = jsonDecode(res.body);
      setState(() => _status = '❌ Failed: ${body['detail'] ?? res.body}');
    }
  }

  Future<void> _setupTOTP(String username, String password) async {
    setState(() => _status = 'Setting up 2FA...');
    
    final res = await http.post(
      Uri.parse('$_apiBase/v1/totp/setup'),
      headers: {'content-type': 'application/json'},
      body: jsonEncode({
        'username': username,
        'password': password,
      }),
    );

    if (res.statusCode == 200) {
      final body = jsonDecode(res.body);
      setState(() {
        _totpSecret = body['secret'];
        _qrCodeData = body['qr_code'];
        _backupCodes = List<String>.from(body['backup_codes']);
        _status = '✅ Password registered! Scan QR code to enable 2FA';
      });
    } else {
      final body = jsonDecode(res.body);
      setState(() => _status = '❌ TOTP setup failed: ${body['detail'] ?? res.body}');
    }
  }

  Future<void> _verifyTOTP(String username) async {
    final code = _totpCodeCtrl.text.trim();
    if (code.isEmpty) {
      setState(() => _status = '❌ TOTP code required');
      return;
    }

    final res = await http.post(
      Uri.parse('$_apiBase/v1/totp/verify'),
      headers: {'content-type': 'application/json'},
      body: jsonEncode({
        'username': username,
        'totp_code': code,
      }),
    );

    if (res.statusCode == 200) {
      setState(() {
        _status = '✅ 2FA enabled successfully!';
        _totpSecret = null;
        _qrCodeData = null;
        _totpCodeCtrl.clear();
      });
    } else {
      final body = jsonDecode(res.body);
      setState(() => _status = '❌ Verification failed: ${body['detail'] ?? res.body}');
    }
  }

  Future<void> _login() async {
    final username = _usernameCtrl.text.trim();
    if (username.isEmpty) return;
    setState(() => _status = 'Starting authentication…');

    // If password is provided, try password/TOTP login
    // Otherwise, try FIDO2
    if (_passwordCtrl.text.isNotEmpty) {
      await _loginPassword(username);
    } else {
      // Try FIDO2 first, fall back to password if it fails
      try {
        await _loginFIDO2(username);
      } catch (e) {
        setState(() => _status = '⚠️ FIDO2 not available. Please enter password.');
      }
    }
  }

  Future<void> _loginFIDO2(String username) async {
    final startRes = await http.post(
      Uri.parse('$_apiBase/v1/login/start'),
      headers: {'content-type': 'application/json'},
      body: jsonEncode({'username': username}),
    );
    if (startRes.statusCode != 200) {
      throw Exception('FIDO2 not available');
    }

    final options = jsonDecode(startRes.body) as Map<String, dynamic>;
    final assertion = await _webauthn('get', options);

    final finishRes = await http.post(
      Uri.parse('$_apiBase/v1/login/finish'),
      headers: {'content-type': 'application/json'},
      body: jsonEncode({'username': username, ...assertion}),
    );

    if (finishRes.statusCode == 200) {
      final body = jsonDecode(finishRes.body);
      setState(() {
        _token = body['token'];
        _status = '✅ Login successful!';
      });
    } else {
      throw Exception(finishRes.body);
    }
  }

  Future<void> _loginPassword(String username) async {
    final password = _passwordCtrl.text;
    if (password.isEmpty) {
      setState(() => _status = '❌ Password required');
      return;
    }

    // First try password-only login
    final passwordRes = await http.post(
      Uri.parse('$_apiBase/v1/password/login'),
      headers: {'content-type': 'application/json'},
      body: jsonEncode({
        'username': username,
        'password': password,
      }),
    );

    if (passwordRes.statusCode == 200) {
      final body = jsonDecode(passwordRes.body);
      setState(() {
        _token = body['token'];
        _status = '✅ Login successful!';
      });
      return;
    }

    // If password login fails with specific error about TOTP, try TOTP login
    if (passwordRes.statusCode == 400) {
      final body = jsonDecode(passwordRes.body);
      if (body['detail']?.toString().contains('totp') ?? false) {
        // User has TOTP enabled, need TOTP code
        final totpCode = _totpCodeCtrl.text.trim();
        if (totpCode.isEmpty) {
          setState(() => _status = '⚠️ 2FA enabled. Please enter TOTP code.');
          return;
        }

        final totpRes = await http.post(
          Uri.parse('$_apiBase/v1/totp/login'),
          headers: {'content-type': 'application/json'},
          body: jsonEncode({
            'username': username,
            'password': password,
            'totp_code': totpCode,
          }),
        );

        if (totpRes.statusCode == 200) {
          final totpBody = jsonDecode(totpRes.body);
          setState(() {
            _token = totpBody['token'];
            _status = '✅ Login successful!';
          });
        } else {
          final totpBody = jsonDecode(totpRes.body);
          setState(() => _status = '❌ Failed: ${totpBody['detail'] ?? totpRes.body}');
        }
        return;
      }
    }

    // Password login failed
    final body = jsonDecode(passwordRes.body);
    setState(() => _status = '❌ Failed: ${body['detail'] ?? passwordRes.body}');
  }

  @override
  Widget build(BuildContext context) => Scaffold(
        appBar: AppBar(
          title: const Text('🔐 FIDO2 Passkey Demo'),
          centerTitle: true,
          backgroundColor: Colors.transparent,
          elevation: 0,
        ),
        body: Center(
          child: Card(
            margin: const EdgeInsets.all(24),
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(24)),
            elevation: 3,
            child: Padding(
              padding: const EdgeInsets.all(24),
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 400),
                child: SingleChildScrollView(
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Text(
                      'Welcome',
                      style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold),
                    ),
                    const SizedBox(height: 8),
                    Text(
                      'Sign in or register securely using your passkey.',
                      style: TextStyle(
                        color: Colors.grey.shade400,
                        fontSize: 14,
                      ),
                      textAlign: TextAlign.center,
                    ),
                    const SizedBox(height: 24),
                    TextField(
                      controller: _usernameCtrl,
                      decoration: const InputDecoration(
                        labelText: 'Username',
                        prefixIcon: Icon(Icons.person_outline),
                      ),
                    ),
                    const SizedBox(height: 24),
                    // Authentication method selection (only for registration)
                    if (!_showPasswordFields) ...[
                      const Text(
                        'Choose authentication method:',
                        style: TextStyle(fontWeight: FontWeight.bold),
                      ),
                      const SizedBox(height: 12),
                      RadioListTile<String>(
                        title: const Text('FIDO2 / Passkey'),
                        subtitle: const Text('Most secure, passwordless'),
                        value: 'fido2',
                        groupValue: _authMethod,
                        onChanged: (value) {
                          setState(() {
                            _authMethod = value!;
                          });
                        },
                      ),
                      RadioListTile<String>(
                        title: const Text('Password Only'),
                        subtitle: const Text('Traditional password'),
                        value: 'password',
                        groupValue: _authMethod,
                        onChanged: (value) {
                          setState(() {
                            _authMethod = value!;
                          });
                        },
                      ),
                      RadioListTile<String>(
                        title: const Text('Password + 2FA (TOTP)'),
                        subtitle: const Text('Password with authenticator app'),
                        value: 'totp',
                        groupValue: _authMethod,
                        onChanged: (value) {
                          setState(() {
                            _authMethod = value!;
                          });
                        },
                      ),
                      const SizedBox(height: 24),
                      // Show password fields when password or totp is selected (during registration)
                      if (_authMethod == 'password' || _authMethod == 'totp') ...[
                        TextField(
                          controller: _passwordCtrl,
                          decoration: const InputDecoration(
                            labelText: 'Password',
                            prefixIcon: Icon(Icons.lock_outline),
                          ),
                          obscureText: true,
                        ),
                        const SizedBox(height: 16),
                        TextField(
                          controller: _passwordConfirmCtrl,
                          decoration: const InputDecoration(
                            labelText: 'Confirm Password',
                            prefixIcon: Icon(Icons.lock_outline),
                          ),
                          obscureText: true,
                        ),
                        const SizedBox(height: 24),
                      ],
                    ],
                    // Password fields for login (when _showPasswordFields is true)
                    if (_showPasswordFields) ...[
                      TextField(
                        controller: _passwordCtrl,
                        decoration: const InputDecoration(
                          labelText: 'Password',
                          prefixIcon: Icon(Icons.lock_outline),
                        ),
                        obscureText: true,
                      ),
                      const SizedBox(height: 16),
                      // TOTP code field (for login with 2FA)
                      if (_authMethod == 'totp')
                        TextField(
                          controller: _totpCodeCtrl,
                          decoration: const InputDecoration(
                            labelText: 'TOTP Code (6 digits, if 2FA enabled)',
                            prefixIcon: Icon(Icons.security),
                            hintText: '000000',
                          ),
                          keyboardType: TextInputType.number,
                          maxLength: 6,
                        ),
                      const SizedBox(height: 24),
                    ],
                    // TOTP verification field (shown when QR code is displayed)
                    if (_qrCodeData != null) ...[
                      TextField(
                        controller: _totpCodeCtrl,
                        decoration: const InputDecoration(
                          labelText: 'TOTP Code (6 digits)',
                          prefixIcon: Icon(Icons.security),
                          hintText: '000000',
                        ),
                        keyboardType: TextInputType.number,
                        maxLength: 6,
                      ),
                      const SizedBox(height: 24),
                    ],
                    // QR Code display for TOTP setup
                    if (_qrCodeData != null) ...[
                      const Text(
                        'Scan this QR code with your authenticator app:',
                        style: TextStyle(fontWeight: FontWeight.bold),
                      ),
                      const SizedBox(height: 12),
                      Image.memory(
                        base64Decode(_qrCodeData!.split(',')[1]),
                        width: 200,
                        height: 200,
                      ),
                      const SizedBox(height: 12),
                      if (_totpSecret != null)
                        Text(
                          'Or enter this secret manually: $_totpSecret',
                          style: const TextStyle(fontSize: 12, fontFamily: 'monospace'),
                        ),
                      const SizedBox(height: 12),
                      if (_backupCodes != null) ...[
                        const Text(
                          'Backup codes (save these!):',
                          style: TextStyle(fontWeight: FontWeight.bold),
                        ),
                        const SizedBox(height: 8),
                        ...(_backupCodes!.map((code) => Text(
                              code,
                              style: const TextStyle(fontFamily: 'monospace'),
                            ))),
                        const SizedBox(height: 12),
                      ],
                      FilledButton.icon(
                        onPressed: () => _verifyTOTP(_usernameCtrl.text.trim()),
                        icon: const Icon(Icons.verified),
                        label: const Text('Verify & Enable 2FA'),
                      ),
                      const SizedBox(height: 24),
                    ],
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        FilledButton.icon(
                          onPressed: _isRegistering ? null : _register,
                          icon: const Icon(Icons.fingerprint),
                          label: const Text('Register'),
                        ),
                        OutlinedButton.icon(
                          onPressed: () {
                            if (!_showPasswordFields) {
                              setState(() => _showPasswordFields = true);
                            } else {
                              _login();
                            }
                          },
                          icon: const Icon(Icons.login),
                          label: const Text('Login'),
                        ),
                      ],
                    ),
                    const SizedBox(height: 24),
                    if (_token != null)
                      Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const Text('JWT Token:',
                              style: TextStyle(fontWeight: FontWeight.bold)),
                          SelectableText(
                            _token!,
                            style: const TextStyle(fontSize: 12, color: Colors.greenAccent),
                          ),
                          const SizedBox(height: 12),
                        ],
                      ),
                    Text(
                      _status,
                      style: const TextStyle(color: Colors.lightBlueAccent),
                    ),
                  ],
                ),
                ),
              ),
            ),
          ),
        ),
      );
}
