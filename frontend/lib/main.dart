import 'dart:convert';
import 'dart:js_interop';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

void main() => runApp(const MyApp());

String get _apiBase => 'http://192.168.0.174:8000/api';

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
  String? _token;
  String _status = '';

  Future<void> _register() async {
    final username = _usernameCtrl.text.trim();
    if (username.isEmpty) return;
    setState(() => _status = 'Starting registration…');

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

  Future<void> _login() async {
    final username = _usernameCtrl.text.trim();
    if (username.isEmpty) return;
    setState(() => _status = 'Starting authentication…');

    final startRes = await http.post(
      Uri.parse('$_apiBase/v1/login/start'),
      headers: {'content-type': 'application/json'},
      body: jsonEncode({'username': username}),
    );
    if (startRes.statusCode != 200) {
      setState(() => _status = 'Start failed: ${startRes.body}');
      return;
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
      setState(() => _status = '❌ Failed: ${finishRes.body}');
    }
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
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        FilledButton.icon(
                          onPressed: _register,
                          icon: const Icon(Icons.fingerprint),
                          label: const Text('Register'),
                        ),
                        OutlinedButton.icon(
                          onPressed: _login,
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
      );
}
