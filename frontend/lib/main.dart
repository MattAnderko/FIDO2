import 'dart:convert';
import 'dart:js' as js;
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

void main() {
  runApp(const MyApp());
}

String get _apiBase => '${Uri.base.origin}/api';

class MyApp extends StatelessWidget {
  const MyApp({super.key});
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'FIDO2 Demo',
      theme: ThemeData(useMaterial3: true, colorSchemeSeed: Colors.blue),
      home: const Home(),
    );
  }
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

    final options = jsonDecode(startRes.body);
    // call JS helper
    final credential = await js.context.callMethod('webauthnCreate', [js.JsObject.jsify(options)]);

    final finishPayload = {
      'username': username,
      'id': credential['id'],
      'rawId': credential['rawId'],
      'response': credential['response'],
      'type': credential['type'],
      'transports': credential['transports'] ?? [],
    };

    final finishRes = await http.post(
      Uri.parse('$_apiBase/v1/register/finish'),
      headers: {'content-type': 'application/json'},
      body: jsonEncode(finishPayload),
    );

    setState(() => _status = finishRes.statusCode == 200 ? 'Registration OK' : 'Finish failed: ${finishRes.body}');
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

    final options = jsonDecode(startRes.body);
    final assertion = await js.context.callMethod('webauthnGet', [js.JsObject.jsify(options)]);

    final finishPayload = {
      'username': username,
      'id': assertion['id'],
      'rawId': assertion['rawId'],
      'response': assertion['response'],
      'type': assertion['type'],
    };

    final finishRes = await http.post(
      Uri.parse('$_apiBase/v1/login/finish'),
      headers: {'content-type': 'application/json'},
      body: jsonEncode(finishPayload),
    );

    if (finishRes.statusCode == 200) {
      final body = jsonDecode(finishRes.body);
      setState(() {
        _token = body['token'];
        _status = 'Login OK';
      });
    } else {
      setState(() => _status = 'Finish failed: ${finishRes.body}');
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('FIDO2 Demo (Flutter PWA)')),
      body: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('Username'),
            TextField(controller: _usernameCtrl),
            const SizedBox(height: 16),
            Wrap(spacing: 12, children: [
              ElevatedButton(onPressed: _register, child: const Text('Register (passkey)')),
              ElevatedButton(onPressed: _login, child: const Text('Login')),
            ]),
            const SizedBox(height: 16),
            if (_token != null) SelectableText('JWT: $_token'),
            const SizedBox(height: 8),
            Text(_status),
          ],
        ),
      ),
    );
  }
}
