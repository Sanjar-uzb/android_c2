function emit(kind, host, port) {
  send({ type: 'tls', kind: kind, host: host || 'ssl://', port: port || 443 });
}

var ssl_connect = Module.findExportByName('libssl.so', 'SSL_connect');
if (ssl_connect) {
  Interceptor.attach(ssl_connect, {
    onEnter: function() { emit('SSL_connect', 'ssl://', 443); }
  });
}
