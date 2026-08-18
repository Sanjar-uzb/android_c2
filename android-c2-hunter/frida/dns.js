function emit(kind, host, port, extra) {
  send({ type: 'dns', kind: kind, host: host, port: port || 0, extra: extra || {} });
}

Interceptor.attach(Module.findExportByName('libc.so', 'getaddrinfo'), {
  onEnter: function(args) {
    var host = Memory.readUtf8String(args[0]);
    if (host) emit('getaddrinfo', host, 0, {});
  }
});
