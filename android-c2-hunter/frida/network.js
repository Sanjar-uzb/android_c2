function emit(kind, host, port, extra) {
  send({ type: 'network', kind: kind, host: host, port: port || 0, extra: extra || {} });
}

Interceptor.attach(Module.findExportByName('libc.so', 'connect'), {
  onEnter: function(args) {
    var addr = args[1];
    var family = Memory.readU16(addr);
    if (family === 2) {
      var port = Memory.readU16(addr.add(2));
      var bytes = [];
      for (var i = 0; i < 4; i++) bytes.push(Memory.readU8(addr.add(4 + i)));
      emit('connect', bytes.join('.'), port, {});
    }
  }
});
