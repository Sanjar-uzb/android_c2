function emit(kind, host, port) {
  send({ type: 'native', kind: kind, host: host || 'unknown', port: port || 0 });
}

Interceptor.attach(Module.findExportByName('libc.so', 'connect'), {
  onEnter: function(args) {
    var addr = args[1];
    if (!addr || addr.isNull()) return;
    var family = Memory.readU16(addr);
    if (family === 2) {
      var port = Memory.readU16(addr.add(2));
      var bytes = [];
      for (var i = 0; i < 4; i++) bytes.push(Memory.readU8(addr.add(4 + i)));
      emit('connect', bytes.join('.'), port);
    }
  }
});
