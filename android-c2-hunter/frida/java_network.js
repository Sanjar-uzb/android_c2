Java.perform(function() {
  var URL = Java.use('java.net.URL');
  URL.openConnection.overload('java.net.Proxy').implementation = function(proxy) {
    send({ type: 'java', action: 'openConnection', host: this.toString() });
    return this.openConnection(proxy);
  };
});
