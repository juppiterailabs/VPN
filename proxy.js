import net, { createServer } from 'net';
import tls from 'tls';
import { HTTPParser } from 'http-parser-js';

var CR = 0xd, LF = 0xa, BUF_CR = Buffer.from([0xd]), BUF_CR_LF_CR_LF = Buffer.from([0xd, 0xa, 0xd, 0xa]),
  BUF_LF_LF = Buffer.from([0xa, 0xa]), BUF_PROXY_CONNECTION_CLOSE = Buffer.from('Proxy-Connection: close');
var STATE_NONE = 0, STATE_FOUND_LF = 1, STATE_FOUND_LF_CR = 2;

function createPortForwarder(local_host, local_port, remote_host, remote_port, buf_proxy_basic_auth, is_remote_https, ignore_https_cert) {
  var localProxyServer = createServer({allowHalfOpen: true}, function (socket) {
    var realCon = (is_remote_https ? tls : net).connect({
      port: remote_port, host: remote_host, allowHalfOpen: true,
      rejectUnauthorized: !ignore_https_cert /*not used when is_remote_https false*/
    });
    realCon.on('data', (buf) => {
      // console.log('<<<<' + (Date.t=new Date()) + '.' + Date.t.getMilliseconds() + '\n' + buf.toString('ascii'));
      socket.write(buf);
      realCon.__haveGotData = true;
    }).on('end', () => {
      socket.end();
      if (!realCon.__haveGotData && !realCon.__haveShownError) {
        console.error('[LocalProxy(:' + local_port + ')][Connection to ' + remote_host + ':' + remote_port + '] Error: ended by remote peer');
        realCon.__haveShownError = true;
      }
    }).on('close', () => {
      socket.end();
      if (!realCon.__haveGotData && !realCon.__haveShownError) {
        console.error('[LocalProxy(:' + local_port + ')][Connection to ' + remote_host + ':' + remote_port + '] Error: reset by remote peer');
        realCon.__haveShownError = true;
      }
    }).on('error', (err) => {
      console.error('[LocalProxy(:' + local_port + ')][Connection to ' + remote_host + ':' + remote_port + '] ' + err);
      realCon.__haveShownError = true;
    });

    var parser = new HTTPParser(HTTPParser.REQUEST);
    parser[HTTPParser.kOnHeadersComplete] = function (versionMajor, versionMinor, headers, method,
                                                      url, statusCode, statusMessage, upgrade,
                                                      shouldKeepAlive) {
      parser.__is_headers_complete = true;
      parser.__upgrade = upgrade;
      parser.__method = method;
    };

    var state = STATE_NONE;

    socket.on('data', (buf) => {
      if (!parser) {
        realCon.write(buf);
        return
      }
      var buf_ary = [], unsavedStart = 0, buf_len = buf.length;

      for (var i = 0; i < buf_len; i++) {
        //find first LF
        if (state === STATE_NONE) {
          if (buf[i] === LF) {
            state = STATE_FOUND_LF;
          }
          continue;
        }

        //find second CR LF or LF
        if (buf[i] === LF) {
          parser.__is_headers_complete = false;
          parser.execute(buf.slice(unsavedStart, i + 1));

          if (parser.__is_headers_complete) {
            buf_ary.push(buf.slice(unsavedStart, buf[i - 1] === CR ? i - 1 : i));
            //console.log('insert auth header');
            buf_ary.push(buf_proxy_basic_auth);
            buf_ary.push(state === STATE_FOUND_LF_CR ? BUF_CR_LF_CR_LF : BUF_LF_LF);

            // stop intercepting packets if encountered TLS and WebSocket handshake
            if (parser.__method === 5 /*CONNECT*/ || parser.__upgrade) {
              parser.close();
              parser = null;

              buf_ary.push(buf.slice(i + 1));
              realCon.write(Buffer.concat(buf_ary));

              state = STATE_NONE;
              return;
            }

            unsavedStart = i + 1;
            state = STATE_NONE;
          }
          else {
            state = STATE_FOUND_LF;
          }
        }
        else if (buf[i] === CR && state === STATE_FOUND_LF) {
          state = STATE_FOUND_LF_CR;
        } else {
          state = STATE_NONE;
        }
      }

      if (unsavedStart < buf_len) {
        buf = buf.slice(unsavedStart, buf_len);
        parser.execute(buf);
        buf_ary.push(buf);
      }

      realCon.write(Buffer.concat(buf_ary));

    }).on('end', cleanup).on('close', cleanup).on('error', function (err) {
      if (!socket.__cleanup) {
        console.error('[LocalProxy(:' + local_port + ')][Incoming connection] ' + err);
      }
    });

    function cleanup() {
      socket.__cleanup = true;
      if (parser) {
        parser.close();
        parser = null;
      }
      realCon.end();
    }
  });

  localProxyServer.on('error', (err) => {
    console.error('[LocalProxy(:' + local_port + ')] ' + err);
    process.exit(1);
  }).on('connection', (socket) => {
    let {address} =  socket.address();
    localProxyServer.getConnections((err, count) => {
      console.log(err, count);
    })
    console.log(`User is connected with ${address}`)
  })
  .listen(local_port, local_host === '*' ? undefined : local_host, function () {
    console.log('[LocalProxy(:' + local_port + ')] OK: forward http://' + local_host + ':' + local_port + ' to ' + ' to http' + (is_remote_https ? 's' : '') + '://' + remote_host + ':' + remote_port);
  });

}

export default createPortForwarder;