import proxy from "./proxy.js";

const usr = 'hoxkwrlp'
const pwd = '65or7blu5bem'
const remote_host = '209.40.115.233'
const remote_port = '6012'
const buf_proxy_basic_auth = Buffer.from('Proxy-Authorization: Basic ' + Buffer.from(usr + ':' + pwd).toString('base64'));

console.log("starting proxy server")
proxy('localhost', 6677, remote_host, remote_port, buf_proxy_basic_auth, true, false)