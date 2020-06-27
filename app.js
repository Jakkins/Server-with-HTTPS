// curl -k https://localhost:8000/

import { createServer } from 'https'
import { readFileSync } from 'fs'

console.log('Ok')

const options = {
  key: readFileSync('./keys/server.key.pem'),
  cert: readFileSync('./keys/server.cert.pem')
}

console.log('Ok')

createServer(options, (req, res) => {
  res.writeHead(200)
  res.end('hello world\n')
}).listen(8000)