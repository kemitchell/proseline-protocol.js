var sodium = require('sodium-universal')
var stringify = require('fast-json-stable-stringify')

module.exports = function (envelope) {
  return sodium.crypto_sign_verify_detached(
    Buffer.from(envelope.signature, 'hex'),
    Buffer.from(stringify(envelope.message)),
    Buffer.from(envelope.publicKey, 'hex')
  )
}
