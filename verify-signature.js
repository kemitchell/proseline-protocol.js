var sodium = require('sodium-universal')
var stringify = require('fast-json-stable-stringify')

// Verify the signature to a message with `publicKey` and `signature`
// properties and a JSON-serializable `message` body.
module.exports = function (envelope) {
  return sodium.crypto_sign_verify_detached(
    Buffer.from(envelope.signature, 'hex'),
    Buffer.from(stringify(envelope.message)),
    Buffer.from(envelope.publicKey, 'hex')
  )
}
