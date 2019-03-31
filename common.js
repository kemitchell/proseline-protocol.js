var sodium = require('sodium-universal')

var SIGN_BYTES = sodium.crypto_sign_BYTES
var SIGN_PUBLICKEYBYTES = sodium.crypto_sign_PUBLICKEYBYTES

exports.hexString = hexString

exports.publicKey = hexString(SIGN_PUBLICKEYBYTES)

exports.signature = hexString(SIGN_BYTES)

// Schemas represent byte strings as hex strings.
function hexString (bytes) {
  return {
    type: 'string',
    pattern: '^[a-f0-9]{' + bytes * 2 + '}$'
  }
}
