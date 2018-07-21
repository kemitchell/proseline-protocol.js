var encryptedJSONProtocol = require('encrypted-json-protocol')
var sodium = require('sodium-universal')
var strictObjectSchema = require('strict-json-object-schema')
var verifySignature = require('./verify-signature')

var GENERICHASH_BYTES = sodium.crypto_generichash_BYTES
var SIGN_BYTES = sodium.crypto_sign_BYTES
var SIGN_PUBLICKEYBYTES = sodium.crypto_sign_PUBLICKEYBYTES

var project = hexString(GENERICHASH_BYTES)
var publicKey = hexString(SIGN_PUBLICKEYBYTES)
var signature = hexString(SIGN_BYTES)

var body = {
  title: 'log entry payload',
  type: 'object'
}

var logEntrySchema = strictObjectSchema({
  publicKey: publicKey,
  index: {type: 'integer', minimum: 0}
})

var firstEntry = strictObjectSchema({
  project: project,
  index: {const: 0},
  body: body
})

var laterEntry = strictObjectSchema({
  project: project,
  index: {type: 'integer', minimum: 1},
  prior: hexString(GENERICHASH_BYTES),
  body: body
})

var envelopeSchema = strictObjectSchema({
  message: {oneOf: [firstEntry, laterEntry]},
  publicKey: publicKey,
  signature: signature,
  authorization: signature
})

function hexString (bytes) {
  return {
    type: 'string',
    pattern: '^[a-f0-9]{' + (bytes * 2) + '}$'
  }
}

module.exports = encryptedJSONProtocol({
  version: 2,
  messages: {
    offer: {schema: logEntrySchema},
    request: {schema: logEntrySchema},
    envelope: {
      schema: envelopeSchema,
      verify: verifySignature
    }
  }
})
