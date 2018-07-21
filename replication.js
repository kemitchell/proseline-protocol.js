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
var digest = hexString(GENERICHASH_BYTES)
var timestamp = {type: 'string', format: 'date-time'}
var name = {type: 'string', minLength: 1, maxLength: 256}

var draft = strictObjectSchema({
  type: {const: 'draft'},
  parents: {
    type: 'array',
    items: digest,
    maxItems: 2,
    uniqueItems: true
  },
  text: {type: 'string'},
  timestamp: timestamp
})

var mark = strictObjectSchema({
  type: {const: 'mark'},
  identifier: hexString(4),
  name: {
    type: 'string',
    minLength: 1,
    maxLength: 256
  },
  timestamp: timestamp,
  draft: digest
})

var note = strictObjectSchema({
  type: {const: 'note'},
  draft: digest,
  range: strictObjectSchema({
    start: {type: 'integer', minimum: 0},
    end: {type: 'integer', minimum: 1}
  }),
  text: {type: 'string', minLength: 1},
  timestamp: timestamp
})

var reply = strictObjectSchema({
  type: {const: 'note'},
  draft: digest,
  parent: digest,
  text: {type: 'string', minLength: 1},
  timestamp: timestamp
})

var intro = strictObjectSchema({
  type: {const: 'intro'},
  name: name,
  device: name,
  timestamp: timestamp
})

var body = {oneOf: [draft, mark, intro, note, reply]}

var entry = strictObjectSchema({
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

var envelope = strictObjectSchema({
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
    offer: {schema: entry},
    request: {schema: entry},
    envelope: {
      schema: envelope,
      verify: verifySignature
    }
  }
})
