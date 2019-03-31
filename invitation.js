var JSONProtocol = require('json-protocol')
var common = require('./common')
var strictObjectSchema = require('strict-json-object-schema')

var request = strictObjectSchema({
  message: strictObjectSchema({
    email: { type: 'string', format: 'email' },
    date: { type: 'string', format: 'date-time' }
  }),
  publicKey: common.publicKey,
  signature: common.signature
})

var invitation = strictObjectSchema({
  message: {
    type: 'object',
    properties: {
      replicationKeyCiphertext: common.hexString(96),
      replicationKeyNonce: common.hexString(48),
      writeSeedCiphertext: common.hexString(96),
      writeSeedNonce: common.hexString(48),
      titleCiphertext: common.hexString(),
      titleNonce: common.hexString(48)
    },
    required: [
      'replicationKeyCiphertext',
      'replicationKeyNonce'
    ],
    additionalProperties: false
  },
  publicKey: common.publicKey,
  signature: common.signature
})

module.exports = JSONProtocol({
  version: 3,
  sign: false,
  encrypt: false,
  messages: {
    invitation: { schema: invitation },
    request: { schema: request }
  }
})
