var JSONProtocol = require('json-protocol')
var common = require('./common')
var strictObjectSchema = require('strict-json-object-schema')

var request = strictObjectSchema({
  message: strictObjectSchema({
    email: {type: 'string', format: 'email'},
    date: {type: 'string', format: 'date-time'}
  }),
  publicKey: common.publicKey,
  signature: common.signature
})

var invitation = strictObjectSchema({
  message: {
    type: 'object',
    properties: {
      replicationKey: common.hexString(32),
      writeSeed: common.hexString(32),
      title: {type: 'string', minLength: 1}
    },
    required: ['replicationKey'],
    additionalProperties: false
  },
  publicKey: common.publicKey,
  signature: common.signature
})

module.exports = JSONProtocol({
  version: 2,
  sign: false,
  encrypt: false,
  messages: {
    invitation: {schema: invitation},
    request: {schema: request}
  }
})
