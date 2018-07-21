var encryptedJSONProtocol = require('encrypted-json-protocol')
var verifySignature = require('./verify-signature')
var strictObjectSchema = require('strict-json-object-schema')

var logEntrySchema = strictObjectSchema({
  publicKey: {
    type: 'string',
    pattern: '^[a-f0-9]{64}$'
  },
  index: {
    type: 'number',
    multipleOf: 1,
    minimum: 0
  }
})

var envelopeSchema = strictObjectSchema({
  message: {
    type: 'object',
    properties: {
      project: {
        title: 'project discovery key',
        type: 'string',
        pattern: '^[a-f0-9]{64}$'
      },
      index: {
        title: 'log entry index',
        type: 'integer',
        minimum: 0
      },
      body: {
        title: 'log entry payload',
        type: 'object'
      }
    },
    required: ['project', 'index', 'body'],
    additionalProperties: false
  },
  publicKey: {
    type: 'string',
    pattern: '^[a-f0-9]{64}$'
  },
  signature: {
    type: 'string',
    pattern: '^[a-f0-9]{128}$'
  },
  authorization: {
    type: 'string',
    pattern: '^[a-f0-9]{128}$'
  }
})

module.exports = {
  Replication: encryptedJSONProtocol({
    version: 2,
    messages: {
      offer: {schema: logEntrySchema},
      request: {schema: logEntrySchema},
      envelope: {
        schema: envelopeSchema,
        verify: verifySignature
      }
    }
  }),
  Invitation: require('./invitation')
}
