var encryptedJSONProtocol = require('encrypted-json-protocol')
var strictObjectSchema = require('strict-json-object-schema')
var verifySignature = require('./verify-signature')

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
  message: strictObjectSchema({
    authorization: {
      title: 'signature with project write key',
      pattern: '^[a-f0-9]{128}$'
    },
    entry: {
      type: 'object',
      properties: {
        project: {
          title: 'project discovery key',
          type: 'string',
          pattern: '^[a-f0-9]{64}$'
        },
        publicKey: {
          title: 'log public key',
          type: 'string',
          pattern: '^[a-f0-9]{64}$'
        },
        index: {
          title: 'log entry index',
          type: 'integer',
          minimum: 0,
          multipleOf: 1
        },
        hash: {
          title: 'SHA256 hash of the unencrypted payload',
          type: 'string',
          pattern: '^[a-f0-9]{64}$'
        },
        prior: {
          title: 'SHA256 hash of the prior message payload',
          comment: 'not required',
          type: 'string',
          pattern: '^[a-f0-9]{64}$'
        },
        encrypted: {
          title: 'log entry payload',
          type: 'string',
          contentEncoding: 'base64',
          pattern: '^(?:[A-Za-z0-9+\\/]{4})*(?:[A-Za-z0-9+\\/]{2}==|[A-Za-z0-9+\\/]{3}=)$'
        },
        signature: {
          title: 'signature with log secret key',
          pattern: '^[a-f0-9]{128}$'
        }
      },
      required: [
        'project',
        'publicKey',
        'index',
        'hash',
        // missing: prior
        'encrypted',
        'signature'
      ],
      additionalProperties: false
    }
  })
})

module.exports = {
  Replication: encryptedJSONProtocol({
    version: 1,
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
