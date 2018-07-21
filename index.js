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

var project = {
  title: 'project discovery key',
  type: 'string',
  pattern: '^[a-f0-9]{64}$'
}

var body = {
  title: 'log entry payload',
  type: 'object'
}

var firstEntry = strictObjectSchema({
  project: project,
  index: {
    type: 'number',
    const: 0
  },
  body: body
})

var laterEntry = strictObjectSchema({
  project: project,
  index: {
    title: 'log entry index',
    type: 'integer',
    minimum: 0
  },
  prior: {
    title: 'digest of prior entry',
    comment: 'optional',
    type: 'string',
    pattern: '^[a-f0-9]{64}$'
  },
  body: body
})

var envelopeSchema = strictObjectSchema({
  message: {oneOf: [firstEntry, laterEntry]},
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
