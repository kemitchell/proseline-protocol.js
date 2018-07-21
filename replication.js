var JSONProtocol = require('json-protocol')
var sodium = require('sodium-universal')
var strictObjectSchema = require('strict-json-object-schema')
var stringify = require('fast-json-stable-stringify')

var GENERICHASH_BYTES = sodium.crypto_generichash_BYTES
var SIGN_BYTES = sodium.crypto_sign_BYTES
var SIGN_PUBLICKEYBYTES = sodium.crypto_sign_PUBLICKEYBYTES

// JSON Schemas reused below:

var project = hexString(GENERICHASH_BYTES)
var publicKey = hexString(SIGN_PUBLICKEYBYTES)
var signature = hexString(SIGN_BYTES)
var digest = hexString(GENERICHASH_BYTES)
var timestamp = {type: 'string', format: 'date-time'}
var name = {type: 'string', minLength: 1, maxLength: 256}
var noteText = {type: 'string', minLength: 1}

// Schemas represent byte strings as hex strings.
function hexString (bytes) {
  return {
    type: 'string',
    pattern: '^[a-f0-9]{' + (bytes * 2) + '}$'
  }
}

// Log Entry Types

// Drafts store the contents of a written draft.
var draft = strictObjectSchema({
  type: {const: 'draft'},
  // A draft can be based on up to two parents:
  // other drafts on which the new draft was based.
  parents: {
    type: 'array',
    // Drafts reference parents by their digests.
    items: digest,
    maxItems: 2,
    uniqueItems: true
  },
  text: {type: 'object'},
  timestamp: timestamp
})

// Marks record when a user moves a named marker onto a
// specific draft.
var mark = strictObjectSchema({
  type: {const: 'mark'},
  // Each identifier has a unique identifier. User may
  // change the names of identifiers over time.
  identifier: hexString(4),
  name: {
    type: 'string',
    minLength: 1,
    maxLength: 256
  },
  timestamp: timestamp,
  // Marks reference drafts by their digests.
  draft: digest
})

// Notes store comments to drafts, as well as replies to
// other notes.  This schema represents a note to a draft.
var note = strictObjectSchema({
  type: {const: 'note'},
  // Notes reference drafts by their digests.
  draft: digest,
  // The cursor position of the range of the draft to which
  // the note pertains.
  range: strictObjectSchema({
    start: {type: 'integer', minimum: 0},
    end: {type: 'integer', minimum: 1}
  }),
  text: noteText,
  timestamp: timestamp
})

var reply = strictObjectSchema({
  type: {const: 'note'},
  draft: digest,
  // Unlike notes to draft, reply notes reference their
  // parent notes by digest, and do not specify ranges with
  // the draft.
  parent: digest,
  text: noteText,
  timestamp: timestamp
})

// Notes associates names and device, like "Kyle on laptop"
// with logs.
var intro = strictObjectSchema({
  type: {const: 'intro'},
  name: name,
  device: name,
  timestamp: timestamp
})

// A log entry body can be one of the types above.
var body = {oneOf: [draft, mark, intro, note, reply]}

// The first entry in a log does not reference any
// prior entry.
var firstEntry = strictObjectSchema({
  project: project,
  index: {const: 0},
  body: body
})

// Log entries after the first reference immediately prior
// log entries by their digests.
var laterEntry = strictObjectSchema({
  project: project,
  index: {type: 'integer', minimum: 1},
  prior: hexString(GENERICHASH_BYTES),
  body: body
})

// Envelopes wrap log entry messages with signatures.
var envelope = strictObjectSchema({
  message: {oneOf: [firstEntry, laterEntry]},
  // The public key of the log.
  publicKey: publicKey,
  // Signature with the secret key of the log.
  signature: signature,
  // Signature with the secret key of the project.
  authorization: signature
})

// References

// References point to particular log entries by log public
// key and integer index. Peers exchange references to offer
// and request log entries.
var reference = strictObjectSchema({
  publicKey: publicKey,
  index: {type: 'integer', minimum: 0}
})

module.exports = JSONProtocol({
  version: 2,
  sign: false,
  requiredSigningKeys: true,
  encrypt: true,
  messages: {
    // Offer messages indicate that a peer can send a
    // particular log entry for replication.
    offer: {schema: reference},

    // Request messages ask peers to send particular
    // log entries that they have offered.
    request: {schema: reference},

    // Peers send envelope messages in response to requests.
    envelope: {
      schema: envelope,
      verify: function (envelope) {
        var stream = this
        var messageBuffer = Buffer.from(stringify(envelope.message))
        var validSignature = sodium.crypto_sign_verify_detached(
          Buffer.from(envelope.signature, 'hex'),
          messageBuffer,
          Buffer.from(envelope.publicKey, 'hex')
        )
        if (!validSignature) return false
        var validAuthorization = sodium.crypto_sign_verify_detached(
          Buffer.from(envelope.authorization, 'hex'),
          messageBuffer,
          stream.publicKey
        )
        if (!validAuthorization) return false
        return true
      }
    }
  }
})
