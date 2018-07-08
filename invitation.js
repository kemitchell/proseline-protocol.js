var AJV = require('ajv')
var Duplexify = require('duplexify')
var assert = require('assert')
var debug = require('debug')('proseline:protocol:invitation')
var inherits = require('util').inherits
var lengthPrefixedStream = require('length-prefixed-stream')
var through2 = require('through2')
var verifySignature = require('./verify-signature')

// Stream implementation of Proseline's protocol for exchanging
// project invitations.
module.exports = InvitationProtocol

var ajv = new AJV()

var PROTOCOL_VERSION = 1

var validHandshake = ajv.compile(strictSchema({
  type: 'object',
  properties: {
    version: {type: 'number', multipleOf: 1, minimum: 1}
  }
}))

// An invitation is a signed copy of the secret key for a project.
var validInvitationData = ajv.compile(strictSchema({
  type: 'object',
  properties: {
    message: strictSchema({
      type: 'object',
      properties: {
        secretKey: {type: 'string', pattern: '^[a-f0-9]{64}$'}
      }
    }),
    publicKey: {type: 'string', pattern: '^[a-f0-9]{64}$'},
    signature: {type: 'string', pattern: '^[a-f0-9]{128}$'}
  }
}))

// Helper function for building JSON schemas for objects that must
// contain exactly the specified properties.
function strictSchema (schema) {
  schema.required = Object.keys(schema.properties)
  schema.additionalProperties = false
  return schema
}

var validInvitation = function (envelope) {
  return validInvitationData(envelope) && verifySignature(envelope)
}

// Message Type Prefixes
var HANDSHAKE = 0
var INVITATION = 1

// Messages are sent as JSON-encoded [prefix, body] tuples.
var validMessage = ajv.compile({
  type: 'array',
  items: [
    {enum: [HANDSHAKE, INVITATION]},
    {type: 'object'}
  ],
  additionalItems: false
})

function InvitationProtocol () {
  if (!(this instanceof InvitationProtocol)) {
    return new InvitationProtocol()
  }

  var self = this

  // Readable: messages to our peer
  self._sentHandshake = false
  self._encoder = lengthPrefixedStream.encode()
    .once('error', function (error) {
      self.destroy(error)
    })

  // Writable: messages from our peer
  self._receivedHandshake = false
  self._decoder = lengthPrefixedStream.decode()
  self._parser = through2.obj(function (chunk, _, done) {
    self._parse(chunk, function (error) {
      if (error) return done(error)
      done()
    })
  })
  self._decoder
    .pipe(self._parser)
    .once('error', function (error) {
      self.destroy(error)
    })

  Duplexify.call(self, self._decoder, self._encoder)
}

inherits(InvitationProtocol, Duplexify)

InvitationProtocol.prototype.handshake = function (callback) {
  var self = this
  if (self._sentHandshake) return callback()
  debug('sending handshake')
  self._encode(HANDSHAKE, {version: PROTOCOL_VERSION}, function (error) {
    if (error) return callback(error)
    self._sentHandshake = true
    callback()
  })
}

InvitationProtocol.prototype.invitation = function (invitation, callback) {
  try {
    assert(validInvitation(invitation))
  } catch (error) {
    return callback(error)
  }
  debug('sending invitation: %o', invitation)
  this._encode(INVITATION, invitation, callback)
}

InvitationProtocol.prototype.finalize = function (callback) {
  assert(typeof callback === 'function')
  var self = this
  self._finalize(function (error) {
    if (error) return self.destroy(error)
    self._encoder.end(callback)
  })
}

InvitationProtocol.prototype._encode = function (prefix, data, callback) {
  var buffer = Buffer.from(JSON.stringify([prefix, data]), 'utf8')
  this._encoder.write(buffer, callback)
}

InvitationProtocol.prototype._parse = function (message, callback) {
  try {
    var parsed = JSON.parse(message)
  } catch (error) {
    return callback(error)
  }
  if (!validMessage(parsed)) {
    debug('invalid message')
    return callback(new Error('invalid message'))
  }
  var prefix = parsed[0]
  var body = parsed[1]
  if (prefix === HANDSHAKE && validHandshake(body)) {
    if (body.version !== PROTOCOL_VERSION) {
      debug('incompatible version: ' + body.version)
      return callback(new Error('incompatible version'))
    }
    this._receivedHandshake = true
  } else if (!this._receivedHandshake) {
    message = 'message before handshake'
    debug(message)
    return callback(new Error(message))
  }
  if (prefix === INVITATION && validInvitation(body)) {
    this.emit('invitation', body, callback) || callback()
  } else {
    debug('invalid message')
    callback()
  }
}
