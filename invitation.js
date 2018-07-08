var AJV = require('ajv')
var Duplexify = require('duplexify')
var assert = require('assert')
var debug = require('debug')('proseline:protocol')
var inherits = require('util').inherits
var lengthPrefixedStream = require('length-prefixed-stream')
var through2 = require('through2')
var verifySignature = require('./verify-signature')

module.exports = InvitationProtocol

var ajv = new AJV()

var validHandshake = ajv.compile({
  type: 'object',
  properties: {
    version: {type: 'number', multipleOf: 1, minimum: 1}
  },
  required: ['version'],
  additionalProperties: false
})

var validInvitationData = ajv.compile({
  type: 'object',
  properties: {
    message: {
      type: 'object',
      properties: {
        secretKey: {type: 'string', pattern: '^[a-f0-9]{64}$'}
      },
      required: ['secretKey'],
      additionalProperties: false
    },
    publicKey: {type: 'string', pattern: '^[a-f0-9]{64}$'},
    signature: {type: 'string', pattern: '^[a-f0-9]{128}$'}
  },
  required: ['secretKey', 'mineOnly', 'publicKey', 'signature'],
  additionalProperties: false
})

var validInvitation = function (envelope) {
  return validInvitationData(envelope) && verifySignature(envelope)
}

var HANDSHAKE = 0
var INVITATION = 1

var validMessage = ajv.compile({
  type: 'array',
  items: [
    {enum: [HANDSHAKE, INVITATION]},
    {type: 'object'}
  ],
  additionalItems: false
})

var VERSION = 1

function InvitationProtocol () {
  if (!(this instanceof InvitationProtocol)) {
    return new InvitationProtocol()
  }

  var self = this

  // Readable: messages to our peer
  self._sentHandshake = false
  self._writable = lengthPrefixedStream.encode()
    .once('error', function (error) {
      self.destroy(error)
    })

  // Writable: messages from our peer
  self._writable = lengthPrefixedStream.decode()
  self._parser = through2.obj(function (chunk, _, done) {
    self._parse(chunk, function (error) {
      if (error) return done(error)
      done()
    })
  })
  self._writable
    .pipe(self._parser)
    .once('error', function (error) {
      self.destroy(error)
    })

  Duplexify.call(self, self._writable, self._writable)
}

inherits(InvitationProtocol, Duplexify)

InvitationProtocol.prototype.handshake = function (callback) {
  var self = this
  if (self._sentHandshake) return callback()
  debug('sending handshake')
  self._encode(HANDSHAKE, {version: VERSION}, function (error) {
    if (error) return callback(error)
    self._sentHandshake = true
    callback()
  })
}

InvitationProtocol.prototype.invitation = function (invitation, callback) {
  assert(validInvitation(invitation))
  debug('sending invitation: %o', invitation)
  this._encode(INVITATION, invitation, callback)
}

InvitationProtocol.prototype.finalize = function (callback) {
  assert(typeof callback === 'function')
  var self = this
  self._finalize(function (error) {
    if (error) return self.destroy(error)
    self._writable.end(callback)
  })
}

InvitationProtocol.prototype._encode = function (prefix, data, callback) {
  var buffer = Buffer.from(JSON.stringify([prefix, data]), 'utf8')
  this._writable.write(buffer, callback)
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
    if (body.version !== VERSION) {
      debug('incompatible version: ' + body.version)
      return callback(new Error('incompatible version'))
    }
  } else if (prefix === INVITATION && validInvitation(body)) {
    this.emit('invitation', body, callback) || callback()
  } else {
    debug('invalid message')
    callback()
  }
}
