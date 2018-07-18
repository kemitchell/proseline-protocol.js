var protocol = require('./')
var sodium = require('sodium-universal')
var stringify = require('fast-json-stable-stringify')
var tape = require('tape')

tape('invitation', function (suite) {
  suite.test('send and receive invitation', function (test) {
    var a = new protocol.Invitation()
    var b = new protocol.Invitation()
    a.pipe(b).pipe(a)
    var keys = makeKeyPair()
    var invitation = {
      message: {
        secretKey: 'a'.repeat(64),
        title: 'test project'
      },
      publicKey: keys.publicKey.toString('hex')
    }
    var signature = Buffer.alloc(sodium.crypto_sign_BYTES)
    sodium.crypto_sign_detached(
      signature,
      Buffer.from(stringify(invitation.message), 'utf8'),
      keys.secretKey
    )
    invitation.signature = signature.toString('hex')
    a.once('handshake', function () {
      a.invitation(invitation, function (error) {
        test.ifError(error, 'no a.invitation error')
      })
    })
    b.once('invitation', function (received) {
      test.deepEqual(received, invitation, 'receives invitation')
      test.end()
    })
    a.handshake(function (error) {
      test.ifError(error, 'no a.handshake error')
    })
    b.handshake(function (error) {
      test.ifError(error, 'no a.handshake error')
    })
  })
})

tape('request', function (suite) {
  suite.test('send and receive request', function (test) {
    var a = new protocol.Invitation()
    var b = new protocol.Invitation()
    a.pipe(b).pipe(a)
    var keys = makeKeyPair()
    var request = {
      message: {
        email: 'test@example.com',
        date: new Date().toISOString()
      },
      publicKey: keys.publicKey.toString('hex')
    }
    var signature = Buffer.alloc(sodium.crypto_sign_BYTES)
    sodium.crypto_sign_detached(
      signature,
      Buffer.from(stringify(request.message), 'utf8'),
      keys.secretKey
    )
    request.signature = signature.toString('hex')
    a.handshake(function (error) {
      test.ifError(error, 'no a.handshake error')
      b.handshake(function (error) {
        test.ifError(error, 'no b.handshake error')
        b.once('request', function (received) {
          test.deepEqual(received, request, 'receives request')
          test.end()
        })
        a.request(request, function (error) {
          test.ifError(error, 'no a.request error')
        })
      })
    })
  })
})

tape('replication', function (suite) {
  suite.test('send and receive offer', function (test) {
    var secretKey = Buffer.alloc(64)
    sodium.randombytes_buf(secretKey)
    var secretKeyHex = secretKey.toString('hex')
    var a = protocol.Replication(secretKeyHex)
    var b = protocol.Replication(secretKeyHex)
    a.pipe(b).pipe(a)
    a.handshake(function (error) {
      test.ifError(error, 'no a.handshake error')
      b.handshake(function (error) {
        test.ifError(error, 'no b.handshake error')
        var offer = {publicKey: 'a'.repeat(64), index: 10}
        b.once('offer', function (received) {
          test.deepEqual(received, offer, 'receives offer')
          test.end()
        })
        a.offer(offer, function (error) {
          test.ifError(error, 'no a.offer error')
        })
      })
    })
  })
})

function makeKeyPair () {
  var publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  var secretKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return {publicKey, secretKey}
}
