var protocol = require('./')
var sodium = require('sodium-universal')
var stringify = require('fast-json-stable-stringify')
var tape = require('tape')

tape('invitation', function (suite) {
  suite.test('basic', function (test) {
    var a = new protocol.Invitation()
    var b = new protocol.Invitation()
    a.pipe(b).pipe(a)
    var aPublicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
    var aSecretKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
    sodium.crypto_sign_keypair(aPublicKey, aSecretKey)
    var invitation = {
      message: {secretKey: 'a'.repeat(64)},
      publicKey: aPublicKey.toString('hex')
    }
    var signature = Buffer.alloc(sodium.crypto_sign_BYTES)
    sodium.crypto_sign_detached(
      signature,
      Buffer.from(stringify(invitation.message), 'utf8'),
      aSecretKey
    )
    invitation.signature = signature.toString('hex')
    a.handshake(function (error) {
      test.ifError(error, 'no a.handshake error')
      b.handshake(function (error) {
        test.ifError(error, 'no b.handshake error')
        b.once('invitation', function (received) {
          test.deepEqual(received, invitation, 'receives invitation')
          test.end()
        })
        a.invitation(invitation, function (error) {
          test.ifError(error, 'no a.invitation error')
        })
      })
    })
  })
})
