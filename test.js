var protocol = require('./')
var sodium = require('sodium-universal')
var stringify = require('fast-json-stable-stringify')
var tape = require('tape')

tape('invitation', function (suite) {
  suite.test('send and receive invitation', function (test) {
    var replicationKey = Buffer.alloc(sodium.crypto_stream_KEYBYTES)
    sodium.randombytes_buf(replicationKey)

    var writeSeed = Buffer.alloc(sodium.crypto_sign_SEEDBYTES)
    sodium.randombytes_buf(writeSeed)

    var a = new protocol.Invitation()
    var b = new protocol.Invitation()

    a.pipe(b).pipe(a)

    var keyPair = makeKeyPair()
    var invitation = {
      message: {
        replicationKey: replicationKey.toString('hex'),
        writeSeed: 'a'.repeat(64),
        title: 'test project'
      },
      publicKey: keyPair.publicKey.toString('hex')
    }
    var signature = Buffer.alloc(sodium.crypto_sign_BYTES)
    sodium.crypto_sign_detached(
      signature,
      Buffer.from(stringify(invitation.message), 'utf8'),
      keyPair.secretKey
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

tape('invitation without seed', function (test) {
  var replicationKey = Buffer.alloc(sodium.crypto_stream_KEYBYTES)
  sodium.randombytes_buf(replicationKey)

  var writeSeed = Buffer.alloc(sodium.crypto_sign_SEEDBYTES)
  sodium.randombytes_buf(writeSeed)

  var stream = new protocol.Invitation()

  var keyPair = makeKeyPair()
  var invitation = {
    message: {
      replicationKey: replicationKey.toString('hex'),
      title: 'test project'
    },
    publicKey: keyPair.publicKey.toString('hex')
  }
  var signature = Buffer.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(
    signature,
    Buffer.from(stringify(invitation.message), 'utf8'),
    keyPair.secretKey
  )
  invitation.signature = signature.toString('hex')
  stream.handshake(function () {
    test.doesNotThrow(function () {
      stream.invitation(invitation, function (error) { })
    }, 'valid invitation')
    test.end()
  })
})

tape('request', function (suite) {
  suite.test('send and receive request', function (test) {
    var a = new protocol.Invitation()
    var b = new protocol.Invitation()
    a.pipe(b).pipe(a)
    var keyPair = makeKeyPair()
    var request = {
      message: {
        email: 'test@example.com',
        date: new Date().toISOString()
      },
      publicKey: keyPair.publicKey.toString('hex')
    }
    var signature = Buffer.alloc(sodium.crypto_sign_BYTES)
    sodium.crypto_sign_detached(
      signature,
      Buffer.from(stringify(request.message), 'utf8'),
      keyPair.secretKey
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
    var replicationKey = Buffer.alloc(sodium.crypto_stream_KEYBYTES)
    sodium.randombytes_buf(replicationKey)
    var a = protocol.Replication({replicationKey})
    var b = protocol.Replication({replicationKey})
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

tape('send offer for envelope', function (test) {
  var replicationKey = Buffer.alloc(sodium.crypto_stream_KEYBYTES)
  sodium.randombytes_buf(replicationKey)
  var discoveryKey = Buffer.alloc(sodium.crypto_generichash_BYTES)
  sodium.crypto_generichash(discoveryKey, replicationKey)

  var writeSeed = Buffer.alloc(sodium.crypto_sign_SEEDBYTES)
  sodium.randombytes_buf(writeSeed)
  var writeKeyPair = {
    publicKey: Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES),
    secretKey: Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  }
  sodium.crypto_sign_seed_keypair(
    writeKeyPair.publicKey, writeKeyPair.secretKey, writeSeed
  )

  var anna = protocol.Replication({replicationKey})
  var annasKeyPair = makeKeyPair()
  var bob = protocol.Replication({replicationKey})

  anna.handshake(function (error) {
    test.ifError(error, 'anna sent handshake')
  })

  bob.handshake(function (error) {
    test.ifError(error, 'bob sent handshake')
  })

  anna.once('request', function (request) {
    test.equal(
      request.publicKey, annasKeyPair.publicKey.toString('hex'),
      'anna received request for anna log'
    )
    test.equal(
      request.index, 0,
      'anna received request for entry 0'
    )
    var envelope = {
      message: {
        project: discoveryKey.toString('hex'),
        index: 0,
        body: {arbitrary: 'data'}
      },
      publicKey: annasKeyPair.publicKey.toString('hex')
    }
    var signature = Buffer.alloc(sodium.crypto_sign_BYTES)
    sodium.crypto_sign_detached(
      signature,
      Buffer.from(stringify(envelope.message), 'utf8'),
      annasKeyPair.secretKey
    )
    envelope.signature = signature.toString('hex')
    var authorization = Buffer.alloc(sodium.crypto_sign_BYTES)
    sodium.crypto_sign_detached(
      authorization,
      Buffer.from(stringify(envelope.message), 'utf8'),
      writeKeyPair.secretKey
    )
    envelope.authorization = authorization.toString('hex')
    anna.envelope(envelope, function (error) {
      test.ifError(error, 'anna sent envelope')
    })
  })

  bob.once('handshake', function () {
    bob.request({
      publicKey: annasKeyPair.publicKey.toString('hex'),
      index: 0
    }, function (error) {
      test.ifError(error, 'bob sent request')
    })
    bob.once('envelope', function (envelope) {
      test.pass('bob received envelope')
      test.end()
    })
  })

  anna.pipe(bob).pipe(anna)
})

tape('entry links', function (test) {
  var replicationKey = Buffer.alloc(sodium.crypto_stream_KEYBYTES)
  sodium.randombytes_buf(replicationKey)
  var discoveryKey = Buffer.alloc(sodium.crypto_generichash_BYTES)
  sodium.crypto_generichash(discoveryKey, replicationKey)

  var projectSeed = Buffer.alloc(sodium.crypto_sign_SEEDBYTES)
  sodium.randombytes_buf(projectSeed)
  var projectKeyPair = {
    publicKey: Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES),
    secretKey: Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  }
  sodium.crypto_sign_seed_keypair(
    projectKeyPair.publicKey, projectKeyPair.secretKey, projectSeed
  )

  var anna = protocol.Replication({replicationKey})
  var logKeyPair = makeKeyPair()

  anna.handshake(function (error) {
    test.ifError(error, 'anna sent handshake')
    var validFirstEnvelope = makeEnvelope({
      project: discoveryKey.toString('hex'),
      index: 0,
      body: {arbitrary: 'data'}
    })
    test.doesNotThrow(function () {
      anna.envelope(validFirstEnvelope, function () { })
    }, 'index: 0, prior: none valid')
    var invalidSecondEnvelope = makeEnvelope({
      project: discoveryKey.toString('hex'),
      index: 1,
      body: {arbitrary: 'data'}
    })
    test.throws(function () {
      anna.envelope(invalidSecondEnvelope, function () { })
    }, /invalid envelope/, 'index: 1, prior: none invalid')
    var digest = Buffer.alloc(sodium.crypto_generichash_BYTES)
    sodium.crypto_generichash(digest, Buffer.from(
      JSON.stringify(validFirstEnvelope.message),
      'utf8'
    ))
    var validSecondEnvelope = makeEnvelope({
      project: discoveryKey.toString('hex'),
      index: 1,
      prior: digest,
      body: {arbitrary: 'data'}
    })
    test.throws(function () {
      anna.envelope(validSecondEnvelope, function () { })
    }, /invalid envelope/, 'index: 1, prior: digest valid')
    test.end()
  })

  function makeEnvelope (message) {
    var envelope = {
      message: message,
      publicKey: logKeyPair.publicKey.toString('hex')
    }
    var signature = Buffer.alloc(sodium.crypto_sign_BYTES)
    sodium.crypto_sign_detached(
      signature,
      Buffer.from(stringify(envelope.message), 'utf8'),
      logKeyPair.secretKey
    )
    envelope.signature = signature.toString('hex')
    var authorization = Buffer.alloc(sodium.crypto_sign_BYTES)
    sodium.crypto_sign_detached(
      authorization,
      Buffer.from(stringify(envelope.message), 'utf8'),
      projectKeyPair.secretKey
    )
    envelope.authorization = authorization.toString('hex')
    return envelope
  }
})

function makeKeyPair () {
  var publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  var secretKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return {publicKey, secretKey}
}
