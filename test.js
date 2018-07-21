var protocol = require('./')
var sodium = require('sodium-universal')
var stringify = require('fast-json-stable-stringify')
var tape = require('tape')

var intro = {
  type: 'intro',
  name: 'alice',
  device: 'laptop',
  timestamp: new Date().toISOString(),
}

tape('send and receive invitation', function(test) {
  var encryptionKey = makeEncryptionKey()
  var writeSeed = makeSeed()

  var alice = new protocol.Invitation({})
  var bob = new protocol.Invitation({})

  alice.pipe(bob).pipe(alice)

  var keyPair = makeKeyPair()
  var invitation = {
    message: {
      replicationKey: encryptionKey.toString('hex'),
      writeSeed: writeSeed.toString('hex'),
      title: 'test project',
    },
    publicKey: keyPair.publicKey.toString('hex'),
  }
  sign(invitation, keyPair)
  alice.once('handshake', function() {
    alice.invitation(invitation, function(error) {
      test.ifError(error, 'no a.invitation error')
    })
  })
  bob.once('invitation', function(received) {
    test.deepEqual(received, invitation, 'receives invitation')
    test.end()
  })
  alice.handshake(function(error) {
    test.ifError(error, 'no a.handshake error')
  })
  bob.handshake(function(error) {
    test.ifError(error, 'no a.handshake error')
  })
})

tape('invitation without seed', function(test) {
  var encryptionKey = makeEncryptionKey()
  var stream = new protocol.Invitation()
  var keyPair = makeKeyPair()
  var invitation = {
    message: {
      replicationKey: encryptionKey.toString('hex'),
      title: 'test project',
    },
    publicKey: keyPair.publicKey.toString('hex'),
  }
  sign(invitation, keyPair)
  stream.handshake(function() {
    test.doesNotThrow(function() {
      stream.invitation(invitation, function() {})
    }, 'valid invitation')
    test.end()
  })
})

tape('send and receive request', function(test) {
  var alice = new protocol.Invitation()
  var bob = new protocol.Invitation()
  alice.pipe(bob).pipe(alice)
  var keyPair = makeKeyPair()
  var request = {
    message: {
      email: 'test@example.com',
      date: new Date().toISOString(),
    },
    publicKey: keyPair.publicKey.toString('hex'),
  }
  sign(request, keyPair)
  alice.handshake(function(error) {
    test.ifError(error, 'no alice handshake error')
    bob.handshake(function(error) {
      test.ifError(error, 'no bob handshake error')
      bob.once('request', function(received) {
        test.deepEqual(received, request, 'bob received request')
        test.end()
      })
      alice.request(request, function(error) {
        test.ifError(error, 'no alice request error')
      })
    })
  })
})

tape('send and receive offer', function(test) {
  var encryptionKey = makeEncryptionKey()
  var projectKeyPair = makeKeyPair()
  var alice = protocol.Replication({
    encryptionKey,
    publicKey: projectKeyPair.publicKey,
    secretKey: projectKeyPair.secretKey,
  })
  var bob = protocol.Replication({
    encryptionKey,
    publicKey: projectKeyPair.publicKey,
    secretKey: projectKeyPair.secretKey,
  })
  alice.pipe(bob).pipe(alice)
  alice.handshake(function(error) {
    test.ifError(error, 'no a.handshake error')
    bob.handshake(function(error) {
      test.ifError(error, 'no b.handshake error')
      var offer = {publicKey: 'a'.repeat(64), index: 10}
      bob.once('offer', function(received) {
        test.deepEqual(received, offer, 'bob received offer')
        test.end()
      })
      alice.offer(offer, function(error) {
        test.ifError(error, 'no alice offer error')
      })
    })
  })
})

tape('send offer for envelope', function(test) {
  var encryptionKey = makeEncryptionKey()
  var discoveryKey = makeDiscoveryKey(encryptionKey)

  var writeSeed = makeSeed()

  var writeKeyPair = {
    publicKey: Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES),
    secretKey: Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES),
  }
  sodium.crypto_sign_seed_keypair(
    writeKeyPair.publicKey,
    writeKeyPair.secretKey,
    writeSeed
  )

  var alice = protocol.Replication({
    encryptionKey,
    publicKey: writeKeyPair.publicKey,
    secretKey: writeKeyPair.secretKey,
  })
  var aliceKeyPair = makeKeyPair()
  var bob = protocol.Replication({
    encryptionKey,
    publicKey: writeKeyPair.publicKey,
    secretKey: writeKeyPair.secretKey,
  })

  alice.handshake(function(error) {
    test.ifError(error, 'alice sent handshake')
  })

  bob.handshake(function(error) {
    test.ifError(error, 'bob sent handshake')
  })

  alice.once('request', function(request) {
    test.equal(
      request.publicKey,
      aliceKeyPair.publicKey.toString('hex'),
      'alice received request for alice log'
    )
    test.equal(request.index, 0, 'alice received request for entry 0')
    var envelope = {
      message: {
        project: discoveryKey.toString('hex'),
        index: 0,
        body: intro,
      },
      publicKey: aliceKeyPair.publicKey.toString('hex'),
    }
    sign(envelope, aliceKeyPair)
    sign(envelope, writeKeyPair, 'authorization')
    alice.envelope(envelope, function(error) {
      test.ifError(error, 'alice sent envelope')
    })
  })

  bob.once('handshake', function() {
    bob.request(
      {
        publicKey: aliceKeyPair.publicKey.toString('hex'),
        index: 0,
      },
      function(error) {
        test.ifError(error, 'bob sent request')
      }
    )
    bob.once('envelope', function(envelope) {
      test.pass('bob received envelope')
      test.end()
    })
  })

  alice.pipe(bob).pipe(alice)
})

tape('entry links', function(test) {
  var encryptionKey = makeEncryptionKey()
  var discoveryKey = makeDiscoveryKey(encryptionKey)

  var projectSeed = Buffer.alloc(sodium.crypto_sign_SEEDBYTES)
  sodium.randombytes_buf(projectSeed)
  var projectKeyPair = {
    publicKey: Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES),
    secretKey: Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES),
  }
  sodium.crypto_sign_seed_keypair(
    projectKeyPair.publicKey,
    projectKeyPair.secretKey,
    projectSeed
  )

  var alice = protocol.Replication({
    encryptionKey,
    publicKey: projectKeyPair.publicKey,
    secretKey: projectKeyPair.secretKey,
  })
  var logKeyPair = makeKeyPair()

  alice.handshake(function(error) {
    test.ifError(error, 'alice sent handshake')
    var validFirstEnvelope = makeEnvelope({
      project: discoveryKey.toString('hex'),
      index: 0,
      body: intro,
    })
    test.doesNotThrow(function() {
      alice.envelope(validFirstEnvelope, function() {})
    }, 'index: 0, prior: none valid')
    var invalidSecondEnvelope = makeEnvelope({
      project: discoveryKey.toString('hex'),
      index: 1,
      body: intro,
    })
    test.throws(
      function() {
        alice.envelope(invalidSecondEnvelope, function() {})
      },
      /invalid envelope/,
      'index: 1, prior: none invalid'
    )
    var digest = Buffer.alloc(sodium.crypto_generichash_BYTES)
    sodium.crypto_generichash(
      digest,
      Buffer.from(JSON.stringify(validFirstEnvelope.message), 'utf8')
    )
    var validSecondEnvelope = makeEnvelope({
      project: discoveryKey.toString('hex'),
      index: 1,
      prior: digest.toString('hex'),
      body: intro,
    })
    test.doesNotThrow(
      function() {
        alice.envelope(validSecondEnvelope, function() {})
      },
      /invalid envelope/,
      'index: 1, prior: digest valid'
    )
    test.end()
  })

  function makeEnvelope(message) {
    var envelope = {
      message: message,
      publicKey: logKeyPair.publicKey.toString('hex'),
    }
    sign(envelope, logKeyPair)
    sign(envelope, projectKeyPair, 'authorization')
    return envelope
  }
})

function makeSeed() {
  var seed = Buffer.alloc(sodium.crypto_sign_SEEDBYTES)
  sodium.randombytes_buf(seed)
  return seed
}

function sign(object, keyPair, key) {
  key = key || 'signature'
  var signature = Buffer.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(
    signature,
    Buffer.from(stringify(object.message), 'utf8'),
    keyPair.secretKey
  )
  object[key] = signature.toString('hex')
}

function makeEncryptionKey() {
  var encryptionKey = Buffer.alloc(sodium.crypto_stream_KEYBYTES)
  sodium.randombytes_buf(encryptionKey)
  return encryptionKey
}

function makeDiscoveryKey(encryptionKey) {
  var discoveryKey = Buffer.alloc(sodium.crypto_generichash_BYTES)
  sodium.crypto_generichash(discoveryKey, encryptionKey)
  return discoveryKey
}

function makeKeyPair() {
  var publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  var secretKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return {publicKey, secretKey}
}
