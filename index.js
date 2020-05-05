'use strict'

/**
 * Module dependencies.
 * @private
 */

let Buffer = require('safe-buffer').Buffer
let cookie = require('cookie')
let crypto = require('crypto')
let deprecate = require('depd')('express-session')
let onHeaders = require('on-headers')
let parseUrl = require('parseurl')
let signature = require('../libraries/cookie/signature.js')({})
let uid = require('uid-safe').sync

let Cookie = require('./session/cookie')
let MemoryStore = require('./session/memory')
let Session = require('./session/session')
let Store = require('./session/store')

// environment

let env = process.env.NODE_ENV

/**
 * Expose the middleware.
 */

exports = module.exports = session

/**
 * Expose constructors.
 */

exports.Store = Store
exports.Cookie = Cookie
exports.Session = Session
exports.MemoryStore = MemoryStore

/**
 * Warning message for `MemoryStore` usage in production.
 * @private
 */

let warning = 'Warning: connect.session() MemoryStore is not\n'
  + 'designed for a production environment, as it will leak\n'
  + 'memory, and will not scale past a single process.'

/**
 * Node.js 0.8+ async implementation.
 * @private
 */

/* istanbul ignore next */
let defer = typeof setImmediate === 'function' ? setImmediate : function(fn){ process.nextTick(fn.bind.apply(fn, arguments)) }

/**
 * Setup session store with the given `options`.
 *
 * @param {Object} [options]
 * @param {Object} [options.cookie] Options for cookie
 * @param {Function} [options.genid]
 * @param {String} [options.name=connect.sid] Session ID cookie name
 * @param {Boolean} [options.proxy]
 * @param {Boolean} [options.resave] Resave unmodified sessions back to the store
 * @param {Boolean} [options.rolling] Enable/disable rolling session expiration
 * @param {Boolean} [options.saveUninitialized] Save uninitialized sessions to the store
 * @param {String|Array} [options.secret] Secret for signing session ID
 * @param {Object} [options.store=MemoryStore] Session store
 * @param {String} [options.unset]
 * @return {Function} middleware
 * @public
 */

function session(options) {

  let opts = options || {}

  // get the cookie options
  let cookieOptions = opts.cookie || {}
  let hashOptions = options.hashOptions || { algo: 'RSA-SHA3-512', digest: 'hex' }

  // get the session id generate function
  let generateId = opts.genid || generateSessionId

  // get the session cookie name
  let name = opts.name || opts.key || 'connect.sid'

  // get the session store
  let store = opts.store || new MemoryStore()

  // get the trust proxy setting
  let trustProxy = opts.proxy

  // get the resave session option
  let resaveSession = opts.resave

  // get the rolling session option
  let rollingSessions = Boolean(opts.rolling)

  // get the save uninitialized session option
  let saveUninitializedSession = opts.saveUninitialized

  // get the cookie signing secret
  let secret = opts.secret

  if (typeof generateId !== 'function') { throw new TypeError('genid option must be a function') }

  if (resaveSession === undefined) {

    deprecate('undefined resave option provide resave option')
    resaveSession = true
  }

  if (saveUninitializedSession === undefined) {

    deprecate('undefined saveUninitialized option provide saveUninitialized option')
    saveUninitializedSession = true
  }

  if (opts.unset && opts.unset !== 'destroy' && opts.unset !== 'keep') {
    throw new TypeError('unset option must be "destroy" or "keep"')
  }

  // TODO: switch to "destroy" on next major
  let unsetDestroy = opts.unset === 'destroy'

  if (Array.isArray(secret) && secret.length === 0) { throw new TypeError('secret option array must contain one or more strings') }

  if (secret && !Array.isArray(secret)) { secret = [secret] }

  if (!secret) { deprecate('req.secret provide secret option') }

  // notify user that this store is not
  // meant for a production environment
  /* istanbul ignore next: not tested */
  if (env === 'production' && store instanceof MemoryStore) { console.warn(warning) }

  // generates the new session
  store.generate = function(req){

    req.sessionID = generateId(req)
    req.session = new Session(req)
    req.session.cookie = new Cookie(cookieOptions)

    if (cookieOptions.secure === 'auto') { req.session.cookie.secure = issecure(req, trustProxy) }
  }

  let storeImplementsTouch = typeof store.touch === 'function'

  // register event listeners for the store to track readiness
  let storeReady = true
  store.on('disconnect', function ondisconnect() { storeReady = false })
  store.on('connect', function onconnect() { storeReady = true })

  return function session(req, res, next) {

    // self-awareness
    if (req.session) {
      next()
      return
    }

    // Handle connection as if there is no session if
    // the store has temporarily disconnected etc
    if (!storeReady) {

      next()
      return
    }

    // pathname mismatch
    let originalPath = parseUrl.original(req).pathname || '/'

    if (originalPath.indexOf(cookieOptions.path || '/') !== 0) return next()

    // ensure a secret is available or bail
    if (!secret && !req.secret) {

      next(new Error('secret option required for sessions'))
      return
    }

    // backwards compatibility for signed cookies
    // req.secret is passed from the cookie parser middleware
    let secrets = secret || [req.secret]

    let originalHash
    let originalId
    let savedHash
    let touched = false

    // expose store
    req.sessionStore = store

    // get the session ID from the cookie
    let cookieId = req.sessionID = getcookie(req, name, secrets)

    // set-cookie
    onHeaders(res, function(){

      if (!req.session) { return }

      if (!shouldSetCookie(req)) { return }

      // only send secure cookies via https
      if (req.session.cookie.secure && !issecure(req, trustProxy)) { return }

      if (!touched) {

        // touch session
        req.session.touch()
        touched = true
      }

      // set cookie
      setcookie(res, name, req.sessionID, secrets[0], req.session.cookie.data)
    })

    // proxy end() to commit the session
    let _end = res.end
    let _write = res.write
    let ended = false
    res.end = function end(chunk, encoding) {

      if (ended) { return false }

      ended = true

      let ret
      let sync = true

      function writeend() {

        if (sync) {

          ret = _end.call(res, chunk, encoding)
          sync = false
          return
        }

        _end.call(res)
      }

      function writetop() {

        if (!sync) { return ret }

        if (chunk == null) {

          ret = true
          return ret
        }

        let contentLength = Number(res.getHeader('Content-Length'))

        if (!isNaN(contentLength) && contentLength > 0) {

          // measure chunk
          chunk = !Buffer.isBuffer(chunk) ? Buffer.from(chunk, encoding) : chunk
          encoding = undefined

          if (chunk.length !== 0) {

            ret = _write.call(res, chunk.slice(0, chunk.length - 1))
            chunk = chunk.slice(chunk.length - 1, chunk.length)
            return ret
          }
        }

        ret = _write.call(res, chunk, encoding)
        sync = false

        return ret
      }

      if (shouldDestroy(req)) {
        // destroy session

        store.destroy(req.sessionID, function ondestroy(err) {

          if (err) { defer(next, err) }

          writeend()
        })

        return writetop()
      }

      // no session to save
      if (!req.session) { return _end.call(res, chunk, encoding) }

      if (!touched) {

        // touch session
        req.session.touch()
        touched = true
      }

      if (shouldSave(req)) {

        req.session.save(function onsave(err) {

          if (err) { defer(next, err) }

          writeend()
        })

        return writetop()

      } else if (storeImplementsTouch && shouldTouch(req)) {

        // store implements touch method
        store.touch(req.sessionID, req.session, function ontouch(err) {

          if (err) { defer(next, err) }

          writeend()
        })

        return writetop()
      }

      return _end.call(res, chunk, encoding)
    }

    // generate the session
    function generate() {

      store.generate(req)
      originalId = req.sessionID
      originalHash = hash(req.session, hashOptions)
      wrapmethods(req.session)
    }

    // inflate the session
    function inflate (req, sess) {

      store.createSession(req, sess)
      originalId = req.sessionID
      originalHash = hash(sess, hashOptions)

      if (!resaveSession) { savedHash = originalHash }

      wrapmethods(req.session)
    }

    function rewrapmethods (sess, callback) {

      return function () {

        if (req.session !== sess) { wrapmethods(req.session) }

        callback.apply(this, arguments)
      }
    }

    // wrap session methods
    function wrapmethods(sess) {

      let _reload = sess.reload
      let _save = sess.save

      function reload(callback) { _reload.call(this, rewrapmethods(this, callback)) }

      function save() {

        savedHash = hash(this, hashOptions)
        _save.apply(this, arguments)
      }

      Object.defineProperty(sess, 'reload', {

        configurable: true,
        enumerable: false,
        value: reload,
        writable: true
      })

      Object.defineProperty(sess, 'save', {

        configurable: true,
        enumerable: false,
        value: save,
        writable: true
      })
    }

    // check if session has been modified
    function isModified(sess) { return originalId !== sess.id || originalHash !== hash(sess, hashOptions) }

    // check if session has been saved
    function isSaved(sess) { return originalId === sess.id && savedHash === hash(sess, hashOptions) }

    // determine if session should be destroyed
    function shouldDestroy(req) { return req.sessionID && unsetDestroy && req.session == null }

    // determine if session should be saved to store
    function shouldSave(req) {

      // cannot set cookie without a session ID
      if (typeof req.sessionID !== 'string') { return false }

      return !saveUninitializedSession && cookieId !== req.sessionID ? isModified(req.session) : !isSaved(req.session)
    }

    // determine if session should be touched
    function shouldTouch(req) {

      // cannot set cookie without a session ID
      if (typeof req.sessionID !== 'string') { return false }

      return cookieId === req.sessionID && !shouldSave(req)
    }

    // determine if cookie should be set on response
    function shouldSetCookie(req) {

      // cannot set cookie without a session ID
      if (typeof req.sessionID !== 'string') { return false }

      return cookieId !== req.sessionID
        ? saveUninitializedSession || isModified(req.session)
        : rollingSessions || req.session.cookie.expires != null && isModified(req.session)
    }

    // generate a session if the browser doesn't send a sessionID
    if (!req.sessionID) {

      generate()
      next()
      return
    }

    // generate the session object

    store.get(req.sessionID, function(err, sess){

      // error handling
      if (err && err.code !== 'ENOENT') {

        next(err)
        return
      }

      try {

        if (err || !sess) { generate() } else { inflate(req, sess) }

      } catch (e) {

        next(e)
        return
      }

      next()
    })
  }
}

/**
 * Generate a session ID for a new session.
 *
 * @return {String}
 * @private
 */

function generateSessionId(sess) { return uid(128) }

/**
 * Get the session ID cookie from request.
 *
 * @return {string}
 * @private
 */

function getcookie(req, name, secrets) {

  let header = req.headers.cookie
  let raw
  let val

  // read from cookie header
  if (header) {

    let cookies = cookie.parse(header)

    raw = cookies[name]

    if (raw) {

      if (raw.substr(0, 2) === 's:') {

        val = unsigncookie(raw.slice(2), secrets)

        if (val === false) { val = undefined }

      }
    }
  }

  // back-compat read from cookieParser() signedCookies data
  if (!val && req.signedCookies) {

    val = req.signedCookies[name]

    if (val) { deprecate('cookie should be available in req.headers.cookie') }
  }

  // back-compat read from cookieParser() cookies data
  if (!val && req.cookies) {

    raw = req.cookies[name]

    if (raw) {

      if (raw.substr(0, 2) === 's:') {

        val = unsigncookie(raw.slice(2), secrets)

        if (val) { deprecate('cookie should be available in req.headers.cookie') }

        if (val === false) { val = undefined }
      }
    }
  }

  return val
}

/**
 * Hash the given `sess` object omitting changes to `.cookie`.
 *
 * @param {Object} sess
 * @return {String}
 * @private
 */

function hash(sess, hashOptions) {

  // serialize
  let str = JSON.stringify(sess, function (key, val) {

    // ignore sess.cookie property
    if (this === sess && key === 'cookie') { return }

    return val
  })

  // hash
  return crypto.createHash(hashOptions.algo).update(str, 'utf8').digest(hashOptions.digest)
}

/**
 * Determine if request is secure.
 *
 * @param {Object} req
 * @param {Boolean} [trustProxy]
 * @return {Boolean}
 * @private
 */

function issecure(req, trustProxy) {
  // socket is https server
  if (req.connection && req.connection.encrypted) { return true }

  // do not trust proxy
  if (trustProxy === false) { return false }

  // no explicit trust try req.secure from express
  if (trustProxy !== true) { return req.secure === true }

  // read the proto from x-forwarded-proto header
  let header = req.headers['x-forwarded-proto'] || ''
  let index = header.indexOf(',')
  let proto = index !== -1 ? header.substr(0, index).toLowerCase().trim() : header.toLowerCase().trim()

  return proto === 'https'
}

/**
 * Set cookie on response.
 *
 * @private
 */

function setcookie(res, name, val, secret, options) {

  let signed = 's:' + signature.sign(val, secret)
  let data = cookie.serialize(name, signed, options)

  let prev = res.getHeader('Set-Cookie') || []
  let header = Array.isArray(prev) ? prev.concat(data) : [prev, data]

  res.setHeader('Set-Cookie', header)
}

/**
 * Verify and decode the given `val` with `secrets`.
 *
 * @param {String} val
 * @param {Array} secrets
 * @returns {String|Boolean}
 * @private
 */
function unsigncookie(val, secrets) {

  for (let i = 0; i < secrets.length; i++) {
    
    let result = signature.unsign(val, secrets[i])

    if (result !== false) { return result }
  }

  return false
}
