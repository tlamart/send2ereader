#!/usr/bin/env node

const http = require('http')
const Koa = require('koa')
const Router = require('@koa/router')
const multer = require('@koa/multer')
const sendfile = require('koa-sendfile')
const serve = require('koa-static')
const { mkdirp } = require('mkdirp')
const fs = require('fs')
const { spawn } = require('child_process')
const crypto = require('crypto')
const { extname, basename, dirname } = require('path')
const { transliterate } = require('transliteration')
const sanitize = require('sanitize-filename')

loadEnvFile('.env')

const port = 3001
const expireDelay = 30  // 30 seconds
const maxExpireDuration = 1 * 60 * 60  // 1 hour
const secretExpireDelay = readPositiveInteger('SECRET_EXPIRE_DELAY', 24 * 60 * 60)  // 24 hours
const secretMaxExpireDuration = readPositiveInteger('SECRET_MAX_EXPIRE_DURATION', secretExpireDelay)
const maxFileSize = 1024 * 1024 * 800  // 800 MB
const secretMaxFiles = 5
const maxStoredBytes = readPositiveInteger('MAX_STORED_BYTES', maxFileSize * secretMaxFiles)
const rateLimitWindow = readPositiveInteger('RATE_LIMIT_WINDOW', 60)  // 1 minute
const generateRateLimit = readPositiveInteger('GENERATE_RATE_LIMIT', 30)
const uploadRateLimit = readPositiveInteger('UPLOAD_RATE_LIMIT', 10)
const conversionTimeout = readPositiveInteger('CONVERSION_TIMEOUT', 5 * 60)  // 5 minutes
const maxUrlsPerKey = readPositiveInteger('MAX_URLS_PER_KEY', 20)
const secretAuthRateLimit = readPositiveInteger('SECRET_AUTH_RATE_LIMIT', 30)

const secretUploadRoute = normalizeSecretRoute('SECRET_UPLOAD_ROUTE')
const secretReceiveRoute = normalizeSecretRoute('SECRET_RECEIVE_ROUTE')
if ((secretUploadRoute && !secretReceiveRoute) || (!secretUploadRoute && secretReceiveRoute)) {
  throw new Error('SECRET_UPLOAD_ROUTE and SECRET_RECEIVE_ROUTE must be configured together')
}
const secretUploadUsername = process.env.SECRET_UPLOAD_USERNAME || 'send2ereader'
const secretUploadPassword = process.env.SECRET_UPLOAD_PASSWORD || null
if (secretUploadRoute && !secretUploadPassword) {
  throw new Error('SECRET_UPLOAD_PASSWORD must be configured when SECRET_UPLOAD_ROUTE is enabled')
}

const TYPE_EPUB = 'application/epub+zip'
const TYPE_MOBI = 'application/x-mobipocket-ebook'

const allowedTypes = [TYPE_EPUB, TYPE_MOBI, 'application/pdf', 'application/vnd.comicbook+zip', 'application/vnd.comicbook-rar', 'text/html', 'text/plain', 'application/zip', 'application/x-rar-compressed']
const allowedExtensions = ['epub', 'mobi', 'pdf', 'cbz', 'cbr', 'html', 'txt']

const keyChars = "23456789ACDEFGHJKLMNPRSTUVWXYZ"
const keyLength = 4
const secretKey = '__secret__'


function loadEnvFile (filepath) {
  if (!fs.existsSync(filepath)) return

  const lines = fs.readFileSync(filepath, 'utf8').split(/\r?\n/)
  for (const line of lines) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) continue

    const match = trimmed.match(/^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/)
    if (!match) continue

    let value = match[2].trim()
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1)
    }
    if (process.env[match[1]] === undefined) {
      process.env[match[1]] = value
    }
  }
}

function readPositiveInteger (name, fallback) {
  const value = process.env[name]
  if (!value) return fallback

  const parsed = Number.parseInt(value, 10)
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(name + ' must be a positive integer')
  }
  return parsed
}

function normalizeSecretRoute (name) {
  const value = process.env[name]
  if (!value) return null

  const route = value.trim().replace(/\/+$/, '')
  const normalized = route.startsWith('/') ? route : '/' + route

  if (!/^\/[A-Za-z0-9_-]+$/.test(normalized)) {
    throw new Error(name + ' must be a single URL segment, for example /my-secret-route')
  }
  if (['/generate', '/upload', '/status', '/receive', '/file'].includes(normalized)) {
    throw new Error(name + ' cannot use a reserved route: ' + normalized)
  }
  return normalized
}

function isSecretUploadPath (path) {
  return secretUploadRoute && path.split('?')[0] === secretUploadRoute + '/upload'
}

function redactUrl (url) {
  if (!url) return url

  let redacted = url
  const secretRoutes = [secretUploadRoute, secretReceiveRoute]
  secretRoutes.forEach((route) => {
    if (!route) return
    if (redacted === route || redacted.startsWith(route + '/') || redacted.startsWith(route + '?')) {
      redacted = redacted.replace(route, '/[secret-route]')
    }
  })
  return redacted
}

function validateUrl (value) {
  if (!value) return null

  let url = null
  try {
    url = new URL(value)
  } catch (err) {
    return null
  }

  if (!['http:', 'https:'].includes(url.protocol)) return null
  if (url.href.length > 2048) return null
  return url.href
}

function rateLimit (ctx, name, limit) {
  const now = Date.now()
  const id = name + ':' + ctx.ip
  const timestamps = (ctx.rateLimits.get(id) || []).filter((timestamp) => {
    return now - timestamp < rateLimitWindow * 1000
  })
  if (timestamps.length >= limit) {
    ctx.response.status = 429
    ctx.body = 'Too many requests. Please try again later.'
    ctx.rateLimits.set(id, timestamps)
    return false
  }
  timestamps.push(now)
  ctx.rateLimits.set(id, timestamps)
  return true
}

function timingSafeEqualString (left, right) {
  const leftBuffer = Buffer.from(left || '', 'utf8')
  const rightBuffer = Buffer.from(right || '', 'utf8')
  if (leftBuffer.length !== rightBuffer.length) return false
  return crypto.timingSafeEqual(leftBuffer, rightBuffer)
}

function unauthorizedSecretUpload (ctx) {
  ctx.response.status = 401
  ctx.set('WWW-Authenticate', 'Basic realm="send2ereader secret upload", charset="UTF-8"')
  ctx.body = 'Authentication required'
}

function requireSecretUploadAuth (ctx) {
  if (!secretUploadPassword) return true
  if (!rateLimit(ctx, 'secret-upload-auth', secretAuthRateLimit)) return false

  const header = ctx.get('authorization')
  if (!header || !header.startsWith('Basic ')) {
    unauthorizedSecretUpload(ctx)
    return false
  }

  let decoded = ''
  try {
    decoded = Buffer.from(header.slice(6), 'base64').toString('utf8')
  } catch (err) {
    unauthorizedSecretUpload(ctx)
    return false
  }

  const splitAt = decoded.indexOf(':')
  if (splitAt === -1) {
    unauthorizedSecretUpload(ctx)
    return false
  }

  const username = decoded.slice(0, splitAt)
  const password = decoded.slice(splitAt + 1)
  if (!timingSafeEqualString(username, secretUploadUsername) || !timingSafeEqualString(password, secretUploadPassword)) {
    unauthorizedSecretUpload(ctx)
    return false
  }

  return true
}

function trackedBytes (files) {
  return files.reduce((total, file) => {
    return total + (file && file.size ? file.size : 0)
  }, 0)
}

function logUploadMetadata (label, files) {
  console.log(label, files.map((file) => {
    return {
      fieldname: file.fieldname,
      mimetype: file.mimetype,
      size: file.size,
      path: file.path
    }
  }))
}

function doTransliterate(filename) {
  let name = filename.split(".")
  const ext = "." + name.splice(-1).join(".")
  name = name.join(".")

  return transliterate(name) + ext
}

function randomKey () {
  const choices = Math.pow(keyChars.length, keyLength)
  const rnd = Math.floor(Math.random() * choices)

  return rnd.toString(keyChars.length).padStart(keyLength, '0').split('').map((chr) => {
    return keyChars[parseInt(chr, keyChars.length)]
  }).join('')
}

async function detectFileType (filepath) {
  const { fileTypeFromFile } = await import('file-type')
  return fileTypeFromFile(filepath)
}

function removeKey (key) {
  console.log('Removing expired key', key)
  const info = app.context.keys.get(key)
  if (info) {
    clearTimeout(app.context.keys.get(key).timer)
    clearTimeout(app.context.keys.get(key).maxTimer)
    removeFiles(info.files || (info.file ? [info.file] : []), {
      tracked: true
    })
    info.file = null
    info.files = []
    app.context.keys.delete(key)
  } else {
    console.log('Tried to remove non-existing key', key)
  }
}

function removeFiles (files, options = {}) {
  const seen = new Set()
  files.forEach((file) => {
    if (!file || !file.path || seen.has(file.path)) return
    seen.add(file.path)
    if (options.tracked && app.context.storedBytes) {
      app.context.storedBytes = Math.max(0, app.context.storedBytes - (file.size || 0))
    }
    console.log('Deleting file', file.path)
    fs.unlink(file.path, (err) => {
      if (err) console.error(err)
    })
  })
}

function uniqueFilename (filename, files) {
  const usedNames = files.map((file) => file.name)
  if (!usedNames.includes(filename)) return filename

  const ext = extname(filename)
  const name = filename.slice(0, filename.length - ext.length)
  let index = 2
  let candidate = name + ' (' + index + ')' + ext
  while (usedNames.includes(candidate)) {
    index++
    candidate = name + ' (' + index + ')' + ext
  }
  return candidate
}

function expireKey (key) {
  const info = app.context.keys.get(key)
  const delay = info && info.expireDelay ? info.expireDelay : expireDelay
  const timer = setTimeout(removeKey, delay * 1000, key)
  if (info) {
    clearTimeout(info.timer)
    info.timer = timer
    info.alive = new Date()
  }
  return timer
}

function ensureSecretInfo (ctx) {
  let info = ctx.keys.get(secretKey)
  if (info) return info

  info = {
    created: new Date(),
    agent: null,
    expireDelay: secretExpireDelay,
    maxExpireDuration: secretMaxExpireDuration,
    file: null,
    files: [],
    urls: []
  }
  ctx.keys.set(secretKey, info)
  expireKey(secretKey)
  info.maxTimer = setTimeout(() => {
    if(ctx.keys.get(secretKey) === info) removeKey(secretKey)
  }, info.maxExpireDuration * 1000)
  return info
}

function flash (ctx, data) {
  console.log('Response:', {
    success: data.success,
    status: data.success ? 200 : 400
  })
  //ctx.cookies.set('flash', encodeURIComponent(JSON.stringify(data)), {overwrite: true, httpOnly: false, sameSite: 'strict', maxAge: 10 * 1000})
  ctx.response.status = data.success ? 200 : 400
  if (!data.success) {
    ctx.set("Connection", "close")
  }
  ctx.body = data.message
}

const app = new Koa()
app.context.keys = new Map()
app.context.rateLimits = new Map()
app.context.storedBytes = 0
app.use(async (ctx, next) => {
  const start = Date.now()
  ctx.set('X-Content-Type-Options', 'nosniff')
  ctx.set('Referrer-Policy', 'no-referrer')
  ctx.set('X-Frame-Options', 'DENY')
  await next()
  console.log(ctx.method, redactUrl(ctx.url), ctx.status, Date.now() - start + 'ms')
})

const router = new Router()

const upload = multer({
  storage: multer.diskStorage({
    destination: function (req, file, cb) {
      cb(null, 'uploads')
    },
    filename: function (req, file, cb) {
      const uniqueSuffix = Date.now() + '-' + Math.floor(Math.random() * 1E9)
      cb(null, file.fieldname + '-' + uniqueSuffix + extname(file.originalname).toLowerCase())
    }
  }),
  limits: {
    fileSize: maxFileSize,
    files: secretMaxFiles
  },
  fileFilter: (req, file, cb) => {
    // Fixes charset
    // https://github.com/expressjs/multer/issues/1104#issuecomment-1152987772
    file.originalname = sanitize(Buffer.from(file.originalname, 'latin1').toString('utf8'))

    console.log('Incoming file:', {
      fieldname: file.fieldname,
      mimetype: file.mimetype
    })
    const key = isSecretUploadPath(req.url) ? secretKey : (req.body.key || '').toUpperCase()
    if (!app.context.keys.has(key)) {
      console.error('FileFilter: Unknown key: ' + key)
      cb(isSecretUploadPath(req.url) ? "No secret receiver is connected" : "Unknown key " + key, false)
      return
    }
    if ((!allowedTypes.includes(file.mimetype) && file.mimetype != "application/octet-stream") || !allowedExtensions.includes(extname(file.originalname.toLowerCase()).substring(1))) {
      console.error('FileFilter: File is of an invalid type ', {
        fieldname: file.fieldname,
        mimetype: file.mimetype
      })
      cb("Invalid filetype: " + JSON.stringify(file), false)
      return
    }
    cb(null, true)
  }
})

async function generateKey (ctx, options = {}) {
  const agent = ctx.get('user-agent')

  let key = options.key || null
  let attempts = 0
  console.log('There are currently', ctx.keys.size, 'key(s) in use.')
  if (!key) {
    console.log('Generating unique key...', ctx.ip, agent)
    do {
      key = randomKey()
      if (attempts > ctx.keys.size) {
        console.error('Can\'t generate more keys, map is full.', attempts, ctx.keys.size)
        ctx.body = 'error'
        return
      }
      attempts++
    } while (ctx.keys.has(key))

    console.log('Generated key ' + key + ', '+attempts+' attempt(s)')
  }

  const currentInfo = ctx.keys.get(key)
  if (currentInfo) {
    if (options.key === secretKey && currentInfo.agent && currentInfo.agent !== agent && (currentInfo.files || []).length > 0) {
      ctx.response.status = 409
      ctx.body = 'Secret receiver is already connected'
      return
    }
    currentInfo.agent = agent
    currentInfo.expireDelay = options.expireDelay || expireDelay
    currentInfo.maxExpireDuration = options.maxExpireDuration || maxExpireDuration
    expireKey(key)
    clearTimeout(currentInfo.maxTimer)
    currentInfo.maxTimer = setTimeout(() => {
      if(ctx.keys.get(key) === currentInfo) removeKey(key)
    }, currentInfo.maxExpireDuration * 1000)
    ctx.cookies.set('key', key, {overwrite: true, httpOnly: false, sameSite: 'strict', maxAge: currentInfo.expireDelay * 1000})
    ctx.body = key
    return
  }

  const info = {
    created: new Date(),
    agent: agent,
    expireDelay: options.expireDelay || expireDelay,
    maxExpireDuration: options.maxExpireDuration || maxExpireDuration,
    file: null,
    files: [],
    urls: []
  }
  ctx.keys.set(key, info)
  expireKey(key)
  info.maxTimer = setTimeout(() => {
    // remove if it is the same object
    if(ctx.keys.get(key) === info) removeKey(key)
  }, info.maxExpireDuration * 1000)

  ctx.cookies.set('key', key, {overwrite: true, httpOnly: false, sameSite: 'strict', maxAge: info.expireDelay * 1000})

  ctx.body = key
}

router.post('/generate', async ctx => {
  if (!rateLimit(ctx, 'generate', generateRateLimit)) return
  await generateKey(ctx)
})

if (secretReceiveRoute) {
  router.post(secretReceiveRoute + '/generate', async ctx => {
    if (!rateLimit(ctx, 'secret-generate', generateRateLimit)) return
    await generateKey(ctx, {
      key: secretKey,
      expireDelay: secretExpireDelay,
      maxExpireDuration: secretMaxExpireDuration
    })
  })
}

/*
router.get('/download/:key', async ctx => {
  const key = ctx.cookies.get('key')
  if (!key) {
    await next()
    return
  }

  const info = ctx.keys.get(key)

  if (!info || !info.file) {
    await next()
    return
  }

  ctx.redirect('/' + encodeURIComponent(info.file.name));
})
*/

async function downloadFile (ctx, next, options = {}) {
  const key = options.key || ctx.query.key
  if (!key) {
    await next()
    return
  }

  const filename = decodeURIComponent(ctx.params.filename)
  const info = ctx.keys.get(key)

  const files = info && info.files && info.files.length > 0 ? info.files : (info && info.file ? [info.file] : [])
  const file = files.find((item) => item.name === filename)

  if (!info || !file) {
    await next()
    return
  }
  if (info.agent !== ctx.get('user-agent')) {
    console.error("User Agent doesnt match: " + info.agent + " VS " + ctx.get('user-agent'))
    return
  }
  expireKey(key)
  console.log('Sending file', file.path)
  ctx.attachment(file.name)
  await sendfile(ctx, file.path)
}

async function processUploadedFile (ctx, info, uploadedFile) {
  if (uploadedFile.size === 0) {
    throw {
      message: 'Invalid file submitted (empty file)',
      cleanup: [uploadedFile.path]
    }
  }

  let mimetype = uploadedFile.mimetype

  const type = await detectFileType(uploadedFile.path)

  if (mimetype == "application/octet-stream" && type) {
    mimetype = type.mime
  }

  if (mimetype == "application/epub") {
    mimetype = TYPE_EPUB
  }

  if ((!type || !allowedTypes.includes(type.mime)) && !allowedTypes.includes(mimetype)) {
    throw {
      message: 'Uploaded file is of an invalid type: ' + uploadedFile.originalname + ' (' + (type? type.mime : 'unknown mimetype') + ')',
      cleanup: [uploadedFile.path]
    }
  }

  let data = null
  let conversion = null
  let filename = uploadedFile.originalname
  if (ctx.request.body.transliteration) {
    filename = sanitize(doTransliterate(filename))
  }
  if (info.agent.includes('Kindle')) {
    filename = filename.replace(/[^\.\w\-"'\(\)]/g, '_')
  }

  if (mimetype === TYPE_EPUB && info.agent.includes('Kindle') && ctx.request.body.kindlegen) {
    // convert to .mobi
    conversion = 'kindlegen'
    const outname = uploadedFile.path.replace(/\.epub$/i, '.mobi')
    filename = filename.replace(/\.kepub\.epub$/i, '.epub').replace(/\.epub$/i, '.mobi')
    let stderr = ''

    let p = new Promise((resolve, reject) => {
      const kindlegen = spawn('kindlegen', [basename(uploadedFile.path), '-dont_append_source', '-c1', '-o', basename(outname)], {
        // stdio: 'inherit',
        cwd: dirname(uploadedFile.path)
      })
      const timer = setTimeout(() => {
        kindlegen.kill('SIGKILL')
      }, conversionTimeout * 1000)
      kindlegen.once('error', function (err) {
        clearTimeout(timer)
        fs.unlink(uploadedFile.path, (err) => {
          if (err) console.error(err)
          else console.log('Removed file', uploadedFile.path)
        })
        fs.unlink(uploadedFile.path.replace(/\.epub$/i, '.mobi8'), (err) => {
          if (err) console.error(err)
          else console.log('Removed file', uploadedFile.path.replace(/\.epub$/i, '.mobi8'))
        })
        reject('kindlegen error: ' + err)
      })
      kindlegen.once('close', (code) => {
        clearTimeout(timer)
        fs.unlink(uploadedFile.path, (err) => {
          if (err) console.error(err)
          else console.log('Removed file', uploadedFile.path)
        })
        fs.unlink(uploadedFile.path.replace(/\.epub$/i, '.mobi8'), (err) => {
          if (err) console.error(err)
          else console.log('Removed file', uploadedFile.path.replace(/\.epub$/i, '.mobi8'))
        })
        if (code !== 0 && code !== 1) {
          reject('kindlegen error code: ' + code + '\n' + stderr)
          return
        }

        resolve(outname)
      })
      kindlegen.stdout.on('data', function (str) {
        stderr += str
        console.log('kindlegen: ' + str)
      })
      kindlegen.stderr.on('data', function (str) {
        stderr += str
        console.log('kindlegen: ' + str)
      })
    })
    try {
      data = await p
    } catch (err) {
      throw {
        message: err.replaceAll(basename(uploadedFile.path), "infile.epub").replaceAll(basename(outname), "outfile.mobi"),
        cleanup: [outname]
      }
    }

  } else if (mimetype === TYPE_EPUB && info.agent.includes('Kobo') && ctx.request.body.kepubify) {
    // convert to Kobo EPUB
    conversion = 'kepubify'
    const outname = uploadedFile.path.replace(/\.epub$/i, '.kepub.epub')
    filename = filename.replace(/\.kepub\.epub$/i, '.epub').replace(/\.epub$/i, '.kepub.epub')

    let p = new Promise((resolve, reject) => {
      let stderr = ''
      const kepubify = spawn('kepubify', ['-v', '-u', '-o', basename(outname), basename(uploadedFile.path)], {
        //stdio: 'inherit',
        cwd: dirname(uploadedFile.path)
      })
      const timer = setTimeout(() => {
        kepubify.kill('SIGKILL')
      }, conversionTimeout * 1000)
      kepubify.once('error', function (err) {
        clearTimeout(timer)
        fs.unlink(uploadedFile.path, (err) => {
          if (err) console.error(err)
          else console.log('Removed file', uploadedFile.path)
        })
        reject('kepubify error: ' + err)
      })
      kepubify.once('close', (code) => {
        clearTimeout(timer)
        fs.unlink(uploadedFile.path, (err) => {
          if (err) console.error(err)
          else console.log('Removed file', uploadedFile.path)
        })
        if (code !== 0) {
          reject('Kepubify error code: ' + code + '\n' + stderr)
          return
        }

        resolve(outname)
      })
      kepubify.stdout.on('data', function (str) {
        stderr += str
        console.log('kepubify: ' + str)
      })
      kepubify.stderr.on('data', function (str) {
        stderr += str
        console.log('kepubify: ' + str)
      })
    })
    try {
      data = await p
    } catch (err) {
      throw {
        message: err.replaceAll(basename(uploadedFile.path), "infile.epub").replaceAll(basename(outname), "outfile.kepub.epub"),
        cleanup: [outname]
      }
    }

  } else {
    // No conversion
    data = uploadedFile.path
    filename = filename.replace(/\.epub$/i, '.epub').replace(/\.pdf$/i, '.pdf')
  }

  return {
    name: filename,
    path: data,
    size: fs.statSync(data).size,
    conversion: conversion,
    uploaded: new Date()
  }
}

async function uploadFile (ctx, next, options = {}) {
  if (!rateLimit(ctx, options.multiple ? 'secret-upload' : 'upload', uploadRateLimit)) return

  try {
    if (options.multiple) {
      await upload.array('file', secretMaxFiles)(ctx, () => {})
    } else {
      await upload.single('file')(ctx, () => {})
    }
  } catch (err) {
    flash(ctx, {
      message: err,
      success: false
    })
    // ctx.throw(400, err)
    // ctx.res.end(err)
    await next()
    return
  }

  ctx.res.writeContinue()

  const key = options.key || (ctx.request.body.key || '').toUpperCase()

  if (ctx.request.file) {
    logUploadMetadata('Uploaded file:', [ctx.request.file])
  } else if (ctx.request.files) {
    logUploadMetadata('Uploaded files:', ctx.request.files)
  }

  if (!ctx.keys.has(key)) {
    flash(ctx, {
      message: options.key ? 'No secret receiver is connected' : 'Unknown key ' + key,
      success: false
    })
    removeFiles((ctx.request.files || []).map((file) => {
      return {path: file.path}
    }).concat(ctx.request.file ? [{path: ctx.request.file.path}] : []))
    await next()
    return
  }

  const info = ctx.keys.get(key)
  expireKey(key)

  let url = null
  if (ctx.request.body.url) {
    url = validateUrl(ctx.request.body.url.trim())
    if (ctx.request.body.url.trim().length > 0 && !url) {
      removeFiles((ctx.request.files || []).map((file) => {
        return {path: file.path}
      }).concat(ctx.request.file ? [{path: ctx.request.file.path}] : []))
      flash(ctx, {
        message: 'Invalid URL. Only http and https URLs are allowed.',
        success: false,
        key: key
      })
      await next()
      return
    }
    if (url && !info.urls.includes(url)) {
      if (info.urls.length >= maxUrlsPerKey) {
        removeFiles((ctx.request.files || []).map((file) => {
          return {path: file.path}
        }).concat(ctx.request.file ? [{path: ctx.request.file.path}] : []))
        flash(ctx, {
          message: 'Too many URLs stored for this key.',
          success: false,
          key: key
        })
        await next()
        return
      }
      info.urls.push(url)
    }
  }

  const uploadedFiles = options.multiple ? (ctx.request.files || []) : (ctx.request.file ? [ctx.request.file] : [])
  const processedFiles = []

  if (options.multiple) {
    const currentFiles = info.files || (info.file ? [info.file] : [])
    if (currentFiles.length + uploadedFiles.length > secretMaxFiles) {
      removeFiles(uploadedFiles.map((file) => {
        return {path: file.path}
      }))
      flash(ctx, {
        message: 'Secret uploads can store up to ' + secretMaxFiles + ' files. Remove or wait for existing files to expire before adding more.',
        success: false,
        key: key
      })
      await next()
      return
    }
  }

  for (const uploadedFile of uploadedFiles) {
    try {
      const processedFile = await processUploadedFile(ctx, info, uploadedFile)
      processedFile.name = uniqueFilename(processedFile.name, (options.multiple ? (info.files || []) : []).concat(processedFiles))
      processedFiles.push(processedFile)
    } catch (err) {
      removeFiles(processedFiles.concat((ctx.request.files || []).map((file) => {
        return {path: file.path}
      })).concat(ctx.request.file ? [{path: ctx.request.file.path}] : []).concat((err.cleanup || []).map((path) => {
        return {path: path}
      })))
      flash(ctx, {
        message: err.message || err,
        success: false,
        key: key
      })
      await next()
      return
    }
  }

  if (processedFiles.length > 0) {
    expireKey(key)
    const replacedFiles = options.multiple ? [] : (info.files || (info.file ? [info.file] : []))
    const replacedBytes = trackedBytes(replacedFiles)
    const newBytes = trackedBytes(processedFiles)
    if (app.context.storedBytes - replacedBytes + newBytes > maxStoredBytes) {
      removeFiles(processedFiles)
      flash(ctx, {
        message: 'Server storage limit reached. Please try again later.',
        success: false,
        key: key
      })
      await next()
      return
    }
    if (!options.multiple) {
      removeFiles(replacedFiles, {
        tracked: true
      })
    }
    const nextFiles = (options.multiple ? (info.files || (info.file ? [info.file] : [])) : []).concat(processedFiles)
    info.files = nextFiles.map((file) => {
      return {
        name: file.name,
        path: file.path,
        size: file.size,
        uploaded: file.uploaded
      }
    })
    info.file = info.files[0]
    app.context.storedBytes += newBytes
  }

  let messages = []
  if (processedFiles.length > 0) {
    uploadedFiles.forEach((file) => {
      file.skip = true
    })
    messages.push('Upload successful! ' + (processedFiles.length > 1 ? processedFiles.length + ' files were sent' : (processedFiles[0].conversion ? 'Ebook was converted with ' + processedFiles[0].conversion + ' and sent' : 'Sent'))+' to '+(info.agent.includes('Kobo') ? 'a Kobo device.' : (info.agent.includes('Kindle') ? 'a Kindle device.' : 'a device.')))
    processedFiles.forEach((file) => {
      messages.push('Filename: ' + file.name)
    })
  }
  if (url) {
    messages.push("Added url: " + url)
  }

  if (messages.length === 0) {
    flash(ctx, {
      message: 'No file or url selected',
      success: false,
      key: key
    })
    await next()
    return
  }

  flash(ctx, {
    message: messages.join("\n"),
    success: true,
    key: key,
    url: url
  })

  await next()
}

router.post('/upload', async (ctx, next) => {
  await uploadFile(ctx, next)
})

if (secretUploadRoute) {
  router.post(secretUploadRoute + '/upload', async (ctx, next) => {
    if (!requireSecretUploadAuth(ctx)) return
    ensureSecretInfo(ctx)
    await uploadFile(ctx, next, {
      key: secretKey,
      multiple: true
    })
  })
}

router.delete('/file/:key', async ctx => {
  const key = ctx.params.key.toUpperCase()
  const info = ctx.keys.get(key)
  if (!info) {
    ctx.throw(400, 'Unknown key: ' + key)
  }
  removeFiles(info.files || (info.file ? [info.file] : []), {
    tracked: true
  })
  info.file = null
  info.files = []
  ctx.body = 'ok'
})

router.get('/status/:key', async ctx => {
  const key = ctx.params.key.toUpperCase()
  const info = ctx.keys.get(key)
  if (!info) {
    ctx.response.status = 404
    ctx.body = {error: 'Unknown key'}
    return
  }
  if (info.agent !== ctx.get('user-agent')) {
    // don't send this error to client
    console.error("User Agent doesnt match: " + info.agent + " VS " + ctx.get('user-agent'))
    return
  }
  expireKey(key)
  // ctx.cookies.set('key', key, {overwrite: true, httpOnly: false, sameSite: 'strict', maxAge: expireDelay * 1000})
  ctx.body = {
    alive: info.alive,
    file: info.file ? {
      name: info.file.name,
      // size: info.file.size
    } : null,
    files: (info.files || []).map((file) => {
      return {
        name: file.name
      }
    }),
    urls: info.urls
  }
})

if (secretReceiveRoute) {
  router.get(secretReceiveRoute + '/status', async ctx => {
    const info = ctx.keys.get(secretKey)
    if (!info) {
      ctx.response.status = 404
      ctx.body = {error: 'No secret receiver'}
      return
    }
    if (info.agent !== ctx.get('user-agent')) {
      console.error("User Agent doesnt match: " + info.agent + " VS " + ctx.get('user-agent'))
      return
    }
    expireKey(secretKey)
    ctx.body = {
      alive: info.alive,
      file: info.file ? {
        name: info.file.name
      } : null,
      files: (info.files || []).map((file) => {
        return {
          name: file.name
        }
      }),
      urls: info.urls
    }
  })
}

router.get('/receive', async ctx => {
  await sendfile(ctx, 'static/download.html')
})

if (secretUploadRoute) {
  router.get(secretUploadRoute, async ctx => {
    if (!requireSecretUploadAuth(ctx)) return
    await sendfile(ctx, 'static/upload.html')
  })
}

if (secretReceiveRoute) {
  router.get(secretReceiveRoute, async ctx => {
    await sendfile(ctx, 'static/download.html')
  })

  router.get(secretReceiveRoute + '/:filename', async (ctx, next) => {
    await downloadFile(ctx, next, {
      key: secretKey
    })
  })
}

router.get('/', async ctx => {
  const agent = ctx.get('user-agent')
  console.log(ctx.ip, agent)
  await sendfile(ctx, agent.includes('Kobo') || agent.includes('Kindle') || agent.toLowerCase().includes('tolino') || agent.includes('eReader') /*"eReader" is on Tolino*/ ? 'static/download.html' : 'static/upload.html')
})

router.get('/:filename', downloadFile)

app.use(serve("static"))

app.use(router.routes())
app.use(router.allowedMethods())


fs.rm('uploads', {recursive: true}, (err) => {
  if (err) throw err
  mkdirp('uploads').then (() => {
    // app.listen(port)
    const fn = app.callback()
    const server = http.createServer(fn)
    server.on('checkContinue', (req, res) => {
      console.log("check continue!")
      fn(req, res)
    })
    server.listen(port)
    console.log('server is listening on port ' + port)
  })
})
