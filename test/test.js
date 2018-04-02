const restrictIp = require('../index')
const request = require('supertest')
const express = require('express')

const app = express()

const server = app.listen()

let whitelist = ['2.2.2.2', '3.3.3.3']
let blacklist = ['4.4.4.4']

const whitelistRestrict = restrictIp({
  whitelist: new Set(whitelist)
})

const whitelistAllowPrivateRestrict = restrictIp({
  allowPrivate: true,
  whitelist: new Set(whitelist)
})

const blacklistRestrict = restrictIp({
  blacklist: new Set(blacklist)
})

const customHandlerRestrict = restrictIp({
  blacklist: new Set(blacklist),
  onRestrict: async (req, res, next) => {
    if(req.query.hasPassport){
      next()
    }
    else{
      res.status(403).send('custom')
    }
  }
})

const defaultTrustedHeaderSequenceRestrict = restrictIp({
  blacklist: new Set(blacklist)
})

const customTrustedHeaderSequenceRestrict = restrictIp({
  blacklist: new Set(blacklist),
  trustedHeaderSequence: ['x-real-ip', 'x-forwarded-for']
})

const noTrustedHeaderSequenceRestrict = restrictIp({
  blacklist: new Set(blacklist),
  trustedHeaderSequence: []
})

function passed(req, res, next) {
  res.send('passed')
}

app.get('/', whitelistRestrict, passed)
app.get('/1', whitelistAllowPrivateRestrict, passed)
app.get('/2', blacklistRestrict, passed)
app.get('/3', customHandlerRestrict, passed)
app.get('/4', defaultTrustedHeaderSequenceRestrict, passed)
app.get('/5', customTrustedHeaderSequenceRestrict, passed)
app.get('/6', noTrustedHeaderSequenceRestrict, passed)

// 错误处理中间件
app.use(function (err, req, res, next) {
  if(err.message === 'IP restricted'){
    res.status(403).send(err.message + ': ' + err.ip)
  }
  else{
    res.status(500).json(err)
  }
})

describe('白名单外网地址', function () {
  it('在白名单，通过', async function () {
    let fakeIp = '2.2.2.2'
    await request(server)
      .get('/')
      .set('x-real-ip', fakeIp)
      .expect(200)
  })
  it('不在白名单，拦截', async function () {
    let fakeIp = '9.9.9.9'
    await request(server)
      .get('/')
      .set('x-real-ip', fakeIp)
      .expect(403)
  })
})

describe('白名单且允许内网地址', function () {
  it('不在白名单，但是本机地址 通过', async function () {
    await request(server)
      .get('/1')
      .expect(200)
  })
  it('不在白名单，但是是 A 类内网地址 通过', async function () {
    let fakeIp = '10.0.0.2'
    await request(server)
      .get('/1')
      .set('x-real-ip', fakeIp)
      .expect(200)
  })
  it('不在白名单，但是是 B 类内网地址 通过', async function () {
    let fakeIp = '172.16.0.2'
    await request(server)
      .get('/1')
      .set('x-real-ip', fakeIp)
      .expect(200)
  })
  it('不在白名单，但是是 C 类内网地址 通过', async function () {
    let fakeIp = '192.168.0.2'
    await request(server)
      .get('/1')
      .set('x-real-ip', fakeIp)
      .expect(200)
  })
  it('不在白名单，也不是内网地址 拦截', async function () {
    let fakeIp = '9.9.9.9'
    await request(server)
      .get('/1')
      .set('x-real-ip', fakeIp)
      .expect(403)
  })
})

describe('黑名单策略', function () {
  it('不在黑名单 通过', async function () {
    await request(server)
      .get('/2')
      .expect(200)
  })
  it('在黑名单 拦截', async function () {
    let fakeIp = '4.4.4.4'
    await request(server)
      .get('/2')
      .set('x-real-ip', fakeIp)
      .expect(403)
  })
})

describe('自定义函数拦截', function () {
  it('自定义拦截函数 通过', async function () {
    let fakeIp = '4.4.4.4'
    await request(server)
      .get('/3?hasPassport=1')
      .set('x-real-ip', fakeIp)
      .expect(200)
  })
  it('自定义拦截函数 拦截', async function () {
    let fakeIp = '4.4.4.4'
    let a = await request(server)
      .get('/3')
      .set('x-real-ip', fakeIp)
      .expect(403)
  })
})

describe('trustedHeaderSequence', function () {
  it('trustedHeaderSequence 不指定，默认先 x-forwarded-for 后 x-real-ip', async function () {
    let fakeIp = '4.4.4.4'
    await request(server)
      .get('/4')
      .set('x-forwarded-for', fakeIp)
      .set('x-real-ip', '127.0.0.1')
      .expect(403)
  })

  it('trustedHeaderSequence 按指定顺序', async function () {
    let fakeIp = '4.4.4.4'
    await request(server)
      .get('/5')
      .set('x-forwarded-for', fakeIp)
      .set('x-real-ip', '127.0.0.1')
      .expect(200)
  })

  it('trustedHeaderSequence 为空数组，看直接 IP', async function () {
    let fakeIp = '4.4.4.4'
    await request(server)
      .get('/6')
      .set('x-forwarded-for', fakeIp)
      .set('x-real-ip', fakeIp)
      .expect(200)
  })
})
