/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import dns from 'node:dns'
import net from 'node:net'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function isPrivateIp (ip: string): boolean {
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number)
    if (parts.length !== 4 || parts.some(isNaN)) {
      return true
    }
    const [o1, o2, o3, o4] = parts
    if (o1 === 127) return true
    if (o1 === 10) return true
    if (o1 === 172 && (o2 >= 16 && o2 <= 31)) return true
    if (o1 === 192 && o2 === 168) return true
    if (o1 === 169 && o2 === 254) return true
    if (o1 === 0) return true
    if (o1 === 100 && (o2 >= 64 && o2 <= 127)) return true
    if (o1 >= 224) return true
    return false
  } else if (net.isIPv6(ip)) {
    const cleanIp = ip.toLowerCase().trim()
    if (cleanIp === '::1' || cleanIp === '::' || /^0*:[0*:]*0*1$/.test(cleanIp) || /^0*:[0*:]*0*$/.test(cleanIp)) {
      return true
    }
    if (cleanIp.startsWith('fe8') || cleanIp.startsWith('fe9') || cleanIp.startsWith('fea') || cleanIp.startsWith('feb')) {
      return true
    }
    if (cleanIp.startsWith('fc') || cleanIp.startsWith('fd')) {
      return true
    }
    if (cleanIp.startsWith('ff')) {
      return true
    }
    if (cleanIp.includes('.')) {
      const lastPart = cleanIp.split(':').pop()
      if (lastPart && net.isIPv4(lastPart)) {
        return isPrivateIp(lastPart)
      }
    }
    return false
  }
  return true
}

function isPrivateOrLocalHost (hostname: string): boolean {
  const host = hostname.toLowerCase().trim()
  if (host === 'localhost' || host === 'localhost.localdomain' || host.endsWith('.local')) {
    return true
  }
  return false
}

async function resolveIp (hostname: string): Promise<string[]> {
  return new Promise((resolve) => {
    dns.lookup(hostname, { all: true }, (err: Error | null, addresses: dns.LookupAddress[] | undefined) => {
      if (err || !addresses) {
        resolve([])
      } else {
        resolve(addresses.map((addr: dns.LookupAddress) => addr.address))
      }
    })
  })
}

async function isSafeUrl (urlString: string): Promise<boolean> {
  try {
    const parsedUrl = new URL(urlString)
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      return false
    }
    const hostname = parsedUrl.hostname
    if (isPrivateOrLocalHost(hostname) || isPrivateIp(hostname)) {
      return false
    }
    const ips = await resolveIp(hostname)
    for (const ip of ips) {
      if (isPrivateIp(ip)) {
        return false
      }
    }
    return true
  } catch {
    return false
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        if (!(await isSafeUrl(url))) {
          next(new Error('Blocked illegal activity: Unsafe URL'))
          return
        }
        try {
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
