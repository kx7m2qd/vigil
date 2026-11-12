import fs from "fs"
import fetch from "node-fetch"
import { pipeline } from "stream"
import { promisify } from "util"

export async function uploadUrl(url: string) {
  // ruleid: js-ssrf-url-download
  const res = await fetch(url)
  const fileStream = fs.createWriteStream("/tmp/x", { flags: "wx" })
  await promisify(pipeline)(res.body, fileStream)
}

export async function uploadUrlSafe(url: string) {
  // ok: js-ssrf-url-download
  const res = await utils.fetchWithBlacklist(url)
  const fileStream = fs.createWriteStream("/tmp/x", { flags: "wx" })
  await promisify(pipeline)(res.body, fileStream)
}

export const saveAvatar = async (userId: string, avatarUrl: string) => {
  // ruleid: js-ssrf-url-download
  const r = await fetch(avatarUrl)
  await fs.promises.writeFile(`/avatars/${userId}`, Buffer.from(await r.arrayBuffer()))
}

class Importer {
  async import(src: string) {
    // ruleid: js-ssrf-url-download
    const resp = await axios.get(src, { responseType: "arraybuffer" })
    fs.writeFileSync("/data/import.bin", resp.data)
  }
}

export async function getJson(url: string) {
  // ok: js-ssrf-url-download
  const res = await fetch(url)
  return res.json()
}

export async function apiGet(path: string) {
  // ok: js-ssrf-url-download
  const res = await fetch(`https://api.example.com/${path}`)
  fs.writeFileSync("/tmp/cache.json", await res.text())
}

export async function mirror(url: string, dest: string) {
  // ruleid: js-ssrf-url-download
  const res = await fetch(url)
  res.body.pipe(fs.createWriteStream(dest))
}
