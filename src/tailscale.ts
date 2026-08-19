import { spawn, type ChildProcess } from 'node:child_process'
import { join, resolve } from 'node:path'
import { tmpdir } from 'node:os'

/** Options for the bundled tsnet bridge process. */
export interface TailscaleBridgeOptions {
  /** Tailscale auth key; falls back to the TS_AUTHKEY environment variable. */
  readonly authKey?: string
  /** Tailnet device hostname. */
  readonly hostname: string
  /** Local dsh-mobile gateway origin the bridge forwards to. */
  readonly upstream: string
  /** Port the bridge listens on inside the tailnet. */
  readonly listenPort: number
  /** Where the bridge keeps its tailscale state (defaults to a temp dir). */
  readonly stateDir?: string
  /** Bridge executable path (defaults to the packaged bin/tsnet-bridge). */
  readonly binary?: string
}

/** Observable bridge state, mirroring the JSON lines emitted on stdout. */
export interface TailscaleBridgeStatus {
  readonly state: 'starting' | 'running' | 'error' | 'stopped'
  readonly ips?: readonly string[]
  readonly error?: string
}

interface BridgeLine {
  readonly event?: string
  readonly state?: string
  readonly ips?: readonly string[]
  readonly error?: string
}

/**
 * Spawns and supervises the tsnet bridge: it joins the tailnet and exposes
 * the local gateway origin inside it. Failing to start or a bridge exit only
 * degrades the tailnet path — the LAN gateway keeps working as before.
 */
export class TailscaleBridge {
  private process: ChildProcess | undefined
  private current: TailscaleBridgeStatus = { state: 'starting' }
  private readonly listeners = new Set<(status: TailscaleBridgeStatus) => void>()

  constructor(private readonly options: TailscaleBridgeOptions) {}

  start(): void {
    if (this.process !== undefined) return
    const binary = this.options.binary ?? resolve(import.meta.dirname, '..', 'bin', 'tsnet-bridge.exe')
    const stateDir = this.options.stateDir ?? join(tmpdir(), 'dsh-mobile-tailscale')
    const args = [
      '-hostname', this.options.hostname,
      '-upstream', this.options.upstream,
      '-listen', `:${String(this.options.listenPort)}`,
      '-state', stateDir,
    ]
    const env: NodeJS.ProcessEnv = { ...process.env }
    if (this.options.authKey !== undefined) env.TS_AUTHKEY = this.options.authKey
    const child = spawn(binary, args, { env, stdio: ['ignore', 'pipe', 'pipe'] })
    this.process = child

    let buffer = ''
    child.stdout?.on('data', (chunk: Buffer) => {
      buffer += chunk.toString('utf8')
      let newline = buffer.indexOf('\n')
      while (newline >= 0) {
        const line = buffer.slice(0, newline).trim()
        buffer = buffer.slice(newline + 1)
        if (line !== '') this.handleLine(line)
        newline = buffer.indexOf('\n')
      }
    })
    child.stderr?.on('data', (chunk: Buffer) => {
      const text = chunk.toString('utf8').trimEnd()
      if (text !== '') {
        process.emitWarning(`DSH Mobile tailscale bridge: ${text}`, { code: 'DSH_MOBILE_TAILSCALE' })
      }
    })
    child.on('error', (error) => {
      this.update({ state: 'error', error: `bridge failed to start: ${error.message}` })
    })
    child.on('exit', (code, signal) => {
      if (this.process === child) {
        this.process = undefined
        this.update(code === 0
          ? { state: 'stopped' }
          : { state: 'stopped', error: `bridge exited (code ${String(code)}, signal ${String(signal)})` })
      }
    })
  }

  private handleLine(line: string): void {
    let parsed: BridgeLine
    try {
      parsed = JSON.parse(line) as BridgeLine
    } catch {
      return
    }
    if (parsed.event === 'running') {
      this.update(parsed.ips === undefined ? { state: 'running' } : { state: 'running', ips: parsed.ips })
    } else if (parsed.event === 'error') {
      this.update(parsed.error === undefined ? { state: 'error' } : { state: 'error', error: parsed.error })
    }
  }

  private update(next: TailscaleBridgeStatus): void {
    this.current = next
    for (const listener of this.listeners) listener(next)
  }

  /** Subscribe to status changes; the current status is delivered immediately. */
  onStatus(listener: (status: TailscaleBridgeStatus) => void): () => void {
    this.listeners.add(listener)
    listener(this.current)
    return () => { this.listeners.delete(listener) }
  }

  status(): TailscaleBridgeStatus {
    return this.current
  }

  /** Stop the bridge. Tailscale state persists, so a later start reuses it. */
  stop(): void {
    const child = this.process
    this.process = undefined
    if (child !== undefined) child.kill()
  }
}
