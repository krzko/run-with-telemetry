const childProcess = require('child_process')
const os = require('os')
const process = require('process')

function chooseBinary() {
    const platform = os.platform()
    const arch = os.arch()

    if (platform === 'darwin' && arch === 'x64') {
        return `bin/run-with-telemetry-darwin-amd64`
    }
    if (platform === 'darwin' && arch === 'arm64') {
        return `bin/run-with-telemetry-darwin-arm64`
    }
    if (platform === 'linux' && arch === 'x64') {
        return `bin/run-with-telemetry-linux-amd64`
    }
    if (platform === 'linux' && arch === 'arm64') {
        return `bin/run-with-telemetry-linux-armv8`
    }
    if (platform === 'win32' && arch === 'x64') {
        return `bin/run-with-telemetry-windows-amd64.exe`
    }
    if (platform === 'win32' && arch === 'arm64') {
        return `bin/run-with-telemetry-windows-arm64.exe`
    }

    console.error(`Unsupported platform (${platform}) and architecture (${arch})`)
    process.exit(1)
}

function main() {
    const binary = chooseBinary()
    const mainScript = `${__dirname}/${binary}`
    const spawnSyncReturns = childProcess.spawnSync(mainScript, { stdio: 'inherit' })
    const status = spawnSyncReturns.status
    if (typeof status === 'number') {
        process.exit(status)
    }
    process.exit(1)
}

if (require.main === module) {
    main()
}
