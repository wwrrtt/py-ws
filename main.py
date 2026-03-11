import os, sys, asyncio, struct, base64, logging, socket, ipaddress
import aiohttp
from aiohttp import web
from dataclasses import dataclass, field
from typing import Optional

# ── 配置 ─────────────────────────────────────────────────────────────────────

@dataclass
class Config:
    uuid:     str = field(default_factory=lambda: os.environ.get('UUID', 'ee1feada-4e2f-4dc3-aaa6-f97aeed0286b'))
    domain:   str = field(default_factory=lambda: os.environ.get('DOMAIN', 'xxx.xxx.xxx'))
    sub_path: str = field(default_factory=lambda: os.environ.get('SUB_PATH', 'sub'))
    name:     str = field(default_factory=lambda: os.environ.get('NAME', 'VLESS'))
    ws_path:  str = field(default_factory=lambda: os.environ.get('WSPATH', 'VL-WS'))
    port:     int = field(default_factory=lambda: int(os.environ.get('SERVER_PORT') or os.environ.get('PORT') or 3000))
    debug:    bool = field(default_factory=lambda: os.environ.get('DEBUG', '').lower() == 'true')

    def __post_init__(self):
        if not self.ws_path:
            self.ws_path = self.uuid[:8]

cfg = Config()

BLOCKED_DOMAINS = {
    'speedtest.net', 'fast.com', 'speedtest.cn', 'speed.cloudflare.com',
    'speedof.me', 'testmy.net', 'bandwidth.place', 'speed.io',
    'librespeed.org', 'speedcheck.org',
}

# ── 日志 ─────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.DEBUG if cfg.debug else logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
)
for _n in ['aiohttp.access', 'aiohttp.server', 'aiohttp.client', 'aiohttp.websocket']:
    logging.getLogger(_n).setLevel(logging.WARNING)

log = logging.getLogger(__name__)

# ── 节点信息（启动时初始化一次）────────────────────────────────────────────

@dataclass
class NodeInfo:
    domain: str = ''
    port:   int = 443
    tls:    str = 'tls'
    isp:    str = 'Unknown'

node = NodeInfo()

async def init_node_info(session: aiohttp.ClientSession) -> None:
    """启动时获取一次公网 IP / ISP，之后缓存复用。"""
    # ISP
    try:
        async with session.get(
            'https://api.ip.sb/geoip',
            headers={'User-Agent': 'Mozilla/5.0'}, timeout=aiohttp.ClientTimeout(total=5)
        ) as r:
            if r.status == 200:
                d = await r.json()
                node.isp = f"{d.get('country_code','')}-{d.get('isp','')}".replace(' ', '_')
    except Exception as e:
        log.warning(f'ISP 获取失败: {e}')

    # Domain / IP
    if cfg.domain and cfg.domain != 'your-domain.com':
        node.domain, node.tls, node.port = cfg.domain, 'tls', 443
    else:
        try:
            async with session.get(
                'https://api-ipv4.ip.sb/ip', timeout=aiohttp.ClientTimeout(total=5)
            ) as r:
                if r.status == 200:
                    node.domain = (await r.text()).strip()
                    node.tls, node.port = 'none', cfg.port
        except Exception as e:
            log.error(f'公网 IP 获取失败: {e}')
            node.domain = 'change-your-domain.com'

# ── 工具函数 ─────────────────────────────────────────────────────────────────

def find_free_port(start: int, attempts: int = 100) -> Optional[int]:
    for p in range(start, start + attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('0.0.0.0', p))
                return p
            except OSError:
                continue
    return None

def is_blocked(host: str) -> bool:
    h = host.lower()
    return any(h == b or h.endswith('.' + b) for b in BLOCKED_DOMAINS)

async def resolve(session: aiohttp.ClientSession, host: str) -> str:
    """将域名解析为 IP；若已是 IP 则直接返回。"""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        async with session.get(
            f'https://dns.google/resolve?name={host}&type=A',
            timeout=aiohttp.ClientTimeout(total=5)
        ) as r:
            if r.status == 200:
                data = await r.json()
                for ans in data.get('Answer', []):
                    if ans.get('type') == 1:
                        return ans['data']
    except Exception:
        pass
    return host  # 解析失败则返回原域名，让系统 DNS 兜底

# ── VLESS 协议解析 ────────────────────────────────────────────────────────────

UUID_BYTES = bytes.fromhex(cfg.uuid.replace('-', ''))

def parse_vless_header(data: bytes) -> Optional[tuple[str, int, int]]:
    """
    解析 VLESS 请求头，返回 (host, port, payload_offset)。
    若解析失败返回 None。
    """
    if len(data) < 18 or data[0] != 0:
        return None
    if data[1:17] != UUID_BYTES:
        return None

    i = data[17] + 19          # 跳过附加信息
    if i + 3 > len(data):
        return None

    port = struct.unpack('!H', data[i:i+2])[0]
    i += 2
    atyp = data[i]; i += 1

    if atyp == 1:               # IPv4
        if i + 4 > len(data): return None
        host = '.'.join(str(b) for b in data[i:i+4]); i += 4
    elif atyp == 2:             # 域名
        if i >= len(data): return None
        n = data[i]; i += 1
        if i + n > len(data): return None
        host = data[i:i+n].decode(); i += n
    elif atyp == 3:             # IPv6
        if i + 16 > len(data): return None
        host = ':'.join(f'{(data[j]<<8)|data[j+1]:04x}' for j in range(i, i+16, 2)); i += 16
    else:
        return None

    return host, port, i

# ── WebSocket ↔ TCP 双向转发 ────────────────────────────────────────────────

async def pipe_ws_to_tcp(ws: web.WebSocketResponse, writer: asyncio.StreamWriter):
    try:
        async for msg in ws:
            if msg.type == aiohttp.WSMsgType.BINARY:
                writer.write(msg.data)
                await writer.drain()
    finally:
        writer.close()
        try: await writer.wait_closed()
        except Exception: pass

async def pipe_tcp_to_ws(reader: asyncio.StreamReader, ws: web.WebSocketResponse):
    try:
        while chunk := await reader.read(4096):
            await ws.send_bytes(chunk)
    except Exception:
        pass

# ── 路由处理 ─────────────────────────────────────────────────────────────────

async def handle_ws(request: web.Request) -> web.WebSocketResponse:
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    session: aiohttp.ClientSession = request.app['session']

    try:
        msg = await asyncio.wait_for(ws.receive(), timeout=5)
    except asyncio.TimeoutError:
        await ws.close(); return ws

    if msg.type != aiohttp.WSMsgType.BINARY:
        await ws.close(); return ws

    parsed = parse_vless_header(msg.data)
    if not parsed:
        await ws.close(); return ws

    host, port, offset = parsed
    if is_blocked(host):
        log.warning(f'已屏蔽域名: {host}')
        await ws.close(); return ws

    # 响应客户端：连接成功
    await ws.send_bytes(b'\x00\x00')

    target = await resolve(session, host)
    try:
        reader, writer = await asyncio.open_connection(target, port)
    except Exception as e:
        log.error(f'连接 {host}:{port} 失败: {e}')
        await ws.close(); return ws

    # 将第一帧中剩余的有效载荷先发给目标
    if offset < len(msg.data):
        writer.write(msg.data[offset:])
        await writer.drain()

    await asyncio.gather(
        pipe_ws_to_tcp(ws, writer),
        pipe_tcp_to_ws(reader, ws),
    )

    if not ws.closed:
        await ws.close()
    return ws


async def handle_http(request: web.Request) -> web.Response:
    path = request.path

    if path == '/':
        try:
            html = open('index.html', encoding='utf-8').read()
            return web.Response(text=html, content_type='text/html')
        except FileNotFoundError:
            return web.Response(text='Hello World')

    if path == f'/{cfg.sub_path}':
        label = f"{cfg.name}-{node.isp}" if cfg.name else node.isp
        sec   = 'tls' if node.tls == 'tls' else 'none'
        url   = (
            f"vless://{cfg.uuid}@{node.domain}:{node.port}"
            f"?encryption=none&security={sec}&sni={node.domain}"
            f"&fp=chrome&type=ws&host={node.domain}&path=%2F{cfg.ws_path}#{label}"
        )
        return web.Response(
            text=base64.b64encode(url.encode()).decode() + '\n',
            content_type='text/plain',
        )

    return web.Response(status=404, text='404 Not Found\n')

# ── 应用生命周期 ──────────────────────────────────────────────────────────────

async def on_startup(app: web.Application):
    session = aiohttp.ClientSession()
    app['session'] = session
    await init_node_info(session)

async def on_cleanup(app: web.Application):
    await app['session'].close()

# ── 主入口 ────────────────────────────────────────────────────────────────────

async def main():
    port = find_free_port(cfg.port)
    if port is None:
        log.error('没有可用端口，退出')
        sys.exit(1)
    if port != cfg.port:
        log.warning(f'端口 {cfg.port} 已占用，改用 {port}')

    app = web.Application()
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)

    app.router.add_get('/',               handle_http)
    app.router.add_get(f'/{cfg.sub_path}', handle_http)
    app.router.add_get(f'/{cfg.ws_path}', handle_ws)

    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, '0.0.0.0', port).start()

    log.info(f"✅ Server 运行中 → port={port}")

    try:
        await asyncio.Future()          # 永久阻塞
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await runner.cleanup()


if __name__ == '__main__':
    asyncio.run(main())
