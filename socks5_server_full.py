import asyncio
import socket
import select
import struct
import logging
import hashlib
import os
from dotenv import load_dotenv  # python-dotenv 라이브러리 import

# 로깅 설정 (이전과 동일)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# SOCKS5 응답 코드 정의 (이전과 동일)
SOCKS5_REPLY_SUCCEEDED = 0x00
SOCKS5_REPLY_GENERAL_FAILURE = 0x01
SOCKS5_REPLY_CONNECTION_REFUSED = 0x05
SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED = 0x08
SOCKS5_REPLY_COMMAND_NOT_SUPPORTED = 0x07
SOCKS5_REPLY_AUTH_FAILURE = 0x05

# 사용자 정보 (환경 변수에서 로드)
USER_CREDENTIALS = {}

async def handle_client(reader, writer):
    """클라이언트 연결 처리 비동기 함수 (환경 변수 사용자 정보)"""
    client_address = writer.get_extra_info('peername')
    logging.info(f"[{client_address}] 연결됨")
    authenticated = False

    try:
        # 1. 핸드셰이크 (이전과 동일)
        version = await reader.read(1)
        if version != b'\x05':
            return

        methods_count = await reader.read(1)
        methods = await reader.read(methods_count[0])

        # 인증 방식 협상 (이전과 동일)
        if b'\x02' in methods and USER_CREDENTIALS: # 사용자 정보가 있는 경우만 인증 시도
            writer.write(b'\x05\x02')
            await writer.drain()

            # 2. 인증 단계 (Method 0x02)
            authenticated = await authenticate_user(reader, writer, client_address)
            if not authenticated:
                return

        elif b'\x00' in methods or not USER_CREDENTIALS: # 인증 없거나 사용자 정보 없으면 인증 없이 진행
            writer.write(b'\x05\x00')
            await writer.drain()
            authenticated = True
            if not USER_CREDENTIALS:
                logging.warning("사용자 정보가 없어 인증 없이 접속 허용")

        else: # 지원하는 인증 방식 없음
            writer.write(b'\x05\xFF')
            await writer.drain()
            logging.warning(f"[{client_address}] 지원하는 인증 방식 없음")
            return

        if authenticated:
            # 3. 요청 (이전과 동일)
            version_cmd = await reader.read(2)
            if version_cmd[0] != 0x05:
                return

            cmd = version_cmd[1]
            address_type = await reader.read(1)

            # ... (주소 타입 및 목적지 정보 처리 - 이전과 동일) ...
            if address_type[0] == 0x01:  # IPv4
                dest_addr_bytes = await reader.read(4)
                dest_addr = socket.inet_ntoa(dest_addr_bytes)
            elif address_type[0] == 0x03:  # Domain
                domain_length = await reader.read(1)
                dest_addr = (await reader.read(domain_length[0])).decode('utf-8')
            elif address_type[0] == 0x04:  # IPv6 (구현 생략)
                writer.write(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00')
                await writer.drain()
                return
            else:
                writer.write(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00')
                await writer.drain()
                return

            dest_port_bytes = await reader.read(2)
            dest_port = int.from_bytes(dest_port_bytes, 'big')

            # CMD 처리 분기 (이전과 동일)
            if cmd == 0x01: # CONNECT
                await handle_connect_cmd(reader, writer, client_address, dest_addr, dest_port)
            elif cmd == 0x02: # BIND
                await handle_bind_cmd(reader, writer, client_address, dest_addr, dest_port)
            elif cmd == 0x03: # UDP ASSOCIATE
                await handle_udp_associate_cmd(reader, writer, client_address, dest_addr, dest_port)
            else:
                writer.write(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
                await writer.drain()
                logging.warning(f"[{client_address}] 지원되지 않는 CMD: {cmd}")

    except Exception as e:
        logging.error(f"[{client_address}] 클라이언트 처리 중 오류 발생: {e}")
    finally:
        logging.info(f"[{client_address}] 연결 종료")
        writer.close()
        await writer.wait_closed()


async def authenticate_user(reader, writer, client_address):
    """사용자 인증 처리 비동기 함수 (Method 0x02) (이전과 동일)"""
    try:
        version = await reader.read(1)
        if version != b'\x01':
            writer.write(b'\x05\x01')
            await writer.drain()
            logging.warning(f"[{client_address}] 잘못된 인증 프로토콜 버전: {version}")
            return False

        username_len = await reader.read(1)
        username = (await reader.read(username_len[0])).decode('utf-8')

        password_len = await reader.read(1)
        password = (await reader.read(password_len[0])).decode('utf-8')

        # 사용자 인증 (환경 변수에서 로드된 USER_CREDENTIALS 사용)
        if username in USER_CREDENTIALS and USER_CREDENTIALS[username] == password: # 평문 비밀번호 비교 - 보안 취약
        # 실제 환경에서는 해시된 비밀번호 비교 (예시: hashlib.sha256(password.encode()).hexdigest() 비교)
            writer.write(b'\x01\x00')
            await writer.drain()
            logging.info(f"[{client_address}] 사용자 '{username}' 인증 성공")
            return True
        else:
            writer.write(b'\x01\x01')
            await writer.drain()
            logging.warning(f"[{client_address}] 사용자 '{username}' 인증 실패")
            return False

    except Exception as e:
        writer.write(b'\x05\x01')
        await writer.drain()
        logging.error(f"[{client_address}] 인증 오류: {e}")
        return False


async def handle_connect_cmd(reader, writer, client_address, dest_addr, dest_port):
    """CONNECT CMD 처리 비동기 함수 (이전과 동일)"""
    try:
        remote_reader, remote_writer = await asyncio.open_connection(dest_addr, dest_port)
        writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
        await writer.drain()

        logging.info(f"[{client_address}] CONNECT: {dest_addr}:{dest_port} 연결됨")
        await relay_data(reader, writer, remote_reader, remote_writer, client_address)

    except Exception as e:
        logging.error(f"[{client_address}] CONNECT: {dest_addr}:{dest_port} 연결 실패: {e}")
        writer.write(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')
        await writer.drain()


async def handle_bind_cmd(reader, writer, client_address, bind_addr, bind_port):
    """BIND CMD 처리 비동기 함수 (이전과 동일)"""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 0))
    server_socket.listen(1)
    bind_host, bind_port_actual = server_socket.getsockname()

    bind_addr_bytes = socket.inet_aton(get_local_ip())
    bind_port_bytes = bind_port_actual.to_bytes(2, 'big')
    response = b'\x05\x00\x00\x01' + bind_addr_bytes + bind_port_bytes
    writer.write(response)
    await writer.drain()

    logging.info(f"[{client_address}] BIND: 포트 {bind_port_actual} 대기 중")

    server_socket.settimeout(120)
    try:
        loop = asyncio.get_running_loop()
        remote_socket, remote_address = await loop.run_in_executor(None, server_socket.accept)
        server_socket.settimeout(None)

        remote_reader, remote_writer = await asyncio.open_connection(sock=remote_socket)

        logging.info(f"[{client_address}] BIND: {remote_address} 로부터 연결 수락")

        writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
        await writer.drain()

        await relay_data(reader, writer, remote_reader, remote_writer, client_address)

    except socket.timeout:
        logging.warning(f"[{client_address}] BIND: 연결 대기 시간 초과")
        writer.write(b'\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00')
        await writer.drain()
    except Exception as e:
        logging.error(f"[{client_address}] BIND: 오류 발생: {e}")
        writer.write(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
        await writer.drain()
    finally:
        server_socket.close()


async def handle_udp_associate_cmd(reader, writer, client_address, bind_addr, bind_port):
    """UDP ASSOCIATE CMD 처리 비동기 함수 (이전과 동일)"""
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(('0.0.0.0', 0))
    udp_host, udp_port_actual = udp_socket.getsockname()

    bind_addr_bytes = socket.inet_aton(get_local_ip())
    udp_port_bytes = udp_port_actual.to_bytes(2, 'big')
    response = b'\x05\x00\x00\x01' + bind_addr_bytes + udp_port_bytes
    writer.write(response)
    await writer.drain()

    logging.info(f"[{client_address}] UDP ASSOCIATE: UDP 포트 {udp_port_actual} 할당됨")

    asyncio.create_task(relay_udp_data(reader, writer, udp_socket, client_address))


async def relay_data(client_reader, client_writer, remote_reader, remote_writer, client_address):
    """TCP 데이터 릴레이 비동기 함수 (양방향) (이전과 동일)"""
    try:
        await asyncio.gather(
            copy_data(client_reader, remote_writer),
            copy_data(remote_reader, client_writer)
        )
    except Exception as e:
        logging.error(f"[{client_address}] TCP 릴레이 오류: {e}")
    finally:
        logging.info(f"[{client_address}] TCP 릴레이 종료")
        remote_writer.close()
        await remote_writer.wait_closed()
        client_writer.close()
        await client_writer.wait_closed()

async def copy_data(reader, writer):
    """데이터 복사 유틸리티 함수 (reader -> writer) (이전과 동일)"""
    try:
        while True:
            data = await reader.read(4096)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass

async def relay_udp_data(client_reader, client_writer, udp_socket, client_address):
    """UDP 데이터 릴레이 비동기 함수 (단편화 처리 포함) (이전과 동일)"""
    fragment_buffers = {}

    try:
        loop = asyncio.get_running_loop()
        while True:
            try:
                ready = await asyncio.wait_for(get_ready_sockets([client_reader, udp_socket], loop), timeout=1.0)
            except asyncio.TimeoutError:
                continue

            if client_reader in ready:
                try:
                    tcp_data = await client_reader.read(8192)
                    if not tcp_data:
                        break

                    if len(tcp_data) < 10:
                        continue

                    rsv, frag, addr_type = tcp_data[:3]
                    if rsv != 0x0000:
                        logging.warning(f"[{client_address}] 잘못된 RSV: {rsv}")
                        continue

                    frag_byte = frag

                    header_len = 0
                    dest_addr = None
                    dest_port = None
                    udp_payload = None

                    if addr_type == 0x01: # IPv4
                        header_len = 10
                        if len(tcp_data) < header_len:
                            continue
                        dest_addr_bytes = tcp_data[4:8]
                        dest_addr = socket.inet_ntoa(dest_addr_bytes)
                        dest_port = int.from_bytes(tcp_data[8:10], 'big')
                        udp_payload = tcp_data[header_len:]

                    elif addr_type == 0x03: # Domain
                        domain_len = tcp_data[4]
                        header_len = 7 + domain_len
                        if len(tcp_data) < header_len:
                            continue
                        dest_addr = tcp_data[5:5+domain_len].decode('utf-8')
                        dest_port = int.from_bytes(tcp_data[5+domain_len:header_len], 'big')
                        udp_payload = tcp_data[header_len:]
                    elif addr_type == 0x04: # IPv6 (미구현)
                        logging.warning(f"[{client_address}] IPv6 주소 타입은 지원하지 않음")
                        continue
                    else:
                        logging.warning(f"[{client_address}] 알 수 없는 주소 타입: {addr_type}")
                        continue

                    if header_len > 0:
                        if frag_byte == 0x00:
                            await loop.sock_sendto(udp_socket, udp_payload, (dest_addr, dest_port))
                        else:
                            logging.warning(f"[{client_address}] 단편화된 UDP 패킷 (FRAG={frag_byte}) 드롭")
                            # TODO: UDP 단편화 재조립 로직 구현

                except Exception as e:
                    logging.error(f"[{client_address}] UDP 데이터 수신 오류 (TCP): {e}")
                    break


            if udp_socket in ready:
                try:
                    udp_payload, remote_addr_port = await loop.sock_recvfrom(udp_socket, 65535)
                    remote_addr, remote_port = remote_addr_port

                    addr_type_byte = b'\x01'
                    remote_addr_bytes = socket.inet_aton(remote_addr)
                    remote_port_bytes = remote_port.to_bytes(2, 'big')

                    socks5_header = b'\x00\x00\x00' + addr_type_byte + remote_addr_bytes + remote_port_bytes
                    response_packet = socks5_header + udp_payload

                    client_writer.write(response_packet)
                    await client_writer.drain()

                except Exception as e:
                    logging.error(f"[{client_address}] UDP 데이터 수신 오류 (UDP): {e}")
                    break

    except Exception as e:
        logging.error(f"[{client_address}] UDP 릴레이 오류: {e}")
    finally:
        logging.info(f"[{client_address}] UDP 릴레이 종료")
        udp_socket.close()


async def start_server(host, port):
    """SOCKS5 프록시 서버 시작 비동기 함수 (이전과 동일)"""
    server = await asyncio.start_server(
        handle_client, host, port
    )
    addr = server.sockets[0].getsockname()
    logging.info(f"SOCKS5 프록시 서버 시작: {addr}")

    async with server:
        await server.serve_forever()

async def get_ready_sockets(sockets, loop):
    """asyncio reader/writer, socket 객체를 select.select 처럼 감시하는 비동기 함수 (이전과 동일)"""
    wait_list = []
    socket_map = {}

    for s in sockets:
        if isinstance(s, asyncio.StreamReader):
            wait_list.append(loop.sock_recv(s.transport.get_extra_info('socket'), 1))
            socket_map[wait_list[-1]] = s
        elif isinstance(s, socket.socket):
            wait_list.append(loop.sock_recv(s, 1))
            socket_map[wait_list[-1]] = s
        else:
            raise ValueError("지원하지 않는 소켓 타입")

    done, pending = await asyncio.wait(wait_list, return_when=asyncio.FIRST_COMPLETED)

    ready_sockets = []
    for future in done:
        ready_sockets.append(socket_map[future])

    return ready_sockets


def get_local_ip():
    """로컬 IP 주소 가져오는 함수 (외부 네트워크 인터페이스 IP) (이전과 동일)"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        return local_ip
    except:
        return '127.0.0.1'


if __name__ == "__main__":
    load_dotenv() # .env 파일 로드

    # 환경 변수에서 사용자 정보 로드
    user_index = 1
    while True:
        username_env = os.getenv(f'USERNAME_{user_index}')
        password_env = os.getenv(f'PASSWORD_{user_index}')
        if username_env and password_env:
            USER_CREDENTIALS[username_env] = password_env
            user_index += 1
        else:
            break

    if not USER_CREDENTIALS:
        logging.warning("환경 변수에서 사용자 정보를 찾을 수 없습니다. 인증 없이 시작합니다.")
    else:
        logging.info(f"환경 변수에서 {len(USER_CREDENTIALS)}명의 사용자 정보를 로드했습니다.")


    HOST = os.getenv('SOCKS_HOST', '127.0.0.1') # 환경 변수 SOCKS_HOST 없으면 기본값 127.0.0.1 사용
    PORT = int(os.getenv('SOCKS_PORT', 1080))   # 환경 변수 SOCKS_PORT 없으면 기본값 1080 사용


    asyncio.run(start_server(HOST, PORT))
