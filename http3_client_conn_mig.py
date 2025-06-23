import argparse
import asyncio
import logging
import os
import pickle
import socket
import ssl
import time
from collections import deque
from contextlib import asynccontextmanager
from typing import (
    AsyncGenerator,
    BinaryIO,
    Callable,
    Deque,
    Dict,
    List,
    Optional,
    Union,
    cast,
)
from urllib.parse import urlparse

import aioquic
import wsproto
import wsproto.events

# Remove direct import of connect, as we will define a local version
# from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol, QuicStreamHandler
from aioquic.h0.connection import H0_ALPN, H0Connection
from aioquic.h3.connection import H3_ALPN, ErrorCode, H3Connection
from aioquic.h3.events import (
    DataReceived,
    H3Event,
    HeadersReceived,
    PushPromiseReceived,
)
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection, QuicTokenHandler
from aioquic.quic.events import QuicEvent
from aioquic.quic.logger import QuicFileLogger
from aioquic.quic.packet import QuicProtocolVersion
from aioquic.tls import CipherSuite, SessionTicket, SessionTicketHandler

try:
    import uvloop
except ImportError:
    uvloop = None

logger = logging.getLogger("client")

HttpConnection = Union[H0Connection, H3Connection]

USER_AGENT = "aioquic/" + aioquic.__version__


class URL:
    def __init__(self, url: str) -> None:
        parsed = urlparse(url)

        self.authority = parsed.netloc
        self.full_path = parsed.path or "/"
        if parsed.query:
            self.full_path += "?" + parsed.query
        self.scheme = parsed.scheme


class HttpRequest:
    def __init__(
        self,
        method: str,
        url: URL,
        content: bytes = b"",
        headers: Optional[Dict] = None,
    ) -> None:
        if headers is None:
            headers = {}

        self.content = content
        self.headers = headers
        self.method = method
        self.url = url


class WebSocket:
    def __init__(
        self, http: HttpConnection, stream_id: int, transmit: Callable[[], None]
    ) -> None:
        self.http = http
        self.queue: asyncio.Queue[str] = asyncio.Queue()
        self.stream_id = stream_id
        self.subprotocol: Optional[str] = None
        self.transmit = transmit
        self.websocket = wsproto.Connection(wsproto.ConnectionType.CLIENT)

    async def close(self, code: int = 1000, reason: str = "") -> None:
        """
        Perform the closing handshake.
        """
        data = self.websocket.send(
            wsproto.events.CloseConnection(code=code, reason=reason)
        )
        self.http.send_data(stream_id=self.stream_id, data=data, end_stream=True)
        self.transmit()

    async def recv(self) -> str:
        """
        Receive the next message.
        """
        return await self.queue.get()

    async def send(self, message: str) -> None:
        """
        Send a message.
        """
        assert isinstance(message, str)

        data = self.websocket.send(wsproto.events.TextMessage(data=message))
        self.http.send_data(stream_id=self.stream_id, data=data, end_stream=False)
        self.transmit()

    def http_event_received(self, event: H3Event) -> None:
        if isinstance(event, HeadersReceived):
            for header, value in event.headers:
                if header == b"sec-websocket-protocol":
                    self.subprotocol = value.decode()
        elif isinstance(event, DataReceived):
            self.websocket.receive_data(event.data)

        for ws_event in self.websocket.events():
            self.websocket_event_received(ws_event)

    def websocket_event_received(self, event: wsproto.events.Event) -> None:
        if isinstance(event, wsproto.events.TextMessage):
            self.queue.put_nowait(event.data)


class HttpClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.pushes: Dict[int, Deque[H3Event]] = {}
        self._http: Optional[HttpConnection] = None
        self._request_events: Dict[int, Deque[H3Event]] = {}
        self._request_waiter: Dict[int, asyncio.Future[Deque[H3Event]]] = {}
        self._websockets: Dict[int, WebSocket] = {}

        if self._quic.configuration.alpn_protocols[0].startswith("hq-"):
            self._http = H0Connection(self._quic)
        else:
            self._http = H3Connection(self._quic)

    async def get(self, url: str, headers: Optional[Dict] = None) -> Deque[H3Event]:
        """
        Perform a GET request.
        """
        return await self._request(
            HttpRequest(method="GET", url=URL(url), headers=headers)
        )

    async def post(
        self, url: str, data: bytes, headers: Optional[Dict] = None
    ) -> Deque[H3Event]:
        """
        Perform a POST request.
        """
        return await self._request(
            HttpRequest(method="POST", url=URL(url), content=data, headers=headers)
        )

    async def upload(
        self, url: str, file_path: str, headers: Optional[Dict] = None
    ) -> Deque[H3Event]:
        """
        Perform a POST request to upload a file.
        """
        # Keep 'headers: Optional[Dict] = None' for compatibility,
        # but ignore it for now.

        # os module should be imported at the top of the file.
        # basename = os.path.basename(file_path)
        # This line is no longer needed for headers
        minimal_headers: Dict[str, str] = {
            # No "Content-Type"
            # No "Content-Disposition"
        }
        # The 'headers' input parameter is deliberately ignored.

        request = HttpRequest(
            method="PUT", url=URL(url), content=b"", headers=minimal_headers
        )
        return await self._request(request, file_path=file_path)

    async def websocket(
        self, url: str, subprotocols: Optional[List[str]] = None
    ) -> WebSocket:
        """
        Open a WebSocket.
        """
        request = HttpRequest(method="CONNECT", url=URL(url))
        stream_id = self._quic.get_next_available_stream_id()
        websocket = WebSocket(
            http=self._http, stream_id=stream_id, transmit=self.transmit
        )

        self._websockets[stream_id] = websocket

        headers = [
            (b":method", b"CONNECT"),
            (b":scheme", b"https"),
            (b":authority", request.url.authority.encode()),
            (b":path", request.url.full_path.encode()),
            (b":protocol", b"websocket"),
            (b"user-agent", USER_AGENT.encode()),
            (b"sec-websocket-version", b"13"),
        ]
        if subprotocols:
            headers.append(
                (b"sec-websocket-protocol", ", ".join(subprotocols).encode())
            )
        self._http.send_headers(stream_id=stream_id, headers=headers)

        self.transmit()

        return websocket

    def http_event_received(self, event: H3Event) -> None:
        if isinstance(event, (HeadersReceived, DataReceived)):
            stream_id = event.stream_id
            if stream_id in self._request_events:
                # http
                self._request_events[event.stream_id].append(event)
                if event.stream_ended:
                    request_waiter = self._request_waiter.pop(stream_id)
                    request_waiter.set_result(self._request_events.pop(stream_id))

            elif stream_id in self._websockets:
                # websocket
                websocket = self._websockets[stream_id]
                websocket.http_event_received(event)

            elif event.push_id in self.pushes:
                # push
                self.pushes[event.push_id].append(event)

        elif isinstance(event, PushPromiseReceived):
            self.pushes[event.push_id] = deque()
            self.pushes[event.push_id].append(event)

    def quic_event_received(self, event: QuicEvent) -> None:
        #  pass event to the HTTP layer
        if self._http is not None:
            for http_event in self._http.handle_event(event):
                self.http_event_received(http_event)

    async def _request(
        self, request: HttpRequest, file_path: Optional[str] = None
    ) -> Deque[H3Event]:
        if len(self._request_waiter) > 100:  # Threshold for warning
            logger.warning(
                (
                    f"HttpClient has {len(self._request_waiter)} concurrent "
                    "requests pending. Further stream creations might be delayed "
                    "due to server-imposed concurrent stream limits."
                )
            )
        stream_id = self._quic.get_next_available_stream_id()

        common_headers = [
            (b":method", request.method.encode()),
            (b":scheme", request.url.scheme.encode()),
            (b":authority", request.url.authority.encode()),
            (b":path", request.url.full_path.encode()),
            (b"user-agent", USER_AGENT.encode()),
        ] + [(k.encode(), v.encode()) for (k, v) in request.headers.items()]

        if file_path:
            # Sending a file
            self._http.send_headers(
                stream_id=stream_id,
                headers=common_headers,
                end_stream=False,  # Headers are not the end of the stream
            )

            chunk_size = 4096
            try:
                with open(file_path, "rb") as f:
                    while True:
                        chunk = f.read(chunk_size)
                        if not chunk:
                            break  # End of file
                        self._http.send_data(
                            stream_id=stream_id, data=chunk, end_stream=False
                        )
                # After all chunks are sent, send an empty data frame
                # with end_stream=True
                self._http.send_data(stream_id=stream_id, data=b"", end_stream=True)
            except FileNotFoundError:
                # Handle file not found error appropriately.
                # For now, we can log it or raise an exception.
                # This example will simply not send data if file not found,
                # but a real application should handle this more gracefully.
                logger.error(f"File not found: {file_path}")
                # We might want to send an error back to the client or close the stream.
                # For simplicity, sending an empty data frame with end_stream=True
                # to correctly terminate the stream.
                self._http.send_data(stream_id=stream_id, data=b"", end_stream=True)

        else:
            # Original behavior: sending content from request.content
            # True if no content, False if content follows
            self._http.send_headers(
                stream_id=stream_id,
                headers=common_headers,
                end_stream=not request.content,
            )
            if request.content:
                self._http.send_data(
                    stream_id=stream_id, data=request.content, end_stream=True
                )
            # If no request.content, headers with end_stream=True was already sent.

        waiter = self._loop.create_future()
        self._request_events[stream_id] = deque()
        self._request_waiter[stream_id] = waiter
        self.transmit()

        return await asyncio.shield(waiter)


async def perform_http_request(
    client: HttpClient,
    url: str,
    data: Optional[str],
    include: bool,
    output_dir: Optional[str],
    upload_file_path: Optional[str] = None,
) -> None:
    # perform request
    start = time.time()
    if upload_file_path:
        # Pass empty headers for now, as per instruction.
        # The `upload` method itself sets Content-Type to application/octet-stream.
        http_events = await client.upload(url, file_path=upload_file_path, headers={})
        method = "PUT"
    elif data is not None:
        data_bytes = data.encode()
        http_events = await client.post(
            url,
            data=data_bytes,
            headers={
                "content-length": str(len(data_bytes)),
                "content-type": "application/x-www-form-urlencoded",
            },
        )
        method = "POST"
    else:
        async def conn_mig():
            loop = asyncio.get_event_loop()
            import netifaces as ni
            import os
            def is_interface_up(interface):
                try:
                    addr = ni.ifaddresses(interface)
                    return ni.AF_INET in addr
                except Exception as e:
                    print(e)
                    return False

            is_up = is_interface_up('eth1:3')
            if not is_up:
                os.system("ifconfig eth1:3 172.16.2.105 netmask 255.255.255.0 up")
            try:
                interface = "eth1:3"
                ip = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
                print(ip)
            except Exception as e:
                print(e)
                ip = None
            list1_3 = ["::", 0]
            ip_mac = "::ffff:"
            if ip:
                ip_c = ip_mac + str(ip)
                list1_3[0] = ip_c
                addr_c = tuple(list1_3)
            else:
                addr_c = tuple(list1_3)
            import re
            try:
                interface_c = "eth1"
                ip_s = ni.ifaddresses(interface_c)[ni.AF_INET][0]['addr']
                print(ip_s)
            except Exception as e:
                print(e)
                ip_s = None
            list_s = ["::", 4433]
            nn = ip_s
            nm = re.split(r'(\.)', nn)
            if int(nn[-1]) == 2:
                nm[-1] = '1'
            if int(nn[-1]) == 1:
                nm[-1] = '2'
            nm = "".join(nm)
            ip_chan = ip_mac + str(nm)
            list_s[0] = ip_chan
            addr_s = tuple(list_s)
            print(addr_c)
            print(addr_s)
            client._transport.close()
            await loop.create_datagram_endpoint(lambda: client, local_addr=addr_c, remote_addr=addr_s)
            # await loop.create_datagram_endpoint(lambda: client, local_addr=("::",0))
            # client._quic.change_connection_id()

        ###just before start of file download
        await asyncio.gather(conn_mig())
        task1 = await asyncio.create_task(conn_mig())
        task1
        http_events = await client.get(url)
        method = "GET"
        ###just after finish of file download
        # await asyncio.gather(conn_mig())
        # task1 = await asyncio.create_task(conn_mig())
        # task1
    elapsed = time.time() - start

    # print speed
    # Check method and ensure upload_file_path is available
    if method == "PUT" and upload_file_path:
        try:
            octets = os.path.getsize(upload_file_path)
        except OSError as e:
            logger.error(f"Could not get size of uploaded file {upload_file_path}: {e}")
            # Fallback if file size can't be read (e.g. deleted post-send start)
            octets = 0
    else:  # For GET, POST, or if PUT somehow didn't have upload_file_path
        octets = 0
        for http_event in http_events:
            if isinstance(http_event, DataReceived):
                octets += len(http_event.data)

    logger.info(
        "Response received for %s %s : %d bytes in %.1f s (%.3f Mbps)"
        % (method, urlparse(url).path, octets, elapsed, octets * 8 / elapsed / 1000000)
    )

    # output response
    if output_dir is not None:
        output_path = os.path.join(
            output_dir, os.path.basename(urlparse(url).path) or "index.html"
        )
        with open(output_path, "wb") as output_file:
            write_response(
                http_events=http_events, include=include, output_file=output_file
            )


def process_http_pushes(
    client: HttpClient,
    include: bool,
    output_dir: Optional[str],
) -> None:
    for _, http_events in client.pushes.items():
        method = ""
        octets = 0
        path = ""
        for http_event in http_events:
            if isinstance(http_event, DataReceived):
                octets += len(http_event.data)
            elif isinstance(http_event, PushPromiseReceived):
                for header, value in http_event.headers:
                    if header == b":method":
                        method = value.decode()
                    elif header == b":path":
                        path = value.decode()
        logger.info("Push received for %s %s : %s bytes", method, path, octets)

        # output response
        if output_dir is not None:
            output_path = os.path.join(
                output_dir, os.path.basename(path) or "index.html"
            )
            with open(output_path, "wb") as output_file:
                write_response(
                    http_events=http_events, include=include, output_file=output_file
                )


def write_response(
    http_events: Deque[H3Event], output_file: BinaryIO, include: bool
) -> None:
    for http_event in http_events:
        if isinstance(http_event, HeadersReceived) and include:
            headers = b""
            for k, v in http_event.headers:
                headers += k + b": " + v + b"\r\n"
            if headers:
                output_file.write(headers + b"\r\n")
        elif isinstance(http_event, DataReceived):
            output_file.write(http_event.data)


def save_session_ticket(ticket: SessionTicket) -> None:
    """
    Callback which is invoked by the TLS engine when a new session ticket
    is received.
    """
    logger.info("New session ticket received")
    if args.session_ticket:
        with open(args.session_ticket, "wb") as fp:
            pickle.dump(ticket, fp)


async def main(
    configuration: QuicConfiguration,
    urls: List[str],
    data: Optional[str],
    include: bool,
    output_dir: Optional[str],
    local_ip: str,  # Added local_ip
    local_port: int,
    zero_rtt: bool,
    upload_file: Optional[str] = None,
    num_streams: int = 1,
) -> None:
    # parse URL
    parsed = urlparse(urls[0])
    assert parsed.scheme in (
        "https",
        "wss",
    ), "Only https:// or wss:// URLs are supported."
    host = parsed.hostname
    if parsed.port is not None:
        port = parsed.port
    else:
        port = 443

    # check validity of 2nd urls and later.
    for i in range(1, len(urls)):
        _p = urlparse(urls[i])

        # fill in if empty
        _scheme = _p.scheme or parsed.scheme
        _host = _p.hostname or host
        _port = _p.port or port

        assert _scheme == parsed.scheme, "URL scheme doesn't match"
        assert _host == host, "URL hostname doesn't match"
        assert _port == port, "URL port doesn't match"

        # reconstruct url with new hostname and port
        _p = _p._replace(scheme=_scheme)
        _p = _p._replace(netloc="{}:{}".format(_host, _port))
        _p = urlparse(_p.geturl())
        urls[i] = _p.geturl()

    async with _local_connect(  # Changed to _local_connect
        host,
        port,
        configuration=configuration,
        create_protocol=HttpClient,
        session_ticket_handler=save_session_ticket,
        local_host=local_ip,  # Passed local_ip as local_host
        local_port=local_port,
        # local_host="0.0.0.0", # Removed as it caused TypeError with aioquic 1.2.0
        wait_connected=not zero_rtt,
    ) as client:
        client = cast(HttpClient, client)

        if parsed.scheme == "wss":
            ws = await client.websocket(urls[0], subprotocols=["chat", "superchat"])

            # send some messages and receive reply
            for i in range(2):
                message = "Hello {}, WebSocket!".format(i)
                print("> " + message)
                await ws.send(message)

                message = await ws.recv()
                print("< " + message)

            await ws.close()
        else:
            # When using --num-streams, the client will attempt to create
            # multiple streams for each specified URL.
            # Note that the actual number of concurrent streams is limited
            # by the server. The aioquic library will queue stream initiation
            # attempts if the server's limit is reached, and these will be
            # processed as the server increases its limits via MAX_STREAMS frames.

            # The `data` and `upload_file` parameters for main() are derived from
            # args.data and args.upload_file in the `if __name__ == "__main__":` block.
            # If args.upload_file is set, data (data_to_pass) is None.
            # This means `upload_file` takes precedence if provided.

            all_coros = []
            for url_str in urls:  # Iterate through each URL provided
                # For each URL, create num_streams requests
                for _ in range(num_streams):
                    all_coros.append(
                        perform_http_request(
                            client=client,
                            url=url_str,
                            data=data,  # This is data_to_pass from __main__
                            include=include,
                            output_dir=output_dir,
                            # This is args.upload_file from __main__
                            upload_file_path=upload_file,
                        )
                    )

            if all_coros:
                results = await asyncio.gather(*all_coros, return_exceptions=True)
                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        # Determine which URL and request number this was for context
                        # num_streams is available in main's scope
                        # urls is available in main's scope
                        # Avoid division by zero if num_streams somehow is 0
                        url_idx = i // num_streams if num_streams > 0 else i
                        req_num_for_url = (
                            (i % num_streams) + 1 if num_streams > 0 else 1
                        )

                        failed_url = "unknown_url"
                        if url_idx < len(urls):
                            failed_url = urls[url_idx]

                        logger.error(
                            (
                                f"Request {req_num_for_url} for URL {failed_url} "
                                f"encountered an error: {result}"
                            ),
                            # Log traceback if it's an actual exception object
                            exc_info=(
                                result if isinstance(result, BaseException) else None
                            ),
                        )

            # process http pushes
            process_http_pushes(client=client, include=include, output_dir=output_dir)
        client.close(error_code=ErrorCode.H3_NO_ERROR)


# Copied and modified from aioquic.asyncio.client.connect
# Added local_host parameter and removed hardcoding
@asynccontextmanager
async def _local_connect(
    host: str,
    port: int,
    *,
    configuration: Optional[QuicConfiguration] = None,
    create_protocol: Optional[Callable] = QuicConnectionProtocol,
    session_ticket_handler: Optional[SessionTicketHandler] = None,
    stream_handler: Optional[QuicStreamHandler] = None,
    token_handler: Optional[QuicTokenHandler] = None,
    wait_connected: bool = True,
    local_host: str = "::",  # Added parameter
    local_port: int = 0,
) -> AsyncGenerator[QuicConnectionProtocol, None]:
    """
    Connect to a QUIC server at the given `host` and `port`.
    This is a modified version of aioquic.asyncio.client.connect
    to support specifying the local_host.
    """
    loop = asyncio.get_running_loop()
    # local_host is now a parameter

    # lookup remote address
    # We need to do this first to make sure the remote host is resolvable,
    # otherwise we might create a socket unnecessarily.
    try:
        remote_infos = await loop.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
    except socket.gaierror as e:
        logger.error(f"Error resolving remote address {host}:{port} - {e}")
        raise

    # Use the first resolved address for the remote connection
    # Choose AF_INET6 if available, otherwise AF_INET
    # This logic is simplified from the original which forces an
    # IPv4-mapped IPv6 if addr is len 2
    # For QUIC, an IPv6 socket is generally preferred if the system supports it.
    # The actual connection logic in protocol.connect will handle the specifics.

    # We will determine the final r_addr to use for connect() later,
    # after the local socket's family is known.
    # For now, just store the first resolved remote address info.
    # Default to the first entry from getaddrinfo for the remote host.
    _r_addr_info = remote_infos[0]

    # prepare QUIC connection
    if configuration is None:
        configuration = QuicConfiguration(is_client=True)
    if configuration.server_name is None:
        configuration.server_name = host
    connection = QuicConnection(
        configuration=configuration,
        session_ticket_handler=session_ticket_handler,
        token_handler=token_handler,
    )

    # Create and bind the local socket
    sock = None
    last_exc = None

    if local_host == "::":
        try:
            logger.debug(
                f"Attempting direct IPv6 bind for local_host '::', port {local_port}"
            )
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            if hasattr(socket, "IPV6_V6ONLY") and hasattr(socket, "IPPROTO_IPV6"):
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            sock.bind((local_host, local_port, 0, 0))  # Bind to "::"
        except OSError as e:
            logger.error(
                f"Direct IPv6 bind for '::' failed: {e}. Falling back to getaddrinfo."
            )
            last_exc = e  # Store exception in case fallback also fails
            if sock:
                sock.close()
            sock = None
            # Fall through to getaddrinfo logic if direct "::" bind fails

    if sock is None:  # If not '::' or if '::' direct bind failed
        logger.debug(
            f"Using getaddrinfo for local_host '{local_host}', port {local_port}"
        )
        try:
            # Removed flags=socket.AI_PASSIVE
            local_addrinfos = await loop.getaddrinfo(
                local_host, local_port, type=socket.SOCK_DGRAM
            )
        except socket.gaierror as e:
            logger.error(
                f"Error resolving local_host '{local_host}':{local_port} - {e}"
            )
            # If '::' direct bind failed and getaddrinfo also failed for '::',
            # re-raise initial error or this one
            # Prioritize direct bind error for "::" if it happened
            if last_exc and local_host == "::":
                raise last_exc
            raise

        for res in local_addrinfos:
            af, socktype, proto, canonname, sa = res
            try:
                logger.debug(
                    f"Attempting to bind to {sa} (family {af}) via getaddrinfo"
                )
                sock = socket.socket(af, socktype, proto)
                if af == socket.AF_INET6:
                    # For IPv6, ensure dual-stack for wildcard if we didn't go
                    # through the direct "::" path
                    # For specific IPv6s from getaddrinfo, this might also be desired.
                    # Check sockaddr's host part
                    if sa[0] == "::" or sa[0].upper() == "0:0:0:0:0:0:0:0":
                        if hasattr(socket, "IPV6_V6ONLY") and hasattr(
                            socket, "IPPROTO_IPV6"
                        ):
                            logger.debug(f"Setting IPV6_V6ONLY=0 for {sa}")
                            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                sock.bind(sa)
                logger.debug(f"Successfully bound to {sa}")
                last_exc = None  # Clear previous error on success
                break  # Successfully bound
            except OSError as exc:
                logger.warning(f"Binding to {sa} failed: {exc}")
                last_exc = exc
                if sock is not None:
                    sock.close()
                sock = None
                continue  # Try next address info

        if sock is None:  # If loop completed and sock is still None
            if last_exc is not None:
                logger.error(
                    f"Failed to bind to {local_host}:{local_port} after trying all "
                    f"options - Last error: {last_exc}"
                )
                raise last_exc
            else:
                # This case means getaddrinfo returned no usable addresses
                custom_error = OSError(
                    f"Could not create/bind socket for {local_host}:{local_port} "
                    f"(getaddrinfo yielded no usable address)"
                )
                logger.error(str(custom_error))
                raise custom_error

    # connect
    logger.debug(f"Local socket bound: {sock.getsockname()}, family {sock.family}")
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: create_protocol(connection, stream_handler=stream_handler),
        sock=sock,
    )
    protocol = cast(QuicConnectionProtocol, protocol)
    try:
        # Determine the final remote address to use for connect()
        # The sockaddr is (host, port, flowinfo, scopeid)
        connect_to_addr = _r_addr_info[4]

        # If our local socket is IPv6 and the remote address from getaddrinfo is IPv4,
        # we need to convert the remote address to an IPv4-mapped IPv6 address.
        #
        # A common way to check if a sockaddr is IPv4 is by its length
        # (2 for (host,port)) vs IPv6 (4 for (host,port,flowinfo,scopeid)).
        # Or, more reliably, check the family from _r_addr_info[0]
        remote_family = _r_addr_info[0]

        if sock.family == socket.AF_INET6 and remote_family == socket.AF_INET:
            # Convert IPv4 sockaddr to IPv4-mapped IPv6 sockaddr
            # connect_to_addr is like ('1.2.3.4', 1234)
            # We want ('::ffff:1.2.3.4', 1234, 0, 0)
            connect_to_addr = ("::ffff:" + connect_to_addr[0], connect_to_addr[1], 0, 0)
            logger.debug(
                "Local socket is IPv6, remote is IPv4. Mapping remote to %s",
                connect_to_addr,
            )

        protocol.connect(connect_to_addr, transmit=wait_connected)
        if wait_connected:
            await protocol.wait_connected()
        yield protocol
    finally:
        protocol.close()
        await protocol.wait_closed()
        transport.close()


if __name__ == "__main__":
    defaults = QuicConfiguration(is_client=True)

    parser = argparse.ArgumentParser(description="HTTP/3 client")
    parser.add_argument(
        "url", type=str, nargs="+", help="the URL to query (must be HTTPS)"
    )
    parser.add_argument(
        "--ca-certs", type=str, help="load CA certificates from the specified file"
    )
    parser.add_argument(
        "--certificate",
        type=str,
        help="load the TLS certificate from the specified file",
    )
    parser.add_argument(
        "--cipher-suites",
        type=str,
        help=(
            "only advertise the given cipher suites, e.g. `AES_256_GCM_SHA384,"
            "CHACHA20_POLY1305_SHA256`"
        ),
    )
    parser.add_argument(
        "--congestion-control-algorithm",
        type=str,
        default="reno",
        help="use the specified congestion control algorithm",
    )
    parser.add_argument(
        "-d", "--data", type=str, help="send the specified data in a POST request"
    )
    parser.add_argument(
        "--upload-file",
        type=str,
        help="path to the file to upload (disables --data if used)",
    )
    parser.add_argument(
        "-i",
        "--include",
        action="store_true",
        help="include the HTTP response headers in the output",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="do not validate server certificate",
    )
    parser.add_argument(
        "--legacy-http",
        action="store_true",
        help="use HTTP/0.9",
    )
    parser.add_argument(
        "--max-data",
        type=int,
        help="connection-wide flow control limit (default: %d)" % defaults.max_data,
    )
    parser.add_argument(
        "--max-stream-data",
        type=int,
        help="per-stream flow control limit (default: %d)" % defaults.max_stream_data,
    )
    parser.add_argument(
        "--negotiate-v2",
        action="store_true",
        help="start with QUIC v1 and try to negotiate QUIC v2",
    )

    parser.add_argument(
        "--strictly-v2",
        action="store_true",
        help="connect using only QUIC v2, fail if not supported",
    )

    parser.add_argument(
        "--output-dir",
        type=str,
        help="write downloaded files to this directory",
    )
    parser.add_argument(
        "--private-key",
        type=str,
        help="load the TLS private key from the specified file",
    )
    parser.add_argument(
        "-q",
        "--quic-log",
        type=str,
        help="log QUIC events to QLOG files in the specified directory",
    )
    parser.add_argument(
        "-l",
        "--secrets-log",
        type=str,
        help="log secrets to a file, for use with Wireshark",
    )
    parser.add_argument(
        "-s",
        "--session-ticket",
        type=str,
        help="read and write session ticket from the specified file",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="increase logging verbosity"
    )
    parser.add_argument(
        "--local-port",
        type=int,
        default=0,
        help="local port to bind for connections",
    )
    parser.add_argument(
        "--max-datagram-size",
        type=int,
        default=defaults.max_datagram_size,
        help="maximum datagram size to send, excluding UDP or IP overhead",
    )
    parser.add_argument(
        "--zero-rtt", action="store_true", help="try to send requests using 0-RTT"
    )
    parser.add_argument(
        "--local-ip",
        type=str,
        default="::",
        help="local IP address to bind for connections",
    )
    parser.add_argument(
        "--num-streams",
        type=int,
        default=1,
        help="the number of streams to create (default: 1)",
    )

    args = parser.parse_args()

    if args.negotiate_v2 and args.strictly_v2:
        parser.error("argument --strictly-v2: not allowed with argument --negotiate-v2")

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )

    if args.output_dir is not None and not os.path.isdir(args.output_dir):
        raise Exception("%s is not a directory" % args.output_dir)

    # prepare configuration
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=H0_ALPN if args.legacy_http else H3_ALPN,
        congestion_control_algorithm=args.congestion_control_algorithm,
        max_datagram_size=args.max_datagram_size,
    )
    if args.ca_certs:
        configuration.load_verify_locations(args.ca_certs)
    if args.cipher_suites:
        configuration.cipher_suites = [
            CipherSuite[s] for s in args.cipher_suites.split(",")
        ]
    if args.insecure:
        configuration.verify_mode = ssl.CERT_NONE
    if args.max_data:
        configuration.max_data = args.max_data
    if args.max_stream_data:
        configuration.max_stream_data = args.max_stream_data
    if args.negotiate_v2:
        configuration.original_version = QuicProtocolVersion.VERSION_1
        configuration.supported_versions = [
            QuicProtocolVersion.VERSION_2,
            QuicProtocolVersion.VERSION_1,
        ]
    elif args.strictly_v2:
        configuration.original_version = QuicProtocolVersion.VERSION_2
        configuration.supported_versions = [QuicProtocolVersion.VERSION_2]
    if args.quic_log:
        configuration.quic_logger = QuicFileLogger(args.quic_log)
    if args.secrets_log:
        configuration.secrets_log_file = open(args.secrets_log, "a")
    if args.session_ticket:
        try:
            with open(args.session_ticket, "rb") as fp:
                configuration.session_ticket = pickle.load(fp)
        except FileNotFoundError:
            pass

    # load SSL certificate and key
    if args.certificate is not None:
        configuration.load_cert_chain(args.certificate, args.private_key)

    if uvloop is not None:
        uvloop.install()
    data_to_pass = args.data
    if args.upload_file and args.data:
        logger.warning(
            "Both --data and --upload-file specified. --data will be ignored."
        )
        data_to_pass = None

    asyncio.run(
        main(
            configuration=configuration,
            urls=args.url,
            data=data_to_pass,
            include=args.include,
            output_dir=args.output_dir,
            local_ip=args.local_ip,
            local_port=args.local_port,
            zero_rtt=args.zero_rtt,
            upload_file=args.upload_file,
            num_streams=args.num_streams,
        )
    )
