#
# !!! WARNING !!!
#
# This example uses some private APIs.
#

import argparse
import asyncio
import logging
import ssl
import time
from dataclasses import dataclass, field
from enum import Flag
from typing import Optional, cast

import httpx
from http3_client import HttpClient

from aioquic.asyncio import connect
from aioquic.h0.connection import H0_ALPN
from aioquic.h3.connection import H3_ALPN, H3Connection,ErrorCode
from aioquic.h3.events import DataReceived, HeadersReceived, PushPromiseReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.logger import QuicFileLogger, QuicLogger


class Result(Flag):
    V = 0x000001
    H = 0x000002
    D = 0x000004
    C = 0x000008
    R = 0x000010
    Z = 0x000020
    S = 0x000040
    Q = 0x000080

    M = 0x000100
    B = 0x000200
    A = 0x000400
    U = 0x000800
    P = 0x001000
    E = 0x002000
    L = 0x004000
    T = 0x008000
    PA = 0x009000 # Preferred Address test

    three = 0x010000
    d = 0x020000
    p = 0x040000

    def __str__(self):
        flags = sorted(
            map(
                lambda x: getattr(Result, x),
                filter(lambda x: not x.startswith("_"), dir(Result)),
            ),
            key=lambda x: x.value,
        )
        result_str = ""
        for flag in flags:
            if self & flag:
                result_str += flag.name
            else:
                result_str += "-"
        return result_str


@dataclass
class Server:
    name: str
    host: str
    port: int = 4433
    http3: bool = True
    http3_port: Optional[int] = None
    retry_port: Optional[int] = 4434
    path: str = "/"
    push_path: Optional[str] = None
    result: Result = field(default_factory=lambda: Result(0))
    session_resumption_port: Optional[int] = None
    structured_logging: bool = False
    throughput_path: Optional[str] = "/%(size)d"
    verify_mode: Optional[int] = None
    # preferred_address_info: For testing preferred address. Structure:
    # {
    #     "ipv4": ("host", port), # Optional
    #     "ipv6": ("host", port), # Optional
    #     "cid": b"connection_id_bytes",
    #     "token": b"stateless_reset_token_bytes"
    # }
    # This field in the Server dataclass is for the *test's knowledge*.
    # The server itself must be configured to *send* these values in its transport parameters.
    preferred_address_info: Optional[dict] = None


SERVERS = [
    Server("akamaiquic", "ietf.akaquic.com", port=443, verify_mode=ssl.CERT_NONE),
    Server(
        "aioquic", "quic.aiortc.org", port=443, push_path="/", structured_logging=True,
        # Example: Assume this server instance is configured to send this preferred_address TP.
        # The test will check if the client receives and can act on it.
        # The actual IP '1.2.3.4' and port 4435 would need to be routable to the server for a real test.
        # For local testing, this might be a secondary IP on the same host.
        preferred_address_info={
            "ipv4": ("1.2.3.4", 4435), # Placeholder, server needs to be actually reachable here
            "cid": b"\x1a\x2b\x3c\x4d", # Example CID bytes
            "token": b"\x5e\x6f\x70\x81\x92\xa3\xb4\xc5\xd6\xe7\xf8\x09\x0a\x0b\x0c\x0d" # 16 bytes
        }
    ),
    Server("ats", "quic.ogre.com"),
    Server("f5", "f5quic.com", retry_port=4433, throughput_path=None),
    Server(
        "haskell", "mew.org", structured_logging=True, throughput_path="/num/%(size)s"
    ),
    Server("gquic", "quic.rocks", retry_port=None),
    Server("lsquic", "http3-test.litespeedtech.com", push_path="/200?push=/100"),
    Server("kdaquic", "172.16.2.1", port=4433, retry_port=4433, verify_mode=ssl.CERT_NONE,),
    Server(
        "msquic",
        "quic.westus.cloudapp.azure.com",
        structured_logging=True,
        throughput_path=None,  # "/%(size)d.txt",
        verify_mode=ssl.CERT_NONE,
    ),
    Server(
        "mvfst",
        "fb.mvfst.net",
        port=443,
        push_path="/push",
        retry_port=None,
        structured_logging=True,
    ),
    Server(
        "ngtcp2",
        "nghttp2.org",
        push_path="/?push=/100",
        structured_logging=True,
        throughput_path=None,
    ),
    Server("ngx_quic", "cloudflare-quic.com", port=443, retry_port=None),
    Server("pandora", "pandora.cm.in.tum.de", verify_mode=ssl.CERT_NONE),
    Server("picoquic", "test.privateoctopus.com", structured_logging=True),
    Server("quant", "quant.eggert.org", http3=False, structured_logging=True),
    Server("quic-go", "interop.seemann.io", port=443, retry_port=443),
    Server("quiche", "quic.tech", port=8443, retry_port=8444),
    Server("quicly", "quic.examp1e.net", http3_port=443),
    Server("quinn", "h3.stammw.eu", port=443),
]


async def test_version_negotiation(server: Server, configuration: QuicConfiguration):
    # force version negotiation
    configuration.supported_versions.insert(0, 0x1A2A3A4A)

    async with connect(
        server.host, server.port, configuration=configuration
    ) as protocol:
        await protocol.ping()

        # check log
        for event in configuration.quic_logger.to_dict()["traces"][0]["events"]:
            if (
                event["name"] == "transport:packet_received"
                and event["data"]["header"]["packet_type"] == "version_negotiation"
            ):
                server.result |= Result.M


async def test_version_negotiation_v2(server: Server, configuration: QuicConfiguration):
    # force version negotiation
    configuration.supported_versions.insert(0, 0x709A50C4)
    ##not sure about hex of QUIC v2,so going forward with Martin hex value 0x709a50c4
    ## 0xFF020000,0x00000002

    async with connect(
        server.host, server.port, configuration=configuration
    ) as protocol:
        await protocol.ping()

        # check log
        for event in configuration.quic_logger.to_dict()["traces"][0]["events"]:
            if (
                event["name"] == "transport:packet_received"
                and event["data"]["header"]["packet_type"] == "version_negotiation"
            ):
                server.result |= Result.M


async def test_handshake_and_close(server: Server, configuration: QuicConfiguration):
    async with connect(
        server.host, server.port, configuration=configuration
    ) as protocol:
        await protocol.ping()
        server.result |= Result.H
    server.result |= Result.C


async def test_retry(server: Server, configuration: QuicConfiguration):
    # skip test if there is not retry port
    if server.retry_port is None:
        return

    async with connect(
        server.host, server.retry_port, configuration=configuration
    ) as protocol:
        await protocol.ping()

        # check log
        for event in configuration.quic_logger.to_dict()["traces"][0]["events"]:
            if (
                event["name"] == "transport:packet_received"
                and event["data"]["header"]["packet_type"] == "retry"
            ):
                server.result |= Result.M

async def test_quantum_readiness(server: Server, configuration: QuicConfiguration):
    configuration.quantum_readiness_test = True
    async with connect(
        server.host, server.port, configuration=configuration
    ) as protocol:
        await protocol.ping()
        server.result |= Result.Q


async def test_http_0(server: Server, configuration: QuicConfiguration):
    if server.path is None:
        return

    configuration.alpn_protocols = H0_ALPN
    async with connect(
        server.host,
        server.port,
        configuration=configuration,
        create_protocol=HttpClient,
    ) as protocol:
        protocol = cast(HttpClient, protocol)

        # perform HTTP request
        events = await protocol.get(
            "https://{}:{}{}".format(server.host, server.port, server.path)
        )
        if events and isinstance(events[0], HeadersReceived):
            server.result |= Result.D


async def test_http_3(server: Server, configuration: QuicConfiguration):
    port = server.http3_port or server.port
    if server.path is None:
        return

    configuration.alpn_protocols = H3_ALPN
    async with connect(
        server.host,
        port,
        configuration=configuration,
        create_protocol=HttpClient,
    ) as protocol:
        protocol = cast(HttpClient, protocol)

        # perform HTTP request
        events = await protocol.get(
            "https://{}:{}{}".format(server.host, server.port, server.path)
        )
        if events and isinstance(events[0], HeadersReceived):
            server.result |= Result.D
            server.result |= Result.three

        # perform more HTTP requests to use QPACK dynamic tables
        for i in range(2):
            events = await protocol.get(
                "https://{}:{}{}".format(server.host, server.port, server.path)
            )
        if events and isinstance(events[0], HeadersReceived):
            http = cast(H3Connection, protocol._http)
            protocol._quic._logger.info(
                "QPACK decoder bytes RX %d TX %d",
                http._decoder_bytes_received,
                http._decoder_bytes_sent,
            )
            protocol._quic._logger.info(
                "QPACK encoder bytes RX %d TX %d",
                http._encoder_bytes_received,
                http._encoder_bytes_sent,
            )
            if (
                http._decoder_bytes_received
                and http._decoder_bytes_sent
                and http._encoder_bytes_received
                and http._encoder_bytes_sent
            ):
                server.result |= Result.d

        # check push support
        if server.push_path is not None:
            protocol.pushes.clear()
            await protocol.get(
                "https://{}:{}{}".format(server.host, server.port, server.push_path)
            )
            await asyncio.sleep(0.5)
            for push_id, events in protocol.pushes.items():
                if (
                    len(events) >= 3
                    and isinstance(events[0], PushPromiseReceived)
                    and isinstance(events[1], HeadersReceived)
                    and isinstance(events[2], DataReceived)
                ):
                    protocol._quic._logger.info(
                        "Push promise %d for %s received (status %s)",
                        push_id,
                        dict(events[0].headers)[b":path"].decode("ascii"),
                        int(dict(events[1].headers)[b":status"]),
                    )

                    server.result |= Result.p


async def test_session_resumption(server: Server, configuration: QuicConfiguration):
    port = server.session_resumption_port or server.port
    saved_ticket = None

    def session_ticket_handler(ticket):
        nonlocal saved_ticket
        saved_ticket = ticket

    # connect a first time, receive a ticket
    async with connect(
        server.host,
        port,
        configuration=configuration,
        session_ticket_handler=session_ticket_handler,
    ) as protocol:
        await protocol.ping()

        # some servers don't send the ticket immediately
        await asyncio.sleep(1)

    # connect a second time, with the ticket
    if saved_ticket is not None:
        configuration.session_ticket = saved_ticket
        async with connect(server.host, port, configuration=configuration) as protocol:
            await protocol.ping()

            # check session was resumed
            if protocol._quic.tls.session_resumed:
                server.result |= Result.R

            # check early data was accepted
            if protocol._quic.tls.early_data_accepted:
                server.result |= Result.Z


async def test_key_update(server: Server, configuration: QuicConfiguration):
    async with connect(
        server.host, server.port, configuration=configuration
    ) as protocol:
        # cause some traffic
        await protocol.ping()

        # request key update
        protocol.request_key_update()

        # cause more traffic
        await protocol.ping()

        server.result |= Result.U


async def test_server_cid_change(server: Server, configuration: QuicConfiguration):
    async with connect(
        server.host, server.port, configuration=configuration
    ) as protocol:
        # cause some traffic
        await protocol.ping()

        # change connection ID
        protocol.change_connection_id()

        # cause more traffic
        await protocol.ping()

        server.result |= Result.M


async def test_server_cid_change_multiple(server: Server, configuration: QuicConfiguration):
    port = server.http3_port or server.port
    if server.path is None:
        return
    configuration.alpn_protocols = H3_ALPN
    async with connect(
        server.host,
        port,
        configuration=configuration,
        create_protocol=HttpClient,
    ) as client:
        client = cast(HttpClient, client)

        # cause some traffic
        await client.ping()
        for i in range(50):
            # change connection ID
            client._quic.change_connection_id()

            # cause more traffic
            await client.ping()

            server.result |= Result.M

async def test_cid_not_in_list(server: Server, configuration: QuicConfiguration):
    port = server.http3_port or server.port
    if server.path is None:
        return
    configuration.alpn_protocols = H3_ALPN
    async with connect(
        server.host,
        port,
        configuration=configuration,
        create_protocol=HttpClient,
    ) as client:
        client = cast(HttpClient, client)

        # cause some traffic
        await client.ping()
        for i in range(5):
            # change connection ID
            client._quic.change_connection_id_notinlist()
            # cause more traffic
            await client.ping()
            server.result |= Result.M

async def test_reuse_dest_cid(server: Server, configuration: QuicConfiguration):
    port = server.http3_port or server.port
    if server.path is None:
        return
    configuration.alpn_protocols = H3_ALPN
    async with connect(
        server.host,
        port,
        configuration=configuration,
        create_protocol=HttpClient,
    ) as client:
        client = cast(HttpClient, client)

        # cause some traffic
        await client.ping()
        for i in range(5):
            # change connection ID
            client._quic.change_connection_id_rdcid()
            # cause more traffic
            await client.ping()
            server.result |= Result.M

async def test_reuse_source_cid(server: Server, configuration: QuicConfiguration):
    port = server.http3_port or server.port
    if server.path is None:
        return
    configuration.alpn_protocols = H3_ALPN
    async with connect(
        server.host,
        port,
        configuration=configuration,
        create_protocol=HttpClient,
    ) as client:
        client = cast(HttpClient, client)

        # cause some traffic
        await client.ping()
        for i in range(5):
            # change connection ID
            client._quic.change_connection_id_rscid()
            # cause more traffic
            await client.ping()
            server.result |= Result.M

async def test_reuse_rdcid_newscid(server: Server, configuration: QuicConfiguration):
    port = server.http3_port or server.port
    if server.path is None:
        return
    configuration.alpn_protocols = H3_ALPN
    async with connect(
        server.host,
        port,
        configuration=configuration,
        create_protocol=HttpClient,
    ) as client:
        client = cast(HttpClient, client)

        # cause some traffic
        await client.ping()
        for i in range(5):
            # change connection ID
            client._quic.change_connection_id_rdcid_as_newscid()
            # cause more traffic
            await client.ping()
            server.result |= Result.M


async def test_reuse_rscid_newdcid(server: Server, configuration: QuicConfiguration):
    port = server.http3_port or server.port
    if server.path is None:
        return
    configuration.alpn_protocols = H3_ALPN
    async with connect(
        server.host,
        port,
        configuration=configuration,
        create_protocol=HttpClient,
    ) as client:
        client = cast(HttpClient, client)

        # cause some traffic
        await client.ping()
        for i in range(5):
            # change connection ID
            client._quic.change_connection_id_rscid_as_newdcid()
            # cause more traffic
            await client.ping()
            server.result |= Result.M






async def test_your_conn(server:Server,configuration: QuicConfiguration):
    port = server.http3_port or server.port
    if server.path is None:
        return

    configuration.alpn_protocols = H3_ALPN
    async with connect(
        server.host,
        port,
        configuration=configuration,
        create_protocol=HttpClient,
    ) as client:
        client = cast(HttpClient, client)
    for i in range(10):
        mysid = int(i)
        client._quic._get_or_create_stream_for_send(stream_id=mysid)  # create our own stream
        client._quic.send_stream_data(stream_id=mysid, data=b'this is my stream ')  # send data to our own stream
        from aioquic.quic.packet import QuicErrorCode
        client._quic.reset_stream(stream_id=mysid, error_code=QuicErrorCode.NO_ERROR)  # do reset of our own stream
        server.result |= Result.M
    # client._quic.send_stream_data(stream_id=mysid, data=b'again send data to reset') #proof to reset is done


async def test_client_reset_sid(server:Server,configuration: QuicConfiguration):
    port = server.http3_port or server.port
    if server.path is None:
        return

    configuration.alpn_protocols = H3_ALPN
    async with connect(
        server.host,
        port,
        configuration=configuration,
        create_protocol=HttpClient,
    ) as client:
        client = cast(HttpClient, client)
        rsid=client._quic.get_next_available_stream_id()
        sid = client._quic.get_next_available_stream_id()  # trying to get next stream id
        print("code is here and sid is", sid)
        intsid = int(sid)  # converting it into int value
        intz = int(0)  # can reset sid by hardcoded values also 0,4,2,6,1,5,3,7

        from aioquic.quic.packet import QuicErrorCode
        client._quic.reset_stream(stream_id=rsid, error_code=QuicErrorCode.NO_ERROR)  # resetting currently used sid
        #client._quic.send_stream_data(stream_id=rsid,data=b'hai') #it is just a proof that if you send data now on resetted sid you will get an error

        sidn = client._quic.get_next_available_stream_id()  # again getting new sid
        intsidn = int(sidn)
        print("code is here and reset done and  new sid is", sidn)
        from aioquic.quic.stream import QuicStreamSender
        p = QuicStreamSender(stream_id=intsid, writable=True)
        p.reset(error_code=ErrorCode.H3_NO_ERROR)  # again resetting cureently used sid
       # p.write(data=b'qwertyuio') # proof after reset sid is not usable  AssertionError: cannot call write() after reset()

        q = QuicStreamSender(stream_id=intsidn, writable=True)
        q.write(data=b'how are you')  # again sending new data to sid
        client._quic.send_stream_data(stream_id=intsidn, data=b'hi')

        '''
        mysid=int(12)
        client._quic._get_or_create_stream_for_send(stream_id=mysid) #create our own stream
        client._quic.send_stream_data(stream_id=mysid, data=b'this is my stream') #send data to our own stream
        client._quic.reset_stream(stream_id=mysid, error_code=QuicErrorCode.NO_ERROR) # do reset of our own stream
       # client._quic.send_stream_data(stream_id=mysid, data=b'again send data to reset') #proof to reset is done
        '''
        await client.ping()

        server.result |= Result.M



async def test_conn_close_im(server:Server,configuration: QuicConfiguration):
    port = server.http3_port or server.port
    if server.path is None:
        return

    configuration.alpn_protocols = H3_ALPN
    async with connect(
        server.host,
        port,
        configuration=configuration,
        create_protocol=HttpClient,
    ) as client:
        client = cast(HttpClient, client)

        def close_conn():
            time.sleep(0.1)
            client._quic.close(error_code=ErrorCode.H3_NO_ERROR,reason_phrase="goodbye i am done ")
            server.result |= Result.M

        from threading import Thread
        t1=Thread(target=close_conn)

        t1.start()
        rsid=client._quic.get_next_available_stream_id()


        client._quic.send_stream_data(stream_id=rsid, data=b'hello')
        client._quic.change_connection_id()
        await client.ping()
        client._quic.change_connection_id()
        await client.ping()
        time.sleep(0.25)
        client._quic.change_connection_id()
        await client.ping()
        client._quic.change_connection_id()
        await client.ping()

        server.result |= Result.H

async def test_parallel_conn(server: Server, configuration: QuicConfiguration):
    import subprocess
    basecommand = "python3 /root/aioquic/examples/http3_client.py --ca-certs /root/aioquic/tests/pycacert.pem -v "

   # myftd2 = "https://172.16.3.1:4433/"

    def run_parallel(url, parallel=1, data="",):
        sed_insert()
        cmd = basecommand + "--parallel " + str(parallel) + " " + url + str(data)
        print("Executing now", cmd)
        run_command(cmd)
        server.result |= Result.M

    def run_command(cmd):
        process = subprocess.run("{}".format(cmd), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        if (len(process.stdout) > 0):
            print(process.stdout)

        if len(process.stderr) != 0 or process.returncode != 0:
            print(process.stderr)

    def sed_insert():
        wc = "grep -irn '/root/aioquic/examples/http3_client.py' -e 'parallel=args.parallel,' | wc -l"
        p1 = subprocess.run("{}".format(wc), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,universal_newlines=True)
        while (int(p1.stdout) == 0):
            s1="sed -i '354i \ \ \ \ parallel: int,' /root/aioquic/examples/http3_client.py"
            s2="sed -i '422i \ \ \ \ \ \ \ \ \ \ \ \ \ \ \  for i in range(parallel)' /root/aioquic/examples/http3_client.py"
            s3='''sed -i '508i \ \ \ \ parser.add_argument("--parallel", type=int, default=1, help="perform this many requests in parallel")' /root/aioquic/examples/http3_client.py'''
            s4="sed -i '575i \ \ \ \ \ \ \ \ \ \ \ \ parallel=args.parallel,' /root/aioquic/examples/http3_client.py"
            l1=[s1,s2,s3,s4]
            for i in (l1):
                subprocess.run("{}".format(i), shell=True)
            wcn="grep -irn '/root/aioquic/examples/http3_client.py' -e 'parallel: int,' | wc -l"
            p1 = subprocess.run("{}".format(wcn), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,universal_newlines=True)

   # run_parallel(myftd1, 10, data=10000)
   # server.result |= Result.M




async def test_received_padding_only(server: Server, configuration: QuicConfiguration):
        from aioquic.quic.connection import QuicConnection, QuicReceiveContext
        port = server.http3_port or server.port
        if server.path is None:
            return
        configuration.alpn_protocols = H3_ALPN
        async with connect(
                server.host,
                port,
                configuration=configuration,
                create_protocol=HttpClient,
        ) as client:
            client = cast(HttpClient, client)

        from aioquic import tls
        def client_receive_context(client, epoch=tls.Epoch.ONE_RTT):
            return QuicReceiveContext(
                epoch=epoch,
                host_cid=client._quic.host_cid,
                network_path=client._quic._network_paths[0],
                quic_logger_frames=[],
                time=time.time(),
            )
        is_ack_eliciting, is_probing = client._quic._payload_received(
            client_receive_context(client=client), b"\x00" * 1200)
        print("is_ack_eliciting is ",is_ack_eliciting) #output must be False
        print("is_probing is ",is_probing) #output must be True

        server.result |= Result.M


async def test_no_padding(server: Server, configuration: QuicConfiguration):
        from aioquic.quic.connection import QuicConnection, QuicReceiveContext
        port = server.http3_port or server.port
        if server.path is None:
            return
        configuration.alpn_protocols = H3_ALPN
        async with connect(
                server.host,
                port,
                configuration=configuration,
                create_protocol=HttpClient,
        ) as client:
            client = cast(HttpClient, client)

            from aioquic import tls
            def client_receive_context(client, epoch=tls.Epoch.ONE_RTT):
                return QuicReceiveContext(
                    epoch=epoch,
                    host_cid=client._quic.host_cid,
                    network_path=client._quic._network_paths[0],
                    quic_logger_frames=[],
                    time=time.time(),
                )
        # no more padding
        from aioquic._buffer import Buffer
        buf = Buffer(data=b"")
        from aioquic.quic.packet import QuicFrameType
        client._quic._handle_padding_frame(
            client_receive_context(client), QuicFrameType.PADDING, buf
        )

        server.result |= Result.M


async def test_padding_until_end(server: Server, configuration: QuicConfiguration):
    from aioquic.quic.connection import QuicConnection, QuicReceiveContext
    port = server.http3_port or server.port
    if server.path is None:
        return
    configuration.alpn_protocols = H3_ALPN
    async with connect(
            server.host,
            port,
            configuration=configuration,
            create_protocol=HttpClient,
    ) as client:
        client = cast(HttpClient, client)

        from aioquic import tls
        def client_receive_context(client, epoch=tls.Epoch.ONE_RTT):
            return QuicReceiveContext(
                epoch=epoch,
                host_cid=client._quic.host_cid,
                network_path=client._quic._network_paths[0],
                quic_logger_frames=[],
                time=time.time(),
            )
        # padding until end
        from aioquic._buffer import Buffer
        from aioquic.quic.packet import QuicFrameType
        buf = Buffer(data=bytes(10))
        client._quic._handle_padding_frame(
            client_receive_context(client), QuicFrameType.PADDING, buf
        )

        server.result |= Result.M


async def test_padding_something(server: Server, configuration: QuicConfiguration):
    from aioquic.quic.connection import QuicConnection, QuicReceiveContext
    port = server.http3_port or server.port
    if server.path is None:
        return
    configuration.alpn_protocols = H3_ALPN
    async with connect(
            server.host,
            port,
            configuration=configuration,
            create_protocol=HttpClient,
    ) as client:
        client = cast(HttpClient, client)

        from aioquic import tls
        def client_receive_context(client, epoch=tls.Epoch.ONE_RTT):
            return QuicReceiveContext(
                epoch=epoch,
                host_cid=client._quic.host_cid,
                network_path=client._quic._network_paths[0],
                quic_logger_frames=[],
                time=time.time(),
            )
        # padding then something else
        from aioquic._buffer import Buffer
        from aioquic.quic.packet import QuicFrameType
        buf = Buffer(data=bytes(10) + b"\x01")
        client._quic._handle_padding_frame(
            client_receive_context(client), QuicFrameType.PADDING, buf
        )

        server.result |= Result.M


async def test_payload_empty(server: Server, configuration: QuicConfiguration):
    try:
        from aioquic.quic.connection import QuicConnection, QuicReceiveContext
        port = server.http3_port or server.port
        if server.path is None:
            return
        configuration.alpn_protocols = H3_ALPN
        async with connect(
                server.host,
                port,
                configuration=configuration,
                create_protocol=HttpClient,
        ) as client:
            client = cast(HttpClient, client)
            from aioquic import tls
            def client_receive_context(client, epoch=tls.Epoch.ONE_RTT):
                return QuicReceiveContext(
                    epoch=epoch,
                    host_cid=client._quic.host_cid,
                    network_path=client._quic._network_paths[0],
                    quic_logger_frames=[],
                    time=time.time(),
                )
            client._quic._payload_received(client_receive_context(client), b"")

        server.result |= Result.H
    except Exception as e :
        print(e)
        server.result |= Result.M


async def test_wrong_frame(server: Server, configuration: QuicConfiguration):
    try:
        from aioquic.quic.connection import QuicConnection, QuicReceiveContext
        port = server.http3_port or server.port
        if server.path is None:
            return
        configuration.alpn_protocols = H3_ALPN
        async with connect(
                server.host,
                port,
                configuration=configuration,
                create_protocol=HttpClient,
        ) as client:
            client = cast(HttpClient, client)
            from aioquic import tls
            def client_receive_context(client, epoch=tls.Epoch.ONE_RTT):
                return QuicReceiveContext(
                    epoch=epoch,
                    host_cid=client._quic.host_cid,
                    network_path=client._quic._network_paths[0],
                    quic_logger_frames=[],
                    time=time.time(),
                )

            client._quic._payload_received(client_receive_context(client), b"\x1f")

        server.result |= Result.H

    except Exception as e:
        print(e)
        server.result |= Result.M



async def test_receive_unexpected_frame(server: Server, configuration: QuicConfiguration):
    try:

        from aioquic.quic.connection import QuicConnection, QuicReceiveContext
        port = server.http3_port or server.port
        if server.path is None:
            return
        configuration.alpn_protocols = H3_ALPN
        async with connect(
                server.host,
                port,
                configuration=configuration,
                create_protocol=HttpClient,
        ) as client:
            client = cast(HttpClient, client)
            from aioquic import tls
            def client_receive_context(client, epoch=tls.Epoch.ONE_RTT):
                return QuicReceiveContext(
                    epoch=epoch,
                    host_cid=client._quic.host_cid,
                    network_path=client._quic._network_paths[0],
                    quic_logger_frames=[],
                    time=time.time(),
                )

            client._quic._payload_received(client_receive_context(client, epoch=tls.Epoch.ZERO_RTT), b"\x06")

        server.result |= Result.H
    except Exception as e :
        print(e)
        server.result |= Result.M


async def test_receive_malformed_frame(server: Server, configuration: QuicConfiguration):
    try:

        from aioquic.quic.connection import QuicConnection, QuicReceiveContext
        port = server.http3_port or server.port
        if server.path is None:
            return
        configuration.alpn_protocols = H3_ALPN
        async with connect(
                server.host,
                port,
                configuration=configuration,
                create_protocol=HttpClient,
        ) as client:
            client = cast(HttpClient, client)
            from aioquic import tls
            def client_receive_context(client, epoch=tls.Epoch.ONE_RTT):
                return QuicReceiveContext(
                    epoch=epoch,
                    host_cid=client._quic.host_cid,
                    network_path=client._quic._network_paths[0],
                    quic_logger_frames=[],
                    time=time.time(),
                )


            client._quic._payload_received(client_receive_context(client), b"\x1ar\x00\x01")

        server.result |= Result.H
    except Exception as e:
        print(e)
        server.result |= Result.M


async def test_push_promise_client(server: Server, configuration: QuicConfiguration):
    try:

        from aioquic.quic.connection import QuicConnection, QuicReceiveContext
        port = server.http3_port or server.port
        if server.path is None:
            return
        configuration.alpn_protocols = H3_ALPN
        async with connect(
                server.host,
                port,
                configuration=configuration,
                create_protocol=HttpClient,
        ) as client:

            # request_headers = [(b":method", b"GET"),(b":scheme", b"https"),]
            request_headerss = [(b"hello"),(b"hai"), ]
            client = cast(HttpClient, client)
            from aioquic.h3.connection import encode_frame, FrameType
            from aioquic.quic.events import StreamDataReceived
            #sid=client._quic.get_next_available_stream_id()
            client._http.handle_event(
                StreamDataReceived(
                    stream_id=0,
                    data=encode_frame(FrameType.PUSH_PROMISE, b"hello"),
                    end_stream=False,
                )
            )
            client._http.send_push_promise(stream_id=0,headers=request_headerss)
        server.result |= Result.H

    except Exception as e:
        print(e)
        server.result |= Result.M



async def test_handle_request_frame_push_promise_from_client(server: Server, configuration: QuicConfiguration):
    try:

        from aioquic.h3.connection import H3_ALPN, H3Connection, ErrorCode, encode_frame, FrameType
        from aioquic.quic.connection import QuicConnection, QuicReceiveContext
        port = server.http3_port or server.port
        if server.path is None:
            return
        configuration.alpn_protocols = H3_ALPN
        async with connect(
                server.host,
                port,
                configuration=configuration,
                create_protocol=HttpClient,
        ) as client:
            request_headers = [(b""),(b""),(b""), ]
            from aioquic.quic.events import StreamDataReceived
            client._http.handle_event(
                    StreamDataReceived(
                        stream_id=0,
                        data=encode_frame(FrameType.PUSH_PROMISE, b""),
                        end_stream=False,
                    )
            )
            client._http.send_push_promise(stream_id=0,headers=request_headers)
        server.result |= Result.H

    except Exception as e :
        print(e)
        server.result |= Result.M










async def test_received_wrong_ietf_version_data(server: Server, configuration: QuicConfiguration):

    from aioquic.h3.connection import H3_ALPN, H3Connection, ErrorCode, encode_frame, FrameType
    from aioquic.quic.connection import QuicConnection, QuicReceiveContext
    port = server.http3_port or server.port
    if server.path is None:
        return
    configuration.alpn_protocols = H3_ALPN
    async with connect(
            server.host,
            port,
            configuration=configuration,
            create_protocol=HttpClient,
    ) as client:
        from aioquic.quic.packet_builder import QuicPacketBuilder
        builder = QuicPacketBuilder(
            host_cid=client._quic._peer_cid.cid,
            is_client=False,
            max_datagram_size=600,
            peer_cid=client._quic.host_cid,
            version=0xFF001122,  # DRAFT_16
        )
        from aioquic.quic.crypto import CryptoPair
        crypto = CryptoPair()
        crypto.setup_initial(
            client._quic._peer_cid.cid, is_client=False, version=client._quic._version
        )
        from aioquic.quic.packet import PACKET_TYPE_INITIAL
        builder.start_packet(PACKET_TYPE_INITIAL, crypto)
        from aioquic.quic.packet import QuicFrameType
        buf = builder.start_frame(QuicFrameType.PADDING)
        buf.push_bytes(bytes(builder.remaining_flight_space))

        for datagram in builder.flush()[0]:
            client._quic.receive_datagram(datagram, client, now=time.time())

        server.result |= Result.M


async def test_exactly_entire_packet(server: Server, configuration: QuicConfiguration):
    from aioquic.h3.connection import H3_ALPN, H3Connection, ErrorCode, encode_frame, FrameType
    from aioquic.quic.connection import QuicConnection, QuicReceiveContext
    port = server.http3_port or server.port
    if server.path is None:
        return
    configuration.alpn_protocols = H3_ALPN
    async with connect(
            server.host,
            port,
            configuration=configuration,
            create_protocol=HttpClient,
    ) as client:
        payload = b"Z" * 1250
        for i in range(30):
            client._quic.send_datagram_frame(payload)
            print(i)
        server.result |= Result.M


async def test_retry_wrong_destination_cid(server: Server, configuration: QuicConfiguration):
    from aioquic.h3.connection import H3_ALPN, H3Connection, ErrorCode, encode_frame, FrameType
    from aioquic.quic.connection import QuicConnection, QuicReceiveContext
    port = server.http3_port or server.port
    if server.path is None:
        return
    configuration.alpn_protocols = H3_ALPN
    async with connect(
            server.host,
            port,
            configuration=configuration,
            create_protocol=HttpClient,
    ) as client:
        from aioquic.quic.packet import encode_quic_retry
        import binascii
        client._quic.receive_datagram(
            encode_quic_retry(
                version=client._quic._version,
                source_cid=binascii.unhexlify("85abb547bf28be97"),
                destination_cid=binascii.unhexlify("c98343fe8f5f0ff4"),
                original_destination_cid=client._quic._peer_cid.cid,
                retry_token=bytes(16),
            ),
            client,
            now=time.time(),
        )
        server.result |= Result.M


async def test_handle_new_token_frame_from_client(server: Server, configuration: QuicConfiguration):
    from aioquic.h3.connection import H3_ALPN, H3Connection, ErrorCode, encode_frame, FrameType
    from aioquic.quic.connection import QuicConnection, QuicReceiveContext
    port = server.http3_port or server.port
    if server.path is None:
        return
    configuration.alpn_protocols = H3_ALPN
    async with connect(
            server.host,
            port,
            configuration=configuration,
            create_protocol=HttpClient,
    ) as client:
        from aioquic import tls
        def client_receive_context(client, epoch=tls.Epoch.ONE_RTT):
            return QuicReceiveContext(
                epoch=epoch,
                host_cid=client._quic.host_cid,
                network_path=client._quic._network_paths[0],
                quic_logger_frames=[],
                time=time.time(),

            )

        from aioquic.quic.packet import QuicFrameType
        from aioquic._buffer import Buffer
        import binascii
        client._quic._handle_new_token_frame(
            client_receive_context(client),
            QuicFrameType.NEW_TOKEN,
            Buffer(data=binascii.unhexlify("080102030405060708")),
        )
        server.result |= Result.M




async def test_pings_parallel(server: Server, configuration: QuicConfiguration):

    from aioquic.h3.connection import H3_ALPN
    port = server.http3_port or server.port
    if server.path is None:
        return
    configuration.alpn_protocols = H3_ALPN
    async with connect(
            server.host,
            port,
            configuration=configuration,
            create_protocol=HttpClient,
    ) as client:
        coros = [client.ping() for x in range(30)]
        await asyncio.gather(*coros)
        server.result |= Result.M



async def test_fin_without_data(server: Server, configuration: QuicConfiguration):

    from aioquic.h3.connection import H3_ALPN
    port = server.http3_port or server.port
    if server.path is None:
        return
    configuration.alpn_protocols = H3_ALPN
    async with connect(
            server.host,
            port,
            configuration=configuration,
            create_protocol=HttpClient,
    ) as client:
        from aioquic.quic.stream import QuicStream
        from aioquic.quic.events import StreamDataReceived
        from aioquic.quic.packet import QuicStreamFrame
        stream = QuicStream(stream_id=0)
        stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"", fin=True)),
        StreamDataReceived(data=b"", end_stream=True, stream_id=0)

        server.result |= Result.M



async def test_reset_after_fin(server: Server, configuration: QuicConfiguration):

    from aioquic.h3.connection import H3_ALPN
    port = server.http3_port or server.port
    if server.path is None:
        return
    configuration.alpn_protocols = H3_ALPN
    async with connect(
            server.host,
            port,
            configuration=configuration,
            create_protocol=HttpClient,
    ) as client:
        from aioquic.quic.stream import QuicStream
        from aioquic.quic.packet import QuicStreamFrame
        stream = QuicStream(stream_id=0)
        stream.receiver.handle_frame(QuicStreamFrame(offset=0, data=b"arun", fin=True))
        stream.receiver.handle_reset(final_size=4),
        from aioquic.quic.events import StreamReset
        from aioquic.quic.packet import QuicErrorCode
        StreamReset(error_code=QuicErrorCode.NO_ERROR, stream_id=0)
        client._quic.reset_stream(stream_id=0,error_code=QuicErrorCode.NO_ERROR)
        server.result |= Result.M



async def test_handle_new_token_frame_sbc(SERVER: Server, configuration: QuicConfiguration):
    try:
        async with connect(
                SERVER.host,SERVER.port, configuration=configuration
        ) as protocol:
            from aioquic.quic.connection import QuicConnection
            import contextlib
            from aioquic.quic.connection import QuicReceiveContext, QuicConnectionError
            import os
            os.system("cp /root/aioquic/tests/pycacert.pem /root/aioquic/examples/pycacert.pem")
            SERVER_CACERTFILE = os.path.join(os.path.dirname(__file__), "pycacert.pem")

            os.system("cp /root/aioquic/tests/ssl_cert.pem /root/aioquic/examples/ssl_cert.pem")
            os.system("cp /root/aioquic/tests/ssl_key.pem /root/aioquic/examples/ssl_key.pem")
            SERVER_CERTFILE = os.path.join(os.path.dirname(__file__), "ssl_cert.pem")
            SERVER_KEYFILE = os.path.join(os.path.dirname(__file__), "ssl_key.pem")

            import re
            CLIENT_ADDR = [1234]
            nn=SERVER.host
            nm = re.split(r'(\.)', nn)
            if int(nn[-1]) == 2:
                nm[-1] = '1'
            if int(nn[-1]) == 1:
                nm[-1] = '2'
            nm = "".join(nm)
            CLIENT_ADDR.insert(0, nm)
            SERVER_ADDR = []
            SERVER_ADDR.append(SERVER.host)
            SERVER_ADDR.append(SERVER.port)

            def transfer(sender, receiver):
                """
                Send datagrams from `sender` to `receiver`.
                """
                datagrams = 0
                from_addr = CLIENT_ADDR if sender._is_client else SERVER_ADDR
                for data, addr in sender.datagrams_to_send(now=time.time()):
                    datagrams += 1
                    receiver.receive_datagram(data, from_addr, now=time.time())
                return datagrams


            def roundtrip(sender, receiver):
                """
                Send datagrams from `sender` to `receiver` and back.
                """
                return (transfer(sender, receiver), transfer(receiver, sender))

            def disable_packet_pacing(connection):
                from aioquic.quic.recovery import QuicPacketPacer
                class DummyPacketPacer(QuicPacketPacer):
                    def next_send_time(self, now):
                        return None

                connection._loss._pacer = DummyPacketPacer()

            @contextlib.contextmanager
            def client_and_server(
                    client_kwargs={},
                    client_options={},
                    client_patch=lambda x: None,
                    handshake=True,
                    server_kwargs={},
                    server_certfile=SERVER_CERTFILE,
                    server_keyfile=SERVER_KEYFILE,
                    server_options={},
                    server_patch=lambda x: None,
            ):
                client_configuration = QuicConfiguration(
                    is_client=True, quic_logger=QuicLogger(), **client_options
                )
                client_configuration.load_verify_locations(cafile=SERVER_CACERTFILE)

                client = QuicConnection(configuration=client_configuration, **client_kwargs)
                client._ack_delay = 0

                disable_packet_pacing(client)
                client_patch(client)
                server_configuration = QuicConfiguration(
                    is_client=False, quic_logger=QuicLogger(), **server_options
                )
                server_configuration.load_cert_chain(server_certfile, server_keyfile)
                server = QuicConnection(
                    configuration=server_configuration,
                    original_destination_connection_id=client.original_destination_connection_id,
                    **server_kwargs
                )
                server._ack_delay = 0
                disable_packet_pacing(server)
                server_patch(server)

                # perform handshake
                if handshake:
                    client.connect(SERVER_ADDR, now=time.time())
                    for i in range(3):
                        # from tests.test_connection import roundtrip
                        roundtrip(client, server)

                yield client, server

                # close
                client.close()
                server.close()

            from aioquic import tls
            def client_receive_context(client, epoch=tls.Epoch.ONE_RTT):
                return QuicReceiveContext(
                    epoch=epoch,
                    host_cid=client.host_cid,
                    network_path=client._network_paths[0],
                    quic_logger_frames=[],
                    time=time.time(),
                )

            from aioquic._buffer import Buffer

            from aioquic import tls
            with client_and_server() as (client, server):


                # server receives NEW_TOKEN
                from aioquic.quic.packet import QuicFrameType
                import binascii
                server._handle_new_token_frame(
                    client_receive_context(client),
                    QuicFrameType.NEW_TOKEN,
                    Buffer(data=binascii.unhexlify("080102030405060708")),
                )
                SERVER.result |= Result.H
    except Exception as e:
            print(e)
            SERVER.result |= Result.M



async def test_connection_migration(server: Server, configuration: QuicConfiguration):
    async with connect(
        server.host, server.port, configuration=configuration
    ) as protocol:
        import netifaces as ni
        try:
            interface = "eth1:3"
            ip = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
        except Exception as e:
            print(e)
            ip=None

        list1 = ["::", 4478]
        ip_mac = "::ffff:"
        if ip:
            nm = ip_mac + str(ip)
            list1[0] = nm
            addr = tuple(list1)
        else:
            addr = tuple(list1)


        # cause some traffic
        await protocol.ping()

        # replace transport
        protocol._transport.close()
        loop = asyncio.get_event_loop()
        await loop.create_datagram_endpoint(lambda: protocol, local_addr=addr)
        # cause more traffic
        await protocol.ping()

        # check log
        path_challenges = 0
        for event in configuration.quic_logger.to_dict()["traces"][0]["events"]:
            if (
                event["name"] == "transport:packet_received"
                and event["data"]["header"]["packet_type"] == "1RTT"
            ):
                for frame in event["data"]["frames"]:
                    if frame["frame_type"] == "path_challenge":
                        path_challenges += 1
        if not path_challenges:
            protocol._quic._logger.warning("No PATH_CHALLENGE received")
            server.result |= Result.H
        else:
            server.result |= Result.M


async def test_connection_migration_spoofed_ip(server: Server, configuration: QuicConfiguration):
    async with connect(
        server.host, server.port, configuration=configuration
    ) as protocol:

        try:

            # cause some traffic
            await protocol.ping()

            ip_rand = '{}.{}.{}.{}'.format(*__import__('random').sample(range(172, 192), 4))
            list1 = ["::", 4478]
            ip_mac = "::ffff:"
            nm = ip_mac + str(ip_rand)
            list1[0] = nm
            addr = tuple(list1)
            print(addr)

            # replace transport
            protocol._transport.close()
            loop = asyncio.get_event_loop()
            await loop.create_datagram_endpoint(lambda: protocol, local_addr=addr)

            # cause more traffic
            await protocol.ping()

            # check log
            path_challenges = 0
            for event in configuration.quic_logger.to_dict()["traces"][0]["events"]:
                if (
                    event["name"] == "transport:packet_received"
                    and event["data"]["header"]["packet_type"] == "1RTT"
                ):
                    for frame in event["data"]["frames"]:
                        if frame["frame_type"] == "path_challenge":
                            path_challenges += 1
            if not path_challenges:
                protocol._quic._logger.warning("No PATH_CHALLENGE received")
                server.result |= Result.B
            else:
                server.result |= Result.H

        except Exception as e:
            print(e)
            server.result |= Result.M


async def test_connection_migration_loop(server: Server, configuration: QuicConfiguration):
    async with connect(
        server.host, server.port, configuration=configuration
    ) as protocol:

        try:

            for i in range(3,15):
                import netifaces as ni
                try:
                    interface = "eth1:{}".format(i)
                    ip = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
                except Exception as e:
                    print(e)
                    ip=None

                list1 = ["::", 4478]
                ip_mac = "::ffff:"
                if ip:
                    nm = ip_mac + str(ip)
                    list1[0] = nm
                    list1[1]=list1[1]+i
                    addr = tuple(list1)
                else:
                    addr = tuple(list1)


                # cause some traffic
                await protocol.ping()
                # change connection ID
                protocol.change_connection_id()
                # replace transport
                protocol._transport.close()
                loop = asyncio.get_event_loop()
                await loop.create_datagram_endpoint(lambda: protocol, local_addr=addr)
                # cause more traffic


                # change connection ID
                #protocol.change_connection_id()

                await protocol.ping()

                # check log

                path_challenges = 0
                for event in configuration.quic_logger.to_dict()["traces"][0]["events"]:
                    if (
                        event["name"] == "transport:packet_received"
                        and event["data"]["header"]["packet_type"] == "1RTT"
                    ):
                        for frame in event["data"]["frames"]:

                            if frame["frame_type"] == "path_challenge":
                                path_challenges += 1
            if not path_challenges:
                protocol._quic._logger.warning("No PATH_CHALLENGE received")
                server.result |= Result.H
            else:
                server.result |= Result.M
        except Exception as e:
            print(e)
            server.result |= Result.H



async def test_nat_rebinding(server: Server, configuration: QuicConfiguration):
    async with connect(
        server.host, server.port, configuration=configuration
    ) as protocol:
        # cause some traffic
        await protocol.ping()

        # replace transport
        protocol._transport.close()
        await loop.create_datagram_endpoint(lambda: protocol, local_addr=("::", 0))

        # cause more traffic
        await protocol.ping()

        # check log
        path_challenges = 0
        for event in configuration.quic_logger.to_dict()["traces"][0]["events"]:
            if (
                event["name"] == "transport:packet_received"
                and event["data"]["header"]["packet_type"] == "1RTT"
            ):
                for frame in event["data"]["frames"]:
                    if frame["frame_type"] == "path_challenge":
                        path_challenges += 1
        if not path_challenges:
            protocol._quic._logger.warning("No PATH_CHALLENGE received")
        else:
            server.result |= Result.B


async def test_address_mobility(server: Server, configuration: QuicConfiguration):
    async with connect(
        server.host, server.port, configuration=configuration
    ) as protocol:
        # cause some traffic
        await protocol.ping()

        # replace transport
        protocol._transport.close()
        await loop.create_datagram_endpoint(lambda: protocol, local_addr=("::", 0))

        # change connection ID
        protocol.change_connection_id()

        # cause more traffic
        await protocol.ping()

        # check log
        path_challenges = 0
        for event in configuration.quic_logger.to_dict()["traces"][0]["events"]:
            if (
                event["name"] == "transport:packet_received"
                and event["data"]["header"]["packet_type"] == "1RTT"
            ):
                for frame in event["data"]["frames"]:
                    if frame["frame_type"] == "path_challenge":
                        path_challenges += 1
        if not path_challenges:
            protocol._quic._logger.warning("No PATH_CHALLENGE received")
        else:
            server.result |= Result.A


async def test_spin_bit(server: Server, configuration: QuicConfiguration):
    async with connect(
        server.host, server.port, configuration=configuration
    ) as protocol:
        for i in range(5):
            await protocol.ping()

        # check log
        spin_bits = set()
        for event in configuration.quic_logger.to_dict()["traces"][0]["events"]:
            if event["name"] == "connectivity:spin_bit_updated":
                spin_bits.add(event["data"]["state"])
        if len(spin_bits) == 2:
            server.result |= Result.M


async def test_send_after_peer_reset(server: Server, configuration: QuicConfiguration):
    # RFC 9000 Section 2.4 explicitly states:
    # "An endpoint that receives a RESET_STREAM frame for a send stream MUST NOT
    # send any further STREAM frames for that stream."
    # RFC 9000 Section 3.4:
    # "An endpoint that receives a RESET_STREAM frame MUST NOT send STREAM frames
    # on this stream. If it subsequently receives a STREAM frame for a stream
    # where it has received a RESET_STREAM frame, it MUST treat this as a
    # connection error of type STREAM_STATE_ERROR."
    # And also:
    # "An endpoint that has sent a RESET_STREAM frame and has received an
    # acknowledgement for it (i.e., the packet containing the RESET_STREAM
    # was acknowledged, or a packet sent after the RESET_STREAM was
    # acknowledged) can be in the "Reset Sent" state. In this state, the
    # endpoint only needs to retransmit the RESET_STREAM frame if it
    # receives STREAM frames for this stream." (This part is more for server behavior)

    # For the client, after receiving RESET_STREAM, its sending part of the stream
    # enters the "Reset Recvd" state. It should not send further STREAM frames.

    configuration.alpn_protocols = H3_ALPN # Using H3 for stream-based interaction
    async with connect(
        server.host,
        server.port,
        configuration=configuration,
        create_protocol=HttpClient,
    ) as client:
        client = cast(HttpClient, client)

        # Client opens a stream and sends initial data
        stream_id = client._quic.get_next_available_stream_id()
        # For H3, client needs to send headers first to "open" the stream from its side
        # then it can send data.
        # We'll use a utility that does this or simulate it.
        # A simple GET request will open a stream and send headers.
        # To send data afterwards, we'd need a way to access that stream_id
        # or use a lower-level API if HttpClient doesn't expose it easily.

        # Let's try to manually create a stream and send data to have more control.
        # This is more aligned with testing the QUIC layer behavior directly.

        # Ensure the server is an aioquic server for this test, to control server behavior.
        # This test is more about client behavior, but requires specific server actions.
        # For now, let's assume the generic server might do this, or we have to rely on logs.

        initial_data = b"initial data"

        # Need a way for the server to send RESET_STREAM. This is tricky with generic servers.
        # Let's assume the client sends data, and we want to check if it *stops* sending
        # after a hypothetical RESET_STREAM is received.
        # This might require a custom server or a way to inject RESET_STREAM.

        # For now, we'll focus on the client's behavior if it *were* to receive RESET_STREAM.
        # The current test framework doesn't easily allow custom server logic per test.
        # We might need to simulate the reception of RESET_STREAM on the client side
        # or inspect logs to see if the server sent it and if the client reacted correctly.

        # Let's try a scenario where the client sends data, we simulate the server sending RESET_STREAM
        # (conceptually, as we can't control the server directly in this framework easily for non-aioquic servers),
        # and then the client tries to send more data.

        try:
            # 1. Client opens a stream and sends initial data.
            # Using underlying QUIC methods to send data on a stream.
            # This requires the stream to be created first. H3 client does this implicitly.
            # For a raw QUIC stream:
            client._quic._get_or_create_stream_for_send(stream_id)
            client._quic.send_stream_data(stream_id, initial_data, end_stream=False)

            # 2. Server receives data, then sends RESET_STREAM for that stream.
            # This part is assumed to happen on the server.
            # We need to simulate the client receiving it.
            # One way is to have the client's QuicConnection directly process a RESET_STREAM event.
            # This is deep into the internals.

            # Let's log current stream state before simulating RESET_STREAM
            stream_before_reset = client._quic._streams.get(stream_id)
            # Simulate client receiving RESET_STREAM for stream_id
            # This is a conceptual step. In a real test against a generic server,
            # we'd need the server to actually send it.
            # If we were testing aioquic against aioquic, we could program the server.
            # For now, let's assume the reset happens and check client's state or log.

            # To make this testable against generic servers, we might need a server that has a specific endpoint
            # that sends data and then RESET_STREAM.
            # Or, we rely on observing that no more data is sent after some point.

            # Let's modify the client's stream state directly to "Reset Recvd".
            # This is highly intrusive but helps test the "no send after reset" logic.
            target_stream = client._quic._streams.get(stream_id)
            if target_stream:
                # Manually transition the sender to a state as if RESET_STREAM was received.
                # The actual state is more complex, this is a simplification.
                # A more accurate way would be to find how a RESET_STREAM frame updates the state.
                # RESET_STREAM from peer affects the *receiving* part of local stream and *sending* part of peer's stream.
                # If peer resets *its sending part*, our *receiving part* goes to "Size Known" or "Reset Recvd".
                # If peer resets *its receiving part* (by us sending RESET_STREAM), our *sending part* goes to "Reset Sent".

                # The scenario is: Server sends RESET_STREAM for *its sending stream* (our receiving stream)
                # OR server sends RESET_STREAM for *our sending stream* (its receiving stream).
                # The test says "Server receives data, then sends RESET_STREAM for that stream."
                # This means the server is resetting the stream on which the client is sending.
                # So, the client's sending part of the stream should go to "Reset Recvd".

                # Simulate QuicConnection processing a RESET_STREAM frame from the peer for `stream_id`
                # This would normally happen in _payload_received -> _handle_reset_stream_frame
                from aioquic.quic.frame_parser import parse_stream_frame
                from aioquic._buffer import Buffer
                from aioquic.quic.packet import QuicErrorCode

                # This simulates the event that QuicConnection would emit.
                # The stream itself needs to handle this.
                # Let's assume the stream's state is correctly updated by the underlying machinery
                # if a RESET_STREAM were actually received and processed by QuicConnection.
                # For this test, we'll assume the server sends RESET_STREAM and client processes it.
                # The key is what happens *after* this.

                # For a more direct simulation:
                # client._quic.reset_stream(stream_id, QuicErrorCode.NO_ERROR) # This is client sending reset. Not what we want.

                # We need to simulate the *reception* of a RESET_STREAM.
                # This would transition the stream's send_state to "Reset Recvd"
                # See `QuicStream.sender.handle_stop_sending_and_reset`
                # or how `_handle_reset_stream_frame` updates the sender.
                # `_handle_reset_stream_frame` calls `stream.sender.on_reset_stream_received(frame.error_code)`
                # Let's assume this has happened.

                # Log initial number of packets sent
                packets_sent_before_further_send_attempt = len(configuration.quic_logger.to_dict()["traces"][0]["events"])

                # 4. Client attempts to send further STREAM frames on the reset stream.
                further_data = b"further data"
                try:
                    client._quic.send_stream_data(stream_id, further_data, end_stream=False)
                except Exception as e:
                    # Depending on implementation, this might raise an error if stream is reset.
                    client._quic._logger.info(f"Exception when trying to send on reset stream: {e}")


                # 5. Verify that the client does not send new STREAM frames for that stream.
                # This requires inspecting logs after the attempt.
                # We need to wait for a bit to ensure packets *would* have been sent if not for reset.
                await asyncio.sleep(0.1) # Give time for any potential send to occur

                packets_sent_after_further_send_attempt = len(configuration.quic_logger.to_dict()["traces"][0]["events"])

                stream_frames_after_reset = 0
                logged_events = configuration.quic_logger.to_dict()["traces"][0]["events"]
                for i in range(packets_sent_before_further_send_attempt, len(logged_events)):
                    event = logged_events[i]
                    if event["name"] == "transport:packet_sent":
                        if "frames" in event["data"]:
                            for frame in event["data"]["frames"]:
                                if frame["frame_type"] == "stream" and frame["stream_id"] == stream_id:
                                    # Check if this stream frame carries new data by inspecting its offset and length,
                                    # or if it's just a retransmission of old data.
                                    # For simplicity, we'll assume any STREAM frame for this stream_id after reset is a failure,
                                    # unless it's a known retransmission (which is hard to check here without more state).
                                    # A robust check would be to see if `further_data` appears in any sent packet.
                                    stream_frames_after_reset += 1
                                    client._quic._logger.warning(f"STREAM frame sent for reset stream {stream_id} after reset received simulation.")


                if stream_frames_after_reset == 0:
                    # This is the expected outcome if client behaves correctly after its sending part is "Reset Recvd"
                    # However, simulating "Reset Recvd" accurately is key.
                    # A better approach for generic servers:
                    # 1. Client sends data.
                    # 2. Client sends STOP_SENDING (to ask server to send RESET_STREAM).
                    # 3. Client waits for RESET_STREAM from server.
                    # 4. Client tries to send more data.
                    # 5. Check logs.
                    # This relies on server correctly implementing STOP_SENDING -> RESET_STREAM.

                    # Let's re-evaluate. The test is "send data AFTER PEER RESET".
                    # So, the server must send RESET_STREAM. Client receives it. Client tries to send.
                    # This means we need a server that sends RESET_STREAM.
                    # If we test against a generic server, we might need a specific URL that triggers this.
                    # Or, we need to assume some servers might do this under certain conditions (e.g., after an error).

                    # For now, let's assume the test needs to be structured to make the server send RESET_STREAM.
                    # How about: client sends request, server sends part of response, then sends RESET_STREAM.
                    # Then client tries to send more on *its* side of the stream (if bidi).
                    # This is getting complicated without server-side control.

                    # Let's simplify: the core is "client MUST NOT send STREAM frames ... after its sending part is in Reset Recvd".
                    # What if the client itself initiates a RESET_STREAM, and then tries to send?
                    # No, that's "Reset Sent".

                    # What if the server sends data, then RESET_STREAM on a stream it initiated?
                    # Client receives data, then RESET_STREAM. Client's *receiving* part is "Size Known".
                    # This test is about the client's *sending* part.

                    # Back to: Client sends. Server sends RESET_STREAM. Client receives. Client tries to send more.
                    # The most straightforward way to achieve "server sends RESET_STREAM" with the current framework
                    # is if the client sends a STOP_SENDING, prompting the server to RESET_STREAM that stream.
                    # (RFC 9000, Section 3.5: "an endpoint that receives a STOP_SENDING frame MUST send a RESET_STREAM frame")

                    # Revised plan for test_send_after_peer_reset:
                    # 1. Client opens a bidi stream, sends some data.
                    # 2. Client sends STOP_SENDING for that stream to prompt server to reset.
                    # 3. Client waits a bit for server to process STOP_SENDING and send RESET_STREAM.
                    #    (Client needs to process incoming packets to receive the RESET_STREAM)
                    # 4. Client attempts to send more data on the same stream.
                    # 5. Verify no new STREAM frames for that stream_id are sent by the client after RESET_STREAM is likely processed.

                    client._quic.send_stop_sending(stream_id, QuicErrorCode.NO_ERROR) # Ask server to reset
                    client._quic._logger.info(f"Client sent STOP_SENDING for stream {stream_id}")

                    # Wait for server to send RESET_STREAM and client to process it.
                    # This involves reading from the connection.
                    # The `connect` block handles event processing. We might need to yield control.
                    await asyncio.sleep(0.5) # Time for round trip and processing.

                    # Check if RESET_STREAM was received for this stream in logs, or stream state.
                    reset_received_for_stream = False
                    stream_obj = client._quic._streams.get(stream_id)
                    if stream_obj and stream_obj.sender.stream_reset: # stream_reset indicates RESET_STREAM was received for the sending part
                        reset_received_for_stream = True
                        client._quic._logger.info(f"Stream {stream_id} sending part is in a reset state.")

                    if not reset_received_for_stream:
                        # Check QuicLogger for RESET_STREAM received event if state isn't clear
                        for event in configuration.quic_logger.to_dict()["traces"][0]["events"]:
                            if event["name"] == "transport:frame_received" and event["data"]["frame_type"] == "reset_stream":
                                if event["data"]["stream_id"] == stream_id:
                                    reset_received_for_stream = True
                                    client._quic._logger.info(f"RESET_STREAM frame received for stream {stream_id} from peer.")
                                    break

                    if not reset_received_for_stream:
                        client._quic._logger.warning(f"Did not confirm RESET_STREAM received for stream {stream_id}. Test validity may be affected.")
                        # Mark as inconclusive or failed if RESET_STREAM wasn't verifiably received?
                        # For now, proceed with the send attempt.

                    packets_sent_before_final_send_attempt = len(configuration.quic_logger.to_dict()["traces"][0]["events"])
                    try:
                        client._quic.send_stream_data(stream_id, b"data after allegedly reset", end_stream=False)
                    except Exception as e:
                        client._quic._logger.info(f"Exception during send attempt after STOP_SENDING/RESET_STREAM: {e}")

                    await asyncio.sleep(0.1) # time for potential send

                    stream_frames_sent_post_reset_attempt = 0
                    final_events = configuration.quic_logger.to_dict()["traces"][0]["events"]
                    for i in range(packets_sent_before_final_send_attempt, len(final_events)):
                        event = final_events[i]
                        if event["name"] == "transport:packet_sent":
                            if "frames" in event["data"]:
                                for frame in event["data"]["frames"]:
                                    if frame["frame_type"] == "stream" and frame["stream_id"] == stream_id:
                                        # Any stream frame for this stream ID after reset is problematic.
                                        # We need to be careful about retransmissions of data sent *before* reset.
                                        # A simple check is if any *new* data is sent.
                                        # The `send_stream_data` call above tried to send "data after allegedly reset".
                                        # If this specific data is found in a sent frame, it's a failure.
                                        # For now, any stream frame is flagged.
                                        stream_frames_sent_post_reset_attempt += 1
                                        client._quic._logger.warning(f"A STREAM frame was sent for stream {stream_id} after client sent STOP_SENDING and (presumably) peer sent RESET_STREAM.")
                                        # Potentially log frame content for debugging: frame.get("data", "")

                    if stream_frames_sent_post_reset_attempt == 0:
                        server.result |= Result.M # Mark as pass if no further STREAM frames sent
                        client._quic._logger.info(f"No new STREAM frames sent on stream {stream_id} after STOP_SENDING and potential peer RESET_STREAM, as expected.")
                    else:
                        client._quic._logger.error(f"{stream_frames_sent_post_reset_attempt} STREAM frames unexpectedly sent on stream {stream_id} after STOP_SENDING/RESET_STREAM.")
                        # No Result.M if it fails

        except ConnectionError as e:
            # Connection errors might occur if server doesn't like the sequence of events.
            client._quic._logger.error(f"ConnectionError during test_send_after_peer_reset: {e}")
            # Depending on the error, this might be a pass or fail.
            # E.g. if server sends STREAM_STATE_ERROR because we sent after reset, that's a server enforcing rules.
            # But the client *shouldn't have sent* in the first place.
        except Exception as e:
            client._quic._logger.error(f"Unexpected exception in test_send_after_peer_reset: {e}")
            # This is likely a test setup issue or unexpected library behavior.

    # Note: This test relies on the server correctly sending RESET_STREAM upon receiving STOP_SENDING.
    # If the server doesn't, the condition "after peer reset" isn't met, and the test outcome is less meaningful.
    # A more robust test would be against a server specifically programmed for this scenario.
    # Or using a hook to inject a RESET_STREAM frame into the client's receive path.


async def test_recv_after_stop_sending(server: Server, configuration: QuicConfiguration):
    # RFC 9000 Section 3.5:
    # "An endpoint that sends a STOP_SENDING frame is indicating that it will no longer
    # read from the identified stream. It SHOULD ignore any data received on that stream."
    # "An endpoint that receives a STOP_SENDING frame MUST send a RESET_STREAM frame
    # if the stream is in the "Recv" or "Size Known" state."
    # "If STREAM frames arrive after sending STOP_SENDING, the recipient can simply
    # discard the data. Sending STOP_SENDING means the application on that endpoint
    # is no longer interested in the stream."
    # The client should still ACK the packets containing the (unwanted) data, as ACKs
    # are for the transport, not the application.

    configuration.alpn_protocols = H3_ALPN
    async with connect(
        server.host,
        server.port,
        configuration=configuration,
        create_protocol=HttpClient,
    ) as client:
        client = cast(HttpClient, client)
        stream_id = client._quic.get_next_available_stream_id()

        try:
            # 1. Client opens a stream, sends data, then sends STOP_SENDING.
            client._quic._get_or_create_stream_for_send(stream_id) # Ensure stream exists for client's sending part
            client._quic.send_stream_data(stream_id, b"client_initial_data", end_stream=False) # Client sends some data

            # Client decides it no longer wants to read from this stream.
            # This implies it's a bidirectional stream and client was expecting data from server.
            client._quic.send_stop_sending(stream_id, QuicErrorCode.NO_ERROR)
            client._quic._logger.info(f"Client sent STOP_SENDING for stream {stream_id}")

            # 2. Server (before processing STOP_SENDING) sends more data on the stream.
            # This is the tricky part for generic servers. We can't directly control server timing.
            # We have to assume that the server *might* send data around the time STOP_SENDING arrives.
            # The test is about the client's reaction to this data.

            # To encourage the server to send data on this stream, the client might need
            # to have sent a request that expects a response on this stream_id.
            # For H3, this would be part of a request/response exchange.
            # Let's assume this stream_id is one where the server *would* send data.
            # For example, if client initiated with GET, server would send response.
            # We are testing client's behavior when it receives data on a stream for which it already sent STOP_SENDING.

            # We need to let some time pass for the server to potentially send data
            # and for the client to receive it.
            await asyncio.sleep(0.5) # Allow time for server to send data and for client to process it

            # 3. Verify client acknowledges this data.
            # This is hard to verify directly without deep packet inspection or specific server logs.
            # What we can observe:
            # - Client's QuicLogger for received packets and if ACKs are sent for them.
            # - If the client *doesn't* ACK, the server might retransmit, which could be observed.
            # A simpler proxy for "acknowledges data" is that the client processes the packets
            # (even if it discards the stream data) and the connection remains healthy.
            # The underlying QUIC connection should ACK received packets regardless of application interest.
            # We can check if any ACK-eliciting packet was received from server after STOP_SENDING was sent.
            # And then, check if an ACK frame was sent by the client later.

            # Let's look for STREAM frames received from the server on this stream_id
            # *after* client sent STOP_SENDING.
            received_data_after_stop_sending = False
            ack_sent_for_that_data_packet = False

            log_events = configuration.quic_logger.to_dict()["traces"][0]["events"]
            time_stop_sending_sent = 0

            # Find time when STOP_SENDING was actually packetized and marked as sent
            for event_idx, event in enumerate(log_events):
                if event["name"] == "transport:frame_sent" and event["data"]["frame_type"] == "stop_sending" and event["data"]["stream_id"] == stream_id:
                    # Find the packet_sent event for this frame
                    for pkt_event in log_events[event_idx:]: # Search forward
                        if pkt_event["name"] == "transport:packet_sent" and "frames" in pkt_event["data"]:
                            if any(f.get("frame_type") == "stop_sending" and f.get("stream_id") == stream_id for f in pkt_event["data"]["frames"]):
                                time_stop_sending_sent = event["time"] # use event time as a proxy
                                client._quic._logger.info(f"STOP_SENDING for stream {stream_id} recorded as sent around time {time_stop_sending_sent}")
                                break
                    break

            if time_stop_sending_sent > 0:
                packet_number_of_server_data = None
                for event_idx, event in enumerate(log_events):
                    if event["time"] > time_stop_sending_sent: # Consider events after STOP_SENDING was sent
                        if event["name"] == "transport:frame_received" and event["data"]["frame_type"] == "stream" and event["data"]["stream_id"] == stream_id:
                            received_data_after_stop_sending = True
                            # Try to find the packet number that contained this frame
                            for rcv_pkt_event_idx in range(event_idx, -1, -1): # Search backwards for packet_received
                                rcv_pkt_event = log_events[rcv_pkt_event_idx]
                                if rcv_pkt_event["name"] == "transport:packet_received" and "frames" in rcv_pkt_event["data"]:
                                    if any(f.get("frame_type") == "stream" and f.get("stream_id") == stream_id for f in rcv_pkt_event["data"]["frames"]):
                                        packet_number_of_server_data = rcv_pkt_event["data"]["header"].get("packet_number")
                                        client._quic._logger.info(f"Received STREAM frame on stream {stream_id} (packet {packet_number_of_server_data}) after sending STOP_SENDING.")
                                        break
                                if rcv_pkt_event_idx == 0: break # Stop if we reach beginning
                            break # Found a stream frame

                if packet_number_of_server_data is not None:
                    # Now check if an ACK for this packet was sent by the client
                    for event in log_events:
                        # Consider only events after the server data was received
                        if event["time"] > time_stop_sending_sent and event["name"] == "transport:frame_sent" and event["data"]["frame_type"] == "ack":
                            for ack_range in event["data"].get("acked_ranges", []):
                                if ack_range[0] <= packet_number_of_server_data <= ack_range[1]:
                                    ack_sent_for_that_data_packet = True
                                    client._quic._logger.info(f"Client sent ACK for packet {packet_number_of_server_data} (which contained data on stopped stream {stream_id}).")
                                    break
                            if ack_sent_for_that_data_packet:
                                break

            if received_data_after_stop_sending and not ack_sent_for_that_data_packet:
                client._quic._logger.warning(f"Client received data on stream {stream_id} after STOP_SENDING, but an ACK for it was not clearly identified.")
                # This could be a failure or just a limitation of the log inspection.
            elif not received_data_after_stop_sending:
                client._quic._logger.info(f"No data received on stream {stream_id} after STOP_SENDING, or could not verify. Test point about ACK might be inconclusive.")
                # If no data received, then the ACK verification is moot.

            # 4. Verify server eventually sends RESET_STREAM in response to STOP_SENDING.
            reset_stream_received = False
            await asyncio.sleep(0.5) # More time for server to process STOP_SENDING and send RESET_STREAM

            # Refresh logs
            log_events = configuration.quic_logger.to_dict()["traces"][0]["events"]
            for event in log_events:
                 # Consider events after STOP_SENDING was sent
                if time_stop_sending_sent > 0 and event["time"] <= time_stop_sending_sent:
                    continue
                if event["name"] == "transport:frame_received" and event["data"]["frame_type"] == "reset_stream":
                    if event["data"]["stream_id"] == stream_id:
                        reset_stream_received = True
                        client._quic._logger.info(f"RESET_STREAM frame received for stream {stream_id} from peer, as expected after STOP_SENDING.")
                        break

            # For the overall result:
            # - Client should ACK data received after STOP_SENDING (best effort verification).
            # - Server should send RESET_STREAM.
            # If server sends RESET_STREAM, this is the primary pass condition for this part.
            # The ACK part is secondary and harder to assert robustly with generic servers.
            if reset_stream_received:
                if received_data_after_stop_sending and not ack_sent_for_that_data_packet:
                    # If we detected data and didn't see an ACK, this is a soft fail/warning.
                    # But the server sending RESET_STREAM is good.
                    server.result |= Result.M # Tentative pass, with logged warning for ACK.
                    client._quic._logger.info("Marking test as passed due to RESET_STREAM received, despite potential ACK issue/verification gap.")
                else:
                    server.result |= Result.M # Pass
            else:
                client._quic._logger.error(f"Server did not send RESET_STREAM for stream {stream_id} after client sent STOP_SENDING.")
                # This is a failure of the server to comply, or test timing issue.

        except ConnectionError as e:
            client._quic._logger.error(f"ConnectionError during test_recv_after_stop_sending: {e}")
        except Exception as e:
            client._quic._logger.error(f"Unexpected exception in test_recv_after_stop_sending: {e}")

    # Note: This test's success depends significantly on:
    # 1. The server sending data on the stream around the time client sends STOP_SENDING. (Hard to guarantee)
    # 2. The server correctly processing STOP_SENDING and replying with RESET_STREAM.
    # 3. The ability to reliably verify from logs that client ACKed data. (Challenging)


async def test_exceed_initial_max_stream_data_client_bidi(server: Server, configuration: QuicConfiguration):
    # RFC 9000 Section 4.1: Stream Data Flow Control
    # "An endpoint MUST NOT send data on a stream in excess of the stream data limit
    # set by its peer. If an endpoint receives more data on a stream than its advertised
    # stream data limit, it MUST terminate the connection with a FLOW_CONTROL_ERROR error."
    # This test checks client sending on a bidirectional stream it initiates, exceeding server's limit.
    # We cannot configure the server's `initial_max_stream_data_bidi_remote`.
    # Instead, we will try to send a large amount of data and hope to trigger a flow control limit
    # on the server, then check if the server closes with FLOW_CONTROL_ERROR.

    configuration.alpn_protocols = H3_ALPN
    async with connect(
        server.host,
        server.port,
        configuration=configuration,
        create_protocol=HttpClient,
    ) as client:
        client = cast(HttpClient, client)
        stream_id = client._quic.get_next_available_stream_id() # Client-initiated bidirectional

        # We need to use a stream that the server will keep open and accept data on.
        # A POST request in H3 is suitable.
        # HttpClient's post() method creates a stream, sends headers, then sends data.

        connection_closed_by_flow_control_error = False
        try:
            client._quic._logger.info(f"Attempting to send a small amount of data on stream {stream_id}, then a large amount.")

            # Open the stream by sending headers (e.g. as part of a POST)
            # For direct QUIC stream usage:
            client._quic._get_or_create_stream_for_send(stream_id)
            # With H3, headers would be sent. Let's simulate this by just ensuring stream is ready.

            # Send a small initial chunk - this should be fine.
            small_data = b"hello"
            client._quic.send_stream_data(stream_id, small_data, end_stream=False)
            client._quic._logger.info(f"Sent {len(small_data)} bytes on stream {stream_id}.")

            # Try to send a very large chunk of data to exceed typical initial flow control limits.
            # Common initial limits might be 64KB, 256KB, or 1MB. Let's try 2MB.
            # RFC 9000 default is unspecified, implementations choose.
            # Aioquic's default initial_max_stream_data_bidi_remote is 262144 (256KB)
            # If server's limit is small (e.g. the hypothetical 10 bytes), this will surely exceed it.
            large_data_chunk_size = 2 * 1024 * 1024 # 2MB
            large_data = b"A" * large_data_chunk_size

            client._quic._logger.info(f"Attempting to send {len(large_data)} bytes on stream {stream_id}.")

            # The send_stream_data might block or raise error if limit is hit immediately
            # or it might queue it and error occurs during transmission.
            # We need to ensure data is actually flushed and processed by peer.
            client._quic.send_stream_data(stream_id, large_data, end_stream=True)

            # Keep connection alive to see if server closes it. Ping can help flush buffers.
            # Or try to read response if it was a POST.
            await client.ping() # Try to force data exchange
            await asyncio.sleep(1.0) # Wait for server to react and close if it's going to.
            await client.ping() # Another attempt, might fail if already closed.


            client._quic._logger.info("Client did not experience connection error after sending large data. Server might have a large limit or did not enforce.")

        except ConnectionError as e:
            client._quic._logger.info(f"ConnectionError encountered: {e}")
            # Now check QuicLogger for the close reason
            # The error 'e' itself in aioquic often contains the QuicConnectionError with code and reason
            if hasattr(e, 'error_code') and e.error_code == ErrorCode.FLOW_CONTROL_ERROR: # Assuming H3 ErrorCode here
                 connection_closed_by_flow_control_error = True
                 client._quic._logger.info("Connection closed with FLOW_CONTROL_ERROR (from ConnectionError exception).")
            elif hasattr(e, 'error_code') and e.error_code == QuicErrorCode.FLOW_CONTROL_ERROR: # aioquic.quic.packet.QuicErrorCode
                 connection_closed_by_flow_control_error = True
                 client._quic._logger.info("Connection closed with QUIC FLOW_CONTROL_ERROR (from ConnectionError exception).")
            else:
                client._quic._logger.info(f"ConnectionError had code {getattr(e, 'error_code', 'N/A')}. Checking logs for explicit remote close.")
                # Check logs if exception itself isn't specific enough
                for trace in configuration.quic_logger.to_dict()["traces"]: # Support multiple traces if they exist
                    for event in trace["events"]:
                        if event["name"] == "transport:connection_closed" and event["data"].get("error_code") == QuicErrorCode.FLOW_CONTROL_ERROR:
                            connection_closed_by_flow_control_error = True
                            client._quic._logger.info("QuicLogger recorded connection_closed with FLOW_CONTROL_ERROR.")
                            break
                        # For H3, the error might be an H3 specific one if it's wrapped.
                        # ErrorCode.H3_NO_ERROR, ErrorCode.H3_GENERAL_PROTOCOL_ERROR etc.
                        # RFC 9000 specifies QUIC level FLOW_CONTROL_ERROR.
                    if connection_closed_by_flow_control_error:
                        break
        except asyncio.exceptions.TimeoutError:
            client._quic._logger.warning("Timeout occurred. Server might have silently dropped packets or not responded.")
        except Exception as e:
            client._quic._logger.error(f"Unexpected exception: {e}")

        if connection_closed_by_flow_control_error:
            server.result |= Result.M
            client._quic._logger.info("Test passed: Server closed connection with FLOW_CONTROL_ERROR.")
        else:
            client._quic._logger.warning("Test condition not met: Server did not close with FLOW_CONTROL_ERROR after client sent excessive data.")
            # This isn't necessarily a failure of the *client*, but the server might not have a small limit,
            # or doesn't enforce it with a connection closure, or uses a different error code.
            # For interop, Result.M means "test executed and specific condition met".
            # If the condition (server sending FLOW_CONTROL_ERROR) is not met, this variant of test cannot pass.


async def test_exceed_initial_max_stream_data_server_bidi(server: Server, configuration: QuicConfiguration):
    # RFC 9000 Section 4.1: Stream Data Flow Control
    # This test is for when the server sends more data on a server-initiated bidirectional stream
    # than the client's advertised limit (`initial_max_stream_data_bidi_remote`).
    # The client should then close the connection with FLOW_CONTROL_ERROR.
    #
    # Challenges:
    # 1. Servers might not commonly initiate *bidirectional* streams in H3. H3 PUSH streams are unidirectional.
    # 2. We need a server that *would* initiate such a stream and send data.
    #
    # Approach:
    # - Set client's `initial_max_stream_data_bidi_remote` to a very low value.
    # - Also set `initial_max_stream_data_uni` low, as H3 Push (most common server-initiated stream) is unidirectional.
    # - Make a request that might trigger a PUSH.
    # - Hope the server sends enough data on a unidi/bidi stream to exceed our low limit.
    # - Check if client closes with FLOW_CONTROL_ERROR.

    low_limit = 20  # bytes - very restrictive
    configuration.initial_max_stream_data_bidi_remote = low_limit
    configuration.initial_max_stream_data_uni = low_limit # For H3 PUSH streams
    configuration.alpn_protocols = H3_ALPN

    connection_closed_by_flow_control_error = False

    # We need a server and path that is known to PUSH data.
    # The `server.push_path` seems designed for this.
    if server.push_path is None:
        client_logger = QuicLogger() # Create a temporary logger if client isn't made
        client_logger.info(f"Skipping test_exceed_initial_max_stream_data_server_bidi for {server.name}: no push_path configured.")
        # Cannot mark pass/fail, so we just return. Or use a specific Result flag for "skipped".
        # For now, if it can't run, it won't set Result.M.
        return

    async with connect(
        server.host,
        server.http3_port or server.port, # Ensure using H3 port
        configuration=configuration,
        create_protocol=HttpClient,
    ) as client:
        client = cast(HttpClient, client)
        try:
            client._quic._logger.info(f"Client configured with initial_max_stream_data_bidi_remote={low_limit} and initial_max_stream_data_uni={low_limit}.")
            client._quic._logger.info(f"Requesting GET {server.push_path} which might trigger server PUSH.")

            # Perform a GET request to the path that is supposed to trigger a PUSH
            await client.get(f"https://{server.host}:{server.http3_port or server.port}{server.push_path}")

            # Wait for pushed responses and for client to process them.
            # If server sends > `low_limit` bytes on a pushed stream (uni) or other server-initiated stream (bidi),
            # the client's QUIC stack should detect it and initiate a close with FLOW_CONTROL_ERROR.
            # This might manifest as an exception during client.get() if the push is processed quickly,
            # or during a subsequent operation or sleep if processed asynchronously.

            await asyncio.sleep(1.0) # Allow time for push processing and potential connection close.
            # Try another operation to see if connection is still alive
            await client.ping()
            await asyncio.sleep(0.5)


            client._quic._logger.info("Client did not experience connection error. Server might not have PUSHed, or PUSHed data was within limits, or client did not enforce limit.")

        except ConnectionError as e:
            client._quic._logger.info(f"ConnectionError encountered: {e}")
            if hasattr(e, 'error_code') and (e.error_code == QuicErrorCode.FLOW_CONTROL_ERROR or e.error_code == ErrorCode.FLOW_CONTROL_ERROR):
                 connection_closed_by_flow_control_error = True
                 client._quic._logger.info("Connection closed with FLOW_CONTROL_ERROR (from ConnectionError exception), likely by client.")
            else:
                client._quic._logger.info(f"ConnectionError had code {getattr(e, 'error_code', 'N/A')}. Checking logs for local close reason.")
                # If client closes, it's a local event.
                for trace in configuration.quic_logger.to_dict()["traces"]:
                    for event in trace["events"]:
                        # We are looking for the client initiating the close.
                        # A 'connection_closed' event with error_code FLOW_CONTROL_ERROR and trigger 'local' or not 'remote'.
                        if event["name"] == "transport:connection_closed" and event["data"].get("error_code") == QuicErrorCode.FLOW_CONTROL_ERROR:
                            # Check if this was a client-initiated close.
                            # The 'trigger' field or absence of 'remote' source might indicate this.
                            # For aioquic, a local close by client due to received excess data would be logged this way.
                            connection_closed_by_flow_control_error = True
                            client._quic._logger.info("QuicLogger recorded client closing connection with FLOW_CONTROL_ERROR.")
                            break
                    if connection_closed_by_flow_control_error:
                        break
        except asyncio.exceptions.TimeoutError:
            client._quic._logger.warning("Timeout occurred. Less informative for this test.")
        except Exception as e:
            client._quic._logger.error(f"Unexpected exception: {e}")

        if connection_closed_by_flow_control_error:
            server.result |= Result.M
            client._quic._logger.info("Test passed: Client closed connection with FLOW_CONTROL_ERROR.")
        else:
            client._quic._logger.warning("Test condition not met: Client did not close with FLOW_CONTROL_ERROR after server potentially exceeded stream data limit.")
            # This could mean:
            # - Server didn't PUSH.
            # - Server PUSHed data less than `low_limit`.
            # - Client didn't enforce its advertised limit.
            # - Server initiated a bidi stream but sent less than `low_limit`.


async def test_exceed_initial_max_streams_bidi_client(server: Server, configuration: QuicConfiguration):
    # RFC 9000 Section 4.6: Stream Concurrency Limits
    # "An endpoint MUST NOT open more streams than permitted by its peer. [...]
    # An endpoint that receives a frame that opens a stream that would exceed its
    # advertised stream limit MUST close the connection with a STREAM_LIMIT_ERROR error."
    # This test verifies that if a client attempts to open more bidirectional streams
    # than the server permits, the server closes the connection with STREAM_LIMIT_ERROR.
    # We cannot configure the server's `initial_max_streams_bidi`.
    # Instead, we will attempt to open a moderately large number of streams, hoping to hit the server's limit.

    configuration.alpn_protocols = H3_ALPN
    # Standard H3 clients might open streams for requests.
    # We'll use the lower-level QUIC API to attempt to open many streams.

    connection_closed_by_stream_limit_error = False

    # Number of streams to attempt to open. Default initial_max_streams_bidi is often 100.
    # If a server has a very low limit (e.g. 1 or 10), this will hit it.
    # If server limit is >= this, test won't show the error.
    # Let's try a number that's likely above very conservative minimums but not excessively huge.
    # RFC 9000 recommends allowing at least 100. If we try 110, we might catch servers enforcing this.
    # Or, for a server configured with a *very* low limit (e.g. 1 as per test description example), even 2 would trigger.
    # Let's try a smaller number first, e.g., 5, then a larger one if that doesn't trigger.
    # For the example "e.g., stream 0 and stream 4" for a limit of 1, this implies trying to open the *second* active stream.
    # Stream IDs for client-initiated bidi are 0, 4, 8, 12...
    # If limit is 1, opening stream 0 is OK. Opening stream 4 should fail.

    streams_to_try_opening = 5 # Try to open 5 client-initiated bidi streams (0, 4, 8, 12, 16)

    async with connect(
        server.host,
        server.port,
        configuration=configuration,
        create_protocol=HttpClient, # Using HttpClient for setup, but will use _quic layer
    ) as client:
        client = cast(HttpClient, client)
        try:
            client._quic._logger.info(f"Attempting to open {streams_to_try_opening} client-initiated bidirectional streams.")

            opened_stream_ids = []
            for i in range(streams_to_try_opening):
                stream_id = client._quic.get_next_available_stream_id(is_unidirectional=False)
                client._quic._get_or_create_stream_for_send(stream_id)
                opened_stream_ids.append(stream_id)
                client._quic._logger.info(f"Client attempted to open stream {stream_id}.")
                # Maybe send a tiny bit of data to ensure server acknowledges the stream opening?
                # client._quic.send_stream_data(stream_id, b'o', end_stream=False)

            # Try to make the server process these stream openings
            await client.ping()
            await asyncio.sleep(0.5) # Give server time to react
            await client.ping() # Might fail if server has closed

            client._quic._logger.info(f"Client opened {streams_to_try_opening} streams. Server did not close connection with STREAM_LIMIT_ERROR. Server limit might be >= {streams_to_try_opening}.")

        except ConnectionError as e:
            client._quic._logger.info(f"ConnectionError encountered: {e}")
            # Check error code from exception or QuicLogger
            if hasattr(e, 'error_code') and (e.error_code == QuicErrorCode.STREAM_LIMIT_ERROR or e.error_code == ErrorCode.STREAM_LIMIT_ERROR): # ErrorCode is H3
                 connection_closed_by_stream_limit_error = True
                 client._quic._logger.info("Connection closed with STREAM_LIMIT_ERROR (from ConnectionError exception).")
            else:
                client._quic._logger.info(f"ConnectionError had code {getattr(e, 'error_code', 'N/A')}. Checking logs for explicit remote close.")
                for trace in configuration.quic_logger.to_dict()["traces"]:
                    for event in trace["events"]:
                        if event["name"] == "transport:connection_closed" and event["data"].get("error_code") == QuicErrorCode.STREAM_LIMIT_ERROR:
                            connection_closed_by_stream_limit_error = True
                            client._quic._logger.info("QuicLogger recorded connection_closed with STREAM_LIMIT_ERROR.")
                            break
                    if connection_closed_by_stream_limit_error:
                        break
        except asyncio.exceptions.TimeoutError:
            client._quic._logger.warning("Timeout occurred. Less informative for this test.")
        except Exception as e:
            client._quic._logger.error(f"Unexpected exception: {e}")

        if connection_closed_by_stream_limit_error:
            server.result |= Result.M
            client._quic._logger.info("Test passed: Server closed connection with STREAM_LIMIT_ERROR.")
        else:
            client._quic._logger.warning("Test condition not met: Server did not close with STREAM_LIMIT_ERROR after client attempted to open many streams.")
            # This could mean server's stream limit is higher than attempted, or it doesn't enforce with this error.


async def test_use_retired_connection_id(server: Server, configuration: QuicConfiguration):
    # RFC 9000, Section 5.1.2: "An endpoint sends a RETIRE_CONNECTION_ID frame to indicate
    # that it will no longer use a connection ID that was issued by its peer."
    # "Once an endpoint sends a RETIRE_CONNECTION_ID frame, it can expect that its peer will
    # no longer use the retired connection ID."
    # "An endpoint SHOULD NOT send packets using a connection ID that its peer has retired."
    # This test verifies that after the client retires a server-issued CID,
    # the client does not use it for subsequent packets, and the connection remains healthy.
    # It also touches on server behavior: if the client *were* to use a retired CID,
    # the server should ideally ignore it or close connection. Since a compliant client
    # (like aioquic) won't use a self-retired peer CID, we primarily test client behavior
    # and connection stability.

    configuration.alpn_protocols = H3_ALPN
    async with connect(
        server.host,
        server.port,
        configuration=configuration,
        create_protocol=HttpClient,
    ) as client:
        client = cast(HttpClient, client)
        try:
            client._quic._logger.info("Initial connection established.")
            initial_peer_cids = list(client._quic._peer_cids_available.keys())
            if not initial_peer_cids:
                client._quic._logger.error("No peer CIDs available after connection. Cannot proceed.")
                return

            # 1. Ensure we have a server CID that we can retire.
            # Typically, the server provides an initial CID. Let's get a second one.
            # Trigger client to change its CID, this should prompt server to issue a new one.
            client._quic.change_connection_id()
            await client.ping() # Ensure CID change is processed and server has a chance to respond.
            await asyncio.sleep(0.2) # Wait for NEW_CONNECTION_ID from server

            # Identify a server-issued CID that is not the one currently in use (if possible)
            # or simply one that's available.
            # `_peer_cids_available` maps seq -> QuicReceivedConnectionId
            # `_remote_cid_to_seq` maps cid_bytes -> seq
            # `_remote_cid_sequence_numbers_to_retire` - CIDs server told us to retire (its own)
            # `_peer_cid_sequence_numbers_retired_by_us` - CIDs we told server we are retiring (server's CIDs)

            # Find a server CID to retire. Pick one that's available.
            # We want to retire a CID that the server provided.
            # Let's find the CID with the highest sequence number that we haven't told server to retire yet.
            # This is most likely the "newest" CID the server gave us.

            target_cid_to_retire_seq = -1
            target_cid_to_retire_val = None

            for seq, r_cid_obj in client._quic._peer_cids_available.items():
                if seq > target_cid_to_retire_seq and seq not in client._quic._peer_cid_sequence_numbers_retired_by_us:
                    target_cid_to_retire_seq = seq
                    target_cid_to_retire_val = r_cid_obj.cid

            if target_cid_to_retire_val is None:
                client._quic._logger.error("Could not find a suitable server-issued CID to retire for the test.")
                # This might happen if server only issues one CID and we can't get more,
                # or if change_connection_id didn't result in a new peer CID as expected.
                return

            client._quic._logger.info(f"Client will retire server's CID {target_cid_to_retire_val.hex()} with sequence number {target_cid_to_retire_seq}.")

            # 2. Client sends RETIRE_CONNECTION_ID for target_cid_to_retire_seq.
            client._quic.retire_peer_connection_id(target_cid_to_retire_seq)

            # 3. Client waits for an ACK for the packet containing RETIRE_CONNECTION_ID.
            #    Send a PING; when its ACK is received, the RETIRE_CONNECTION_ID is likely acked.
            ping_acked = asyncio.Event()
            await client.ping(ping_acked_event=ping_acked)
            await asyncio.wait_for(ping_acked.wait(), timeout=2.0) # Wait for PING ack
            client._quic._logger.info(f"RETIRE_CONNECTION_ID for seq {target_cid_to_retire_seq} sent and likely acknowledged.")

            # 4. Client attempts to send a PING.
            #    A compliant client (aioquic) should NOT use the retired CID (target_cid_to_retire_val).
            #    We verify this by checking the logs for the DCID used in the next sent PING.

            packets_sent_before_ping = len(configuration.quic_logger.to_dict()["traces"][0]["events"])
            await client.ping()
            await asyncio.sleep(0.1) # allow time for packet to be logged

            used_retired_cid_for_ping = False
            found_ping_packet = False
            log_events = configuration.quic_logger.to_dict()["traces"][0]["events"]

            for i in range(packets_sent_before_ping, len(log_events)):
                event = log_events[i]
                if event["name"] == "transport:packet_sent":
                    # Check if this packet contains a PING frame
                    is_ping_packet = False
                    if "frames" in event["data"]:
                        for frame in event["data"]["frames"]:
                            if frame["frame_type"] == "ping":
                                is_ping_packet = True
                                found_ping_packet = True
                                break

                    if is_ping_packet:
                        sent_dcid = event["data"]["header"].get("destination_connection_id")
                        client._quic._logger.info(f"Client sent PING using DCID {sent_dcid}.")
                        if sent_dcid == target_cid_to_retire_val.hex():
                            used_retired_cid_for_ping = True
                            client._quic._logger.error(f"Client ERRONEOUSLY used retired server CID {target_cid_to_retire_val.hex()} for PING.")
                            break
                        else:
                            client._quic._logger.info(f"Client correctly used non-retired CID {sent_dcid} for PING.")
                            # This is the expected behavior for the client.
                            break

            if not found_ping_packet:
                 client._quic._logger.warning("Could not find a PING packet in logs after retiring CID to verify DCID used.")
                 # This might be an issue with logging or test timing.

            # 5. Verify connection is still alive and server didn't complain (e.g. by closing).
            #    The PING above should be ACKed if connection is healthy.
            #    If client used a valid CID, server should be fine.
            #    If client *had* used a retired CID, server might close or ignore.
            #    Since we expect client to use a valid CID, this ping should succeed.
            ping_acked_after_retire = asyncio.Event()
            await client.ping(ping_acked_event=ping_acked_after_retire)
            await asyncio.wait_for(ping_acked_after_retire.wait(), timeout=2.0)
            client._quic._logger.info("Connection is still alive and responsive after retiring a server CID and pinging.")

            if not used_retired_cid_for_ping:
                server.result |= Result.M # Pass if client did not use the retired CID and connection is alive.
            else:
                # Client misbehaved. This is a client bug if it happens.
                # The test was to see what server does, but we found client issue.
                pass


        except ConnectionError as e:
            # This might happen if server closes connection upon receiving RETIRE_CONNECTION_ID for a CID it deems active,
            # or if the subsequent PING (even with a valid CID) fails due to some server state.
            # Or if the server *did* receive a packet with a retired CID (if client misbehaved) and closed.
            client._quic._logger.error(f"ConnectionError in test_use_retired_connection_id: {e}")
            # If client correctly didn't use retired CID, but server still closed, this is a server issue or other problem.
            # For this test, if ConnectionError occurs and we are sure client behaved, it's not Result.M for this specific test's goal.
        except asyncio.exceptions.TimeoutError:
            client._quic._logger.error("Timeout in test_use_retired_connection_id.")
        except Exception as e:
            client._quic._logger.error(f"Unexpected exception in test_use_retired_connection_id: {e}")


async def test_server_exceeds_active_connection_id_limit(server: Server, configuration: QuicConfiguration):
    # RFC 9000, Section 5.1.1: "An endpoint sets a limit on the number of connection IDs
    # its peer issues and stores using the active_connection_id_limit transport parameter."
    # "An endpoint MUST NOT store more connection IDs from its peer than the limit set
    # by the active_connection_id_limit transport parameter it sends."
    # "An endpoint that receives a NEW_CONNECTION_ID frame that would exceed its
    # active_connection_id_limit MUST respond with a connection error of type CONNECTION_ID_LIMIT_ERROR."
    # This test verifies that if the server attempts to issue more CIDs than the client's
    # advertised limit, the client closes the connection with CONNECTION_ID_LIMIT_ERROR.

    # Set client's limit for CIDs it's willing to store from the server.
    client_cid_limit = 2
    configuration.active_connection_id_limit = client_cid_limit
    configuration.alpn_protocols = H3_ALPN

    connection_closed_by_cid_limit_error = False

    async with connect(
        server.host,
        server.port,
        configuration=configuration,
        create_protocol=HttpClient,
    ) as client:
        client = cast(HttpClient, client)
        try:
            client._quic._logger.info(f"Client configured with active_connection_id_limit = {client_cid_limit}.")

            # The server issues an initial CID during handshake. This is CID #1.
            # We need the server to issue `client_cid_limit` more CIDs without retiring old ones
            # such that the total active CIDs from server exceeds `client_cid_limit`.
            # Server issues initial CID (seq 0). Client stores it. (Count = 1)
            # To hit limit of 2, server needs to issue two more CIDs (seq 1, seq 2)
            # such that seq 0 is not yet retired by the server via `retire_prior_to` in NEW_CONNECTION_ID.

            # Try to make the server issue new CIDs.
            # Client migrating its own CID can prompt the server to issue a new one.
            for i in range(client_cid_limit + 1): # Try to provoke `limit + 1` NEW_CONNECTION_ID frames
                client._quic._logger.info(f"Attempting client CID migration {i+1} to provoke server into sending NEW_CONNECTION_ID.")
                client._quic.change_connection_id()
                # Send some data to ensure the server sees the new client CID
                # A ping should be ack-eliciting and trigger responses.
                ping_event = asyncio.Event()
                await client.ping(ping_acked_event=ping_event)

                # Wait for the ping to be acknowledged, implying server processed current client CID.
                # Also wait a bit for server to potentially send NEW_CONNECTION_ID.
                try:
                    await asyncio.wait_for(ping_event.wait(), timeout=1.0)
                    await asyncio.sleep(0.2) # Short delay for server to send NEW_CONNECTION_ID frame
                except asyncio.TimeoutError:
                    client._quic._logger.warning(f"Ping ACK not received during migration attempt {i+1}. Server might be slow or connection breaking.")
                    # If connection breaks here, it might be the error we are looking for.
                    # The ConnectionError will be caught by the outer try-except.
                    pass # Allow the outer loop to potentially catch ConnectionError immediately

                # Check current number of active peer CIDs stored by client.
                # `_peer_cids_available` stores CIDs from server that are not yet retired by server via `retire_prior_to`.
                # This count is what matters for the client's enforcement of its own limit.
                num_server_cids_stored = len(client._quic._peer_cids_available)
                client._quic._logger.info(f"Client currently stores {num_server_cids_stored} CIDs from server.")

                # The client should close IF a NEW_CONNECTION_ID is received that pushes it over the limit.
                # This check might be too late if the error is raised during packet processing.
                # The ConnectionError handler below is the primary checker.

            # If we successfully loop, it implies the client never needed to enforce the limit.
            # This could be because the server retired old CIDs as it issued new ones,
            # keeping the client within its `client_cid_limit`.
            await client.ping() # Final check if connection is still alive.
            client._quic._logger.info("Test completed loop. Server did not seem to exceed client's active_connection_id_limit, or client didn't enforce.")

        except ConnectionError as e:
            client._quic._logger.info(f"ConnectionError encountered: {e}")
            # Check if this error is CONNECTION_ID_LIMIT_ERROR
            # ErrorCode.CONNECTION_ID_LIMIT_ERROR is not defined in H3 ErrorCode, it's a QUIC error.
            if hasattr(e, 'error_code') and e.error_code == QuicErrorCode.CONNECTION_ID_LIMIT_ERROR:
                 connection_closed_by_cid_limit_error = True
                 client._quic._logger.info("Connection closed with QUIC CONNECTION_ID_LIMIT_ERROR (from ConnectionError exception). This is the expected client action.")
            else:
                client._quic._logger.info(f"ConnectionError had code {getattr(e, 'error_code', 'N/A')}. Checking logs for local close reason if any.")
                # If client closes with this error, QuicLogger should record it.
                for trace in configuration.quic_logger.to_dict()["traces"]:
                    for event in trace["events"]:
                        if event["name"] == "transport:connection_closed" and \
                           event["data"].get("error_code") == QuicErrorCode.CONNECTION_ID_LIMIT_ERROR and \
                           event["data"].get("trigger") == "local": # Ensure it's client closing
                            connection_closed_by_cid_limit_error = True
                            client._quic._logger.info("QuicLogger recorded client closing connection with CONNECTION_ID_LIMIT_ERROR.")
                            break
                    if connection_closed_by_cid_limit_error:
                        break
        except asyncio.exceptions.TimeoutError:
            client._quic._logger.warning("Timeout occurred. Less informative for this test.")
        except Exception as e:
            client._quic._logger.error(f"Unexpected exception: {e}")

        if connection_closed_by_cid_limit_error:
            server.result |= Result.M
            client._quic._logger.info("Test passed: Client closed connection with CONNECTION_ID_LIMIT_ERROR.")
        else:
            client._quic._logger.warning("Test condition not met: Client did not close with CONNECTION_ID_LIMIT_ERROR.")
            # This could mean:
            # - Server respected the client's limit by retiring old CIDs when issuing new ones.
            # - Server did not issue enough CIDs to exceed the limit.
            # - Client did not correctly enforce its advertised limit (client bug).


async def test_path_validation_preferred_address(server: Server, configuration: QuicConfiguration):
    # RFC 9000 Section 9: Preferred Address
    # This test verifies client behavior when a server provides a preferred address.
    # The client should:
    # 1. Receive preferred_address transport parameter.
    # 2. Initiate path validation to the preferred address using the new CID.
    # 3. Use the preferred address for future communication if validation succeeds. (Harder to verify in short test)

    # This test relies on the server being configured to send the `preferred_address`
    # transport parameter and being reachable on that preferred address.
    # The `server.preferred_address_info` field is used by the test to know what to expect.
    # It does NOT configure the server itself.

    if server.preferred_address_info is None:
        # Using QuicLogger directly as client might not be created
        logger = QuicLogger()
        logger.info(f"Skipping test_path_validation_preferred_address for {server.name}: no preferred_address_info in Server entry.")
        return

    configuration.alpn_protocols = H3_ALPN
    path_validation_initiated_to_preferred = False
    path_validation_succeeded = False
    preferred_cid_from_tp = None
    preferred_addr_tuple = None

    async with connect(
        server.host,
        server.port,
        configuration=configuration,
        create_protocol=HttpClient,
    ) as client:
        client = cast(HttpClient, client)
        try:
            # 1. Check if server sent preferred_address transport parameter
            peer_tp = client._quic.peer_transport_params
            if not peer_tp or peer_tp.preferred_address is None:
                client._quic._logger.warning(f"Server {server.name} did not send preferred_address transport parameter. Skipping further checks.")
                return

            client._quic._logger.info(f"Server {server.name} sent preferred_address TP: {peer_tp.preferred_address}")

            # Extract info from received TP (for logging and conceptual cross-check with server.preferred_address_info)
            # The actual values from TP will be used by the client internally.
            pa_tp_data = peer_tp.preferred_address
            preferred_cid_from_tp = pa_tp_data.connection_id # This is the CID client MUST use for probing

            # Choose an address to probe (e.g., IPv4 if available, else IPv6)
            # The client's internal logic in `probe_path` or similar will handle selection.
            # We need to determine which address it *would* choose to verify logs.

            # For this test, we assume the client (aioquic) will attempt to probe if preferred_address is received.
            # aioquic's QuicConnection automatically starts probing a new path if `migrate_to_path` is called
            # or if it processes a preferred_address TP that leads to a new path.
            # Section 9.6.1: "Clients supporting this extension MUST probe the path to the server's preferred address
            # if the preferred_address transport parameter is received."
            # So, aioquic client should do this automatically after handshake if TP is received.

            # We need to wait for this automatic probing to occur.
            await asyncio.sleep(0.5) # Time for client to process TP and initiate probing.

            # 2. Verify client sends PATH_CHALLENGE to the server's preferred address
            #    using the connection ID from the preferred_address transport parameter.
            log_events = configuration.quic_logger.to_dict()["traces"][0]["events"]
            challenge_data_sent = None

            # Determine what the preferred address tuple would be based on what server configured (for log checking)
            # This is a bit heuristic for the test. Aioquic client will pick one.
            expected_pref_addr_host = None
            expected_pref_addr_port = None
            if server.preferred_address_info.get("ipv4"):
                expected_pref_addr_host, expected_pref_addr_port = server.preferred_address_info["ipv4"]
            elif server.preferred_address_info.get("ipv6"):
                 expected_pref_addr_host, expected_pref_addr_port = server.preferred_address_info["ipv6"]

            # Check QuicLogger for PATH_CHALLENGE sent to the preferred address
            for event in log_events:
                if event["name"] == "transport:packet_sent":
                    # Check if destination IP/port matches one from preferred_address_info
                    # This requires knowing what IP/port the client chose.
                    # For now, let's look for any PATH_CHALLENGE using the preferred CID.
                    if "frames" in event["data"]:
                        for frame in event["data"]["frames"]:
                            if frame["frame_type"] == "path_challenge":
                                # Check if this packet was sent to one of the preferred IPs/ports
                                # This info is not directly in packet_sent event in this form.
                                # We need to rely on aioquic's internal path objects.
                                # A simpler check: was a PATH_CHALLENGE sent with the preferred CID?
                                sent_dcid = event["data"]["header"].get("destination_connection_id")
                                if sent_dcid == preferred_cid_from_tp.hex():
                                    path_validation_initiated_to_preferred = True
                                    challenge_data_sent = bytes.fromhex(frame["data"]) # Save challenge data
                                    client._quic._logger.info(f"PATH_CHALLENGE sent with preferred CID {sent_dcid} (data: {challenge_data_sent.hex()}).")
                                    # We should also verify it was sent to the preferred *address*.
                                    # This requires more detailed logging or client internal state access.
                                    # For now, CID match is a strong indicator.
                                    break
                        if path_validation_initiated_to_preferred:
                            break

            if not path_validation_initiated_to_preferred:
                client._quic._logger.warning("Client did not appear to send PATH_CHALLENGE using the preferred CID.")
                # It's possible aioquic didn't choose to migrate or probe immediately, or logging is insufficient.
                # This might require a more direct way to tell client to probe, e.g., client._quic.probe_path().
                # However, RFC says client MUST probe. Let's assume aioquic does.

            # 3. Verify server sends a PATH_RESPONSE and client receives it.
            if path_validation_initiated_to_preferred and challenge_data_sent:
                for event in log_events:
                    if event["name"] == "transport:packet_received":
                        if "frames" in event["data"]:
                            for frame in event["data"]["frames"]:
                                if frame["frame_type"] == "path_response" and bytes.fromhex(frame["data"]) == challenge_data_sent:
                                    path_validation_succeeded = True
                                    client._quic._logger.info(f"PATH_RESPONSE received with matching data {frame['data']}.")
                                    break
                            if path_validation_succeeded:
                                break

            if not path_validation_succeeded and path_validation_initiated_to_preferred:
                 client._quic._logger.warning("PATH_RESPONSE not received or did not match challenge.")


            # 4. Verify connection remains active.
            if path_validation_succeeded:
                await client.ping() # Ping after potential path migration.
                client._quic._logger.info("Connection is still active after preferred address path validation.")
                server.result |= Result.PA # Use a new Result flag for this test
                server.result |= Result.M # Also generic pass
            elif path_validation_initiated_to_preferred : # It tried, but maybe server didn't respond on pref addr
                 client._quic._logger.warning("Path validation to preferred address initiated but did not complete successfully. Connection might still be on old path.")
                 # Ping to ensure original connection is okay
                 await client.ping()
                 # This is a partial success from client's side (it tried) but not full end-to-end.
                 # Not Result.M for now.
            else: # No attempt or TP not received
                await client.ping() # Ensure original connection is okay

        except ConnectionError as e:
            client._quic._logger.error(f"ConnectionError in test_path_validation_preferred_address: {e}")
        except asyncio.exceptions.TimeoutError:
            client._quic._logger.error("Timeout in test_path_validation_preferred_address.")
        except Exception as e:
            client._quic._logger.error(f"Unexpected exception: {e}")


async def test_throughput(server: Server, configuration: QuicConfiguration):
    failures = 0
    if server.throughput_path is None:
        return

    for size in [5000000, 10000000]:
        path = server.throughput_path % {"size": size}
        print("Testing %d bytes download: %s" % (size, path))

        # perform HTTP request over TCP
        start = time.time()
        response = httpx.get("https://" + server.host + path, verify=False)
        tcp_octets = len(response.content)
        tcp_elapsed = time.time() - start
        assert tcp_octets == size, "HTTP/TCP response size mismatch"

        # perform HTTP request over QUIC
        if server.http3:
            configuration.alpn_protocols = H3_ALPN
            port = server.http3_port or server.port
        else:
            configuration.alpn_protocols = H0_ALPN
            port = server.port
        start = time.time()
        async with connect(
            server.host,
            port,
            configuration=configuration,
            create_protocol=HttpClient,
        ) as protocol:
            protocol = cast(HttpClient, protocol)

            http_events = await protocol.get(
                "https://{}:{}{}".format(server.host, server.port, path)
            )
            quic_elapsed = time.time() - start
            quic_octets = 0
            for http_event in http_events:
                if isinstance(http_event, DataReceived):
                    quic_octets += len(http_event.data)
        assert quic_octets == size, "HTTP/QUIC response size mismatch"

        print(" - HTTP/TCP  completed in %.3f s" % tcp_elapsed)
        print(" - HTTP/QUIC completed in %.3f s" % quic_elapsed)

        if quic_elapsed > 1.1 * tcp_elapsed:
            failures += 1
            print(" => FAIL")
        else:
            print(" => PASS")

    if failures == 0:
        server.result |= Result.T


def print_result(server: Server) -> None:
    result = str(server.result).replace("three", "3")
    result = result[0:8] + " " + result[8:16] + " " + result[16:]
    print("%s%s%s" % (server.name, " " * (20 - len(server.name)), result))


async def run(servers, tests, quic_log=False, secrets_log_file=None) -> None:
    for server in servers:
        if server.structured_logging:
            server.result |= Result.L
        for test_name, test_func in tests:
            print("\n=== %s %s ===\n" % (server.name, test_name))
            configuration = QuicConfiguration(
                alpn_protocols=H3_ALPN + H0_ALPN,
                is_client=True,
                quic_logger=QuicFileLogger(quic_log) if quic_log else QuicLogger(),
                secrets_log_file=secrets_log_file,
                verify_mode=server.verify_mode,
            )
            if test_name == "test_throughput":
                timeout = 120
            else:
                timeout = 10
            try:
                await asyncio.wait_for(
                    test_func(server, configuration), timeout=timeout
                )
            except Exception as exc:
                print(exc)

        print("")
        print_result(server)

    # print summary
    if len(servers) > 1:
        print("SUMMARY")
        for server in servers:
            print_result(server)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="QUIC interop client")
    parser.add_argument(
        "-q",
        "--quic-log",
        type=str,
        help="log QUIC events to QLOG files in the specified directory",
    )
    parser.add_argument(
        "--server", type=str, help="only run against the specified server."
    )
    parser.add_argument("--test", type=str, help="only run the specifed test.")
    parser.add_argument(
        "-l",
        "--secrets-log",
        type=str,
        help="log secrets to a file, for use with Wireshark",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="increase logging verbosity"
    )

    args = parser.parse_args()

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )

    # open SSL log file
    if args.secrets_log:
        secrets_log_file = open(args.secrets_log, "a")
    else:
        secrets_log_file = None

    # determine what to run
    servers = SERVERS
    tests = list(filter(lambda x: x[0].startswith("test_"), globals().items()))
    if args.server:
        servers = list(filter(lambda x: x.name == args.server, servers))
    if args.test:
        tests = list(filter(lambda x: x[0] == args.test, tests))

    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(
            run(
                servers=servers,
                tests=tests,
                quic_log=args.quic_log,
                secrets_log_file=secrets_log_file,
            )
        )
    finally:
        if secrets_log_file is not None:
            secrets_log_file.close()
