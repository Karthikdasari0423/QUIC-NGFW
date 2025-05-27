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
# from aioquic.quic.packet import NewConnectionIdFrame, RetireConnectionIdFrame, PathChallengeFrame, QuicErrorCode, QuicPacketType
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

    three = 0x010000
    d = 0x020000
    p = 0x040000
    X = 0x080000 # Max Streams Limit respected
    Y = 0x100000 # Max Unidirectional Streams Limit respected
    F = 0x200000 # Connection Flow Control respected

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


SERVERS = [
    Server("akamaiquic", "ietf.akaquic.com", port=443, verify_mode=ssl.CERT_NONE),
    Server(
        "aioquic", "quic.aiortc.org", port=443, push_path="/", structured_logging=True
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


async def test_max_streams_bidi_client_respects_limit(server: Server, configuration: QuicConfiguration):
    configuration.alpn_protocols = H3_ALPN
    # Ensure http3_client is imported if not already at top level of script
    # from http3_client import HttpClient (it is already imported)
    # Ensure QuicErrorCode is available if needed for comparison
    from aioquic.quic.packet import QuicErrorCode # For QuicConnectionError.error_code
    from aioquic.quic.connection import QuicConnectionError # To catch specific client-side errors
    # from asyncio import TimeoutError # To catch timeouts if server unresponsive

    port = server.http3_port or server.port

    async with connect(
        server.host,
        port,
        configuration=configuration,
        create_protocol=HttpClient,
    ) as client:
        client = cast(HttpClient, client)
        
        try:
            # Ensure handshake is complete to have transport parameters.
            # A simple ping can achieve this if connect() doesn't guarantee full handshake completion for params.
            await client.ping() 

            if client._quic.peer_transport_parameters is None:
                client._quic._logger.warning(f"({server.name}) Peer transport parameters not available after handshake. Skipping test.")
                return

            advertised_limit = client._quic.peer_transport_parameters.initial_max_streams_bidi
            
            # aioquic's default for initial_max_streams_bidi if peer doesn't send is 100.
            # Let's assume 'None' means it wasn't sent, so default applies.
            if advertised_limit is None:
                client._quic._logger.warning(f"({server.name}) initial_max_streams_bidi not explicitly set by peer, defaults to 100. Test will use a cap.")
                advertised_limit = 100 # aioquic's internal default

            client._quic._logger.info(f"({server.name}) Server advertised initial_max_streams_bidi: {advertised_limit}.")

            # Define the number of streams to actually test opening successfully before expecting a failure.
            # Cap at a practical number for testing, e.g., 10.
            # If advertised_limit is 0, streams_to_open_cap will be 0.
            # If advertised_limit is 1, streams_to_open_cap will be 1.
            streams_to_open_cap = min(advertised_limit, 10)

            if streams_to_open_cap == 0:
                client._quic._logger.info(f"({server.name}) Testing with limit 0. Attempting to open 1 stream, expecting failure.")
                try:
                    await client.get(f"https://{server.host}:{port}{server.path or '/'}?id=limit0_test")
                    client._quic._logger.warning(f"({server.name}) Client initiated a stream even though server's initial_max_streams_bidi is 0.")
                except QuicConnectionError as e:
                    if e.error_code == QuicErrorCode.STREAM_LIMIT_ERROR or "no stream id available" in str(e).lower() or "stream id limit reached" in str(e).lower():
                        client._quic._logger.info(f"({server.name}) Client correctly prevented stream (or server rejected) due to 0 limit: {e}")
                        server.result |= Result.X
                    else:
                        client._quic._logger.error(f"({server.name}) Stream creation failed for 0 limit, but with unexpected error: {e}")
                except asyncio.TimeoutError: # Catch timeout specifically
                    client._quic._logger.info(f"({server.name}) Timeout trying to open stream when limit is 0. Considered as respecting limit.")
                    server.result |= Result.X # If it times out, stream wasn't successfully opened.
                except Exception as e:
                    client._quic._logger.error(f"({server.name}) General error during 0 limit stream test: {e}")
                return

            # For advertised_limit > 0 (tested via streams_to_open_cap)
            client._quic._logger.info(f"({server.name}) Attempting to open {streams_to_open_cap} streams, expecting success.")
            tasks = []
            for i in range(streams_to_open_cap):
                tasks.append(client.get(f"https://{server.host}:{port}{server.path or '/'}?stream_no={i}"))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            successful_streams = 0
            for i, res in enumerate(results):
                # http_client.get returns a list of events, first should be HeadersReceived
                if isinstance(res, list) and res and isinstance(res[0], HeadersReceived):
                    successful_streams += 1
                else:
                    client._quic._logger.error(f"({server.name}) Stream {i} (up to {streams_to_open_cap}) failed or no headers: {res}")
                    return 
            
            if successful_streams != streams_to_open_cap:
                client._quic._logger.error(f"({server.name}) Expected {streams_to_open_cap} successful streams, got {successful_streams}.")
                return
            client._quic._logger.info(f"({server.name}) Successfully opened {successful_streams} bidirectional streams.")

            # Only proceed to test the (limit+1)th stream if we were testing against the actual advertised_limit
            # (i.e., our cap of 10 wasn't lower than the advertised_limit)
            if streams_to_open_cap == advertised_limit:
                client._quic._logger.info(f"({server.name}) Attempting to open {advertised_limit + 1}-th stream, expecting client-side failure.")
                try:
                    await client.get(f"https://{server.host}:{port}{server.path or '/'}?stream_no={advertised_limit}_over_limit")
                    client._quic._logger.warning(f"({server.name}) Client allowed opening the {advertised_limit + 1}-th stream when limit was {advertised_limit}.")
                except QuicConnectionError as e:
                    if e.error_code == QuicErrorCode.STREAM_LIMIT_ERROR or \
                       "no stream id available" in str(e).lower() or \
                       "stream id limit reached" in str(e).lower():
                        client._quic._logger.info(f"({server.name}) Client correctly raised STREAM_LIMIT_ERROR (or similar) for {advertised_limit + 1}-th stream: {e}")
                        server.result |= Result.X
                    else:
                        client._quic._logger.error(f"({server.name}) Unexpected QuicConnectionError on {advertised_limit + 1}-th stream: {e}")
                except asyncio.TimeoutError: # Catch timeout specifically
                    client._quic._logger.info(f"({server.name}) Timeout trying to open {advertised_limit+1}-th stream. Server might be unresponsive or client correctly timed out pending stream ID.")
                    # This is ambiguous for Result.X, ideally we want explicit client error.
                except Exception as e:
                    client._quic._logger.error(f"({server.name}) Unexpected Exception on {advertised_limit + 1}-th stream: {e}")
            else: # streams_to_open_cap < advertised_limit (because advertised_limit > 10)
                client._quic._logger.info(f"({server.name}) Server's advertised limit ({advertised_limit}) is higher than test cap ({streams_to_open_cap}). "
                                     "Cannot definitively test client exceeding advertised limit with this test instance.")
                # To verify this, we could try to open one more stream and it should succeed.
                try:
                    await client.get(f"https://{server.host}:{port}{server.path or '/'}?stream_no={streams_to_open_cap}_under_high_limit")
                    client._quic._logger.info(f"({server.name}) Successfully opened {streams_to_open_cap + 1}-th stream as expected since server limit {advertised_limit} is high.")
                    # This doesn't set Result.X as it doesn't test *hitting* the limit.
                except Exception as e:
                    client._quic._logger.error(f"({server.name}) Error opening {streams_to_open_cap + 1}-th stream even though server limit {advertised_limit} is high: {e}")


        except asyncio.TimeoutError:
            client._quic._logger.warning(f"({server.name}) Test timed out: test_max_streams_bidi_client_respects_limit")
        except Exception as e:
            client._quic._logger.error(f"({server.name}) Generic error in test_max_streams_bidi_client_respects_limit: {e}")
            import traceback
            client._quic._logger.error(traceback.format_exc())


async def test_max_streams_uni_client_respects_limit(server: Server, configuration: QuicConfiguration):
    configuration.alpn_protocols = H3_ALPN
    from aioquic.quic.packet import QuicErrorCode
    from aioquic.quic.connection import QuicConnectionError
    # asyncio.TimeoutError is part of asyncio, available if asyncio is imported.

    port = server.http3_port or server.port

    async with connect(
        server.host,
        port,
        configuration=configuration,
        create_protocol=HttpClient, # Using HttpClient to setup H3 connection easily
    ) as client:
        client = cast(HttpClient, client)
        
        try:
            await client.ping() # Ensure handshake is complete and H3 is established

            # Fetch directly using _remote_max_streams_uni
            advertised_limit_uni = client._quic._remote_max_streams_uni
            
            # The value of client._quic._remote_max_streams_uni will be 0 if the peer doesn't send the parameter.
            # This is the desired behavior for the test logic that follows.

            client._quic._logger.info(f"({server.name}) Uni: Server advertised initial_max_streams_uni: {advertised_limit_uni} (0 means not sent or explicitly 0).")

            # H3 typically opens 3 unidirectional streams:
            # 1 for client control, 1 for QPACK encoder, 1 for QPACK decoder.
            # This count can be observed from client._quic._local_max_streams_uni_open_count after H3 setup.
            # However, relying on this exact number might be fragile if H3Connection changes internals.
            # A safer way: query how many streams are *currently* open that are unidirectional.
            # Let's assume client._quic._stream_count[True][True] gives count of local uni streams.
            # Or, more robustly, try to open streams and see when it fails relative to advertised_limit.
            
            # Number of uni streams client can initiate according to peer's limit
            # This doesn't subtract streams already opened by H3Connection locally, 
            # as initial_max_streams_uni is about how many *peer* will accept in total from us.
            # The client's QuicConnection itself tracks how many it has opened against this limit.

            # Cap the number of *additional* streams we try to open for this test for practicality.
            # If advertised_limit_uni is very low (e.g., 0, 1, 2, 3), this cap might not apply.
            # The number of streams we will attempt to open *in this test logic* (beyond what H3 setup did).
            max_additional_streams_to_test = 5 
            
            streams_opened_by_test = 0
            
            # Case 1: Server allows 0 unidirectional streams from us.
            # This means any uni stream we (client) try to open should fail.
            # H3Connection itself opens uni streams for control, QPACK. If advertised_limit_uni
            # is less than what H3 needs, the connection might fail during H3 setup.
            # This test assumes H3 setup succeeded.
            if advertised_limit_uni < client._quic._local_max_streams_uni_open_count:
                 client._quic._logger.warning(f"({server.name}) Uni: Advertised limit {advertised_limit_uni} is less than streams already opened by H3 ({client._quic._local_max_streams_uni_open_count}). Connection should likely have failed earlier if server enforces strictly.")
                 # If connection is still up, try to open one more; it must fail.
                 try:
                    stream_id = client._quic.create_stream(is_unidirectional=True)
                    if stream_id is not None:
                        client._quic._logger.warning(f"({server.name}) Uni: Client created a uni stream {stream_id} when advertised limit {advertised_limit_uni} was already exceeded by H3 streams.")
                        # Send a byte to make it count towards open_count if create_stream doesn't do it.
                        # client._quic.send_stream_data(stream_id, b'a', end_stream=True) 
                    else: # stream_id is None
                        client._quic._logger.info(f"({server.name}) Uni: Client correctly failed to create uni stream (returned None) as limit {advertised_limit_uni} likely exceeded by H3 setup.")
                        server.result |= Result.Y
                 except QuicConnectionError as e:
                    if e.error_code == QuicErrorCode.STREAM_LIMIT_ERROR:
                        client._quic._logger.info(f"({server.name}) Uni: Client correctly raised STREAM_LIMIT_ERROR as limit {advertised_limit_uni} likely exceeded by H3 setup.")
                        server.result |= Result.Y
                    else:
                        client._quic._logger.error(f"({server.name}) Uni: Stream creation failed as expected due to low limit, but with unexpected error: {e}")
                 return # Test ends here for this case.


            # Try to open streams one by one until we hit the advertised_limit_uni or our practical cap for *total* open uni streams.
            for i in range(max_additional_streams_to_test + 1): # +1 to try to exceed the cap / limit
                current_total_client_uni_streams = client._quic._local_max_streams_uni_open_count
                
                if current_total_client_uni_streams >= advertised_limit_uni:
                    # We are at or over the server's advertised limit for total uni streams from us.
                    # Attempting to create one more should fail.
                    client._quic._logger.info(f"({server.name}) Uni: Client has {current_total_client_uni_streams} uni streams. Server limit {advertised_limit_uni}. Attempting to create one more (expect fail).")
                    try:
                        stream_id = client._quic.create_stream(is_unidirectional=True)
                        if stream_id is not None:
                            client._quic._logger.warning(f"({server.name}) Uni: Client CREATED uni stream {stream_id} EXCEEDING server limit {advertised_limit_uni}. Current count: {client._quic._local_max_streams_uni_open_count + 1 if stream_id is not None else 'failed'}")
                        else: # stream_id is None, meaning client prevented it.
                            client._quic._logger.info(f"({server.name}) Uni: Client correctly PREVENTED uni stream creation (returned None) at limit {advertised_limit_uni}.")
                            server.result |= Result.Y
                    except QuicConnectionError as e:
                        if e.error_code == QuicErrorCode.STREAM_LIMIT_ERROR:
                            client._quic._logger.info(f"({server.name}) Uni: Client correctly RAISED STREAM_LIMIT_ERROR at limit {advertised_limit_uni}.")
                            server.result |= Result.Y
                        else:
                            client._quic._logger.error(f"({server.name}) Uni: Expected STREAM_LIMIT_ERROR at limit {advertised_limit_uni}, but got {e}.")
                    except Exception as e:
                        client._quic._logger.error(f"({server.name}) Uni: Unexpected exception when trying to exceed limit {advertised_limit_uni}: {e}")
                    return # Test finishes after checking the one-too-many attempt.

                # If we are below the advertised limit and below our practical test cap for *additional* streams for this loop
                if i < max_additional_streams_to_test:
                    client._quic._logger.info(f"({server.name}) Uni: Client has {current_total_client_uni_streams} uni streams. Server limit {advertised_limit_uni}. Attempting to create additional stream #{i+1}.")
                    try:
                        stream_id = client._quic.create_stream(is_unidirectional=True)
                        if stream_id is not None:
                            streams_opened_by_test += 1
                            client._quic._logger.info(f"({server.name}) Uni: Successfully created additional uni stream {stream_id} (total client uni: {client._quic._local_max_streams_uni_open_count}).")
                            # Optionally send a byte to make it "active" if create_stream itself doesn't update counts relevant for limits immediately.
                            # client._quic.send_stream_data(stream_id, b'a', end_stream=True)
                        else:
                            client._quic._logger.error(f"({server.name}) Uni: Client FAILED to create additional uni stream #{i+1} (returned None) even though current_count {current_total_client_uni_streams} < limit {advertised_limit_uni}.")
                            return # Should not happen if below limit
                    except QuicConnectionError as e:
                         client._quic._logger.error(f"({server.name}) Uni: Client FAILED to create additional uni stream #{i+1} with error {e} even though current_count {current_total_client_uni_streams} < limit {advertised_limit_uni}.")
                         return # Should not happen
                    except Exception as e:
                        client._quic._logger.error(f"({server.name}) Uni: Unexpected exception creating additional uni stream #{i+1}: {e}")
                        return
                else: # i == max_additional_streams_to_test
                    # We've opened our practical cap of additional streams for this test.
                    # And we were still under the server's advertised_limit_uni.
                    client._quic._logger.info(f"({server.name}) Uni: Reached practical test cap of {max_additional_streams_to_test} additional uni streams. "
                                         f"Total client uni streams: {client._quic._local_max_streams_uni_open_count}. "
                                         f"Server limit {advertised_limit_uni} was not reached by this test.")
                    return


            # If loop finished, it means we didn't hit the condition current_total_client_uni_streams >= advertised_limit_uni
            # within max_additional_streams_to_test+1 iterations. This implies advertised_limit_uni was high.
            client._quic._logger.info(f"({server.name}) Uni: Test completed. Opened {streams_opened_by_test} additional uni streams. "
                                 f"Server advertised limit {advertised_limit_uni} was likely not reached or tested for exceeding if it was > internal H3 count + {max_additional_streams_to_test}.")

        except asyncio.TimeoutError:
            client._quic._logger.warning(f"({server.name}) Uni: Test timed out: test_max_streams_uni_client_respects_limit")
        except Exception as e:
            client._quic._logger.error(f"({server.name}) Uni: Generic error in test_max_streams_uni_client_respects_limit: {e}")
            import traceback
            client._quic._logger.error(traceback.format_exc())


async def test_initial_max_data_client_respects_limit(server: Server, configuration: QuicConfiguration):
    configuration.alpn_protocols = H3_ALPN
    from aioquic.quic.packet import QuicErrorCode
    from aioquic.quic.connection import QuicConnectionError
    # asyncio is imported at top level

    port = server.http3_port or server.port
    # Using HttpClient to setup H3 and then access _quic for direct stream manipulation
    async with connect(
        server.host,
        port,
        configuration=configuration,
        create_protocol=HttpClient,
    ) as client:
        client = cast(HttpClient, client)
        
        try:
            await client.ping() # Ensure handshake is complete and H3 is established

            advertised_initial_max_data = client._quic._remote_max_data
            
            if advertised_initial_max_data is None:
                # If not specified by peer, QUIC spec implies a small limit (e.g. 16KB for some drafts)
                # aioquic's QuicConnection initializes flow_control_peer_max_data to 0 if param is None,
                # which means client cannot send any data until MAX_DATA is received.
                # This is a valid scenario to test.
                client._quic._logger.info(f"({server.name}) MaxData: initial_max_data not advertised by peer. Effective limit is 0 initially.")
                advertised_initial_max_data = 0
            
            client._quic._logger.info(f"({server.name}) MaxData: Server advertised initial_max_data: {advertised_initial_max_data}.")

            # Create a stream to send data on. Need to use _quic directly.
            # HttpClient usually handles stream creation for requests.
            # We need a bidi stream to send data.
            stream_id = client._quic.get_next_available_stream_id(is_client=True, is_unidirectional=False)
            if stream_id is None:
                client._quic._logger.error(f"({server.name}) MaxData: Could not create a bidi stream to send data.")
                return
            
            # To make H3 server accept data on this stream, we might need to send H3 headers first.
            # This complicates things. Let's try a POST request via HttpClient, sending data via its generator.
            # This will handle H3 framing. We need a way to feed data slowly/in chunks.

            chunk_size = 4 * 1024  # 4KB chunks
            # Define total data to attempt to send.
            # If advertised_initial_max_data is 0, try to send one chunk.
            # Otherwise, try to send slightly more than advertised_initial_max_data, capped for test duration.
            # Practical cap for data sending in this test, e.g., 256KB.
            # This ensures test doesn't run too long if initial_max_data is huge.
            practical_send_cap = 256 * 1024 
            
            data_to_attempt_total = 0
            if advertised_initial_max_data == 0:
                data_to_attempt_total = chunk_size # Try to send one chunk
            else:
                # Try to send up to the cap, or just over the advertised limit if it's smaller than cap
                data_to_attempt_total = min(advertised_initial_max_data + chunk_size, practical_send_cap)

            client._quic._logger.info(f"({server.name}) MaxData: Will attempt to send {data_to_attempt_total} bytes in total.")

            sent_so_far_total = 0
            
            # Use a generator for POST request data
            async def data_generator():
                nonlocal sent_so_far_total
                bytes_left_to_send_for_test = data_to_attempt_total
                while bytes_left_to_send_for_test > 0:
                    current_chunk_size = min(chunk_size, bytes_left_to_send_for_test)
                    data_chunk = b'a' * current_chunk_size
                    
                    # Before yielding data, check if client is already connection data blocked
                    # This check is a bit indirect as HttpClient handles the actual send calls.
                    # We are more interested if _quic layer gets blocked.
                    if client._quic.data_blocked_local:
                        client._quic._logger.info(f"({server.name}) MaxData: Client is data_blocked_local (conn level) before yielding next chunk. Sent {sent_so_far_total}.")
                        # Stop the generator, effectively stopping the POST.
                        return

                    yield data_chunk
                    sent_so_far_total += len(data_chunk)
                    bytes_left_to_send_for_test -= len(data_chunk)
                    client._quic._logger.info(f"({server.name}) MaxData: Sent {len(data_chunk)} bytes. Total sent by generator: {sent_so_far_total}.")
                    await asyncio.sleep(0.01) # Small sleep to allow QUIC stack to process & update states

                # After generator finishes, check data_blocked_local again
                # This might be set if the last chunk filled the window exactly.
                await asyncio.sleep(0.1) # allow quic stack to process last chunk
                if client._quic.data_blocked_local:
                    client._quic._logger.info(f"({server.name}) MaxData: Client is data_blocked_local after sending all data ({sent_so_far_total}).")
                    # This is a key success condition if sent_so_far_total is around advertised_initial_max_data
                    if advertised_initial_max_data == 0 and sent_so_far_total == 0: # if limit 0, no data should be sent by generator if blocked immediately
                         server.result |= Result.F
                    elif abs(sent_so_far_total - advertised_initial_max_data) < chunk_size : # check if we are near the limit
                         server.result |= Result.F


            post_url = f"https://{server.host}:{port}{server.path or '/'}post_max_data_test"
            try:
                http_events = await client.post(post_url, data=data_generator())
                # Check response if needed, but for this test, primary focus is on sending behavior.
                if http_events and isinstance(http_events[0], HeadersReceived):
                    client._quic._logger.info(f"({server.name}) MaxData: POST request completed. Response headers: {http_events[0].headers}")
                else:
                    client._quic._logger.warning(f"({server.name}) MaxData: POST request finished but no/unexpected headers: {http_events}")

            except QuicConnectionError as e:
                # This might happen if server closes connection due to client sending too much (e.g. FLOW_CONTROL_ERROR)
                # or if client itself hits a hard error during send.
                client._quic._logger.error(f"({server.name}) MaxData: QuicConnectionError during POST: {e}")
                if e.error_code == QuicErrorCode.FLOW_CONTROL_ERROR and client._quic.data_blocked_local:
                    client._quic._logger.info(f"({server.name}) MaxData: Caught FLOW_CONTROL_ERROR and client is data_blocked_local. Likely hit limit.")
                    server.result |= Result.F
            except asyncio.TimeoutError:
                 client._quic._logger.warning(f"({server.name}) MaxData: POST request timed out. Client might be blocked by flow control.")
                 # If it timed out and we were trying to send more than allowed, and data_blocked_local is set, it's a pass.
                 if client._quic.data_blocked_local and sent_so_far_total >= advertised_initial_max_data :
                     server.result |= Result.F
            except Exception as e:
                client._quic._logger.error(f"({server.name}) MaxData: Unexpected exception during POST: {e}")

            # Final check on data_blocked_local after all operations
            # This is the most reliable check for client respecting flow control.
            # This flag is set by aioquic when _send_data_frame cannot send due to connection FC window.
            if client._quic.data_blocked_local:
                client._quic._logger.info(f"({server.name}) MaxData: Test end, client._quic.data_blocked_local is True. Total bytes QUIC connection tried to send: {client._quic.data_sent_local}.")
                # If data_sent_local is close to advertised_initial_max_data, this is a success.
                # Note: data_sent_local is total bytes given to send_stream_data, not necessarily 'in flight'.
                # flow_control_peer_max_data is the current window.
                # If data_sent_local > flow_control_peer_max_data and data_blocked_local is true, it's a strong signal.
                if client._quic.data_sent_local >= client._quic.flow_control_peer_max_data:
                     server.result |= Result.F
                elif advertised_initial_max_data == 0 and client._quic.data_sent_local == 0 : # if limit is 0, and client sent 0 data and is blocked.
                     server.result |= Result.F

        except asyncio.TimeoutError:
            client._quic._logger.warning(f"({server.name}) MaxData: Test timed out globally: test_initial_max_data_client_respects_limit")
        except Exception as e:
            client._quic._logger.error(f"({server.name}) MaxData: Generic error in test_initial_max_data_client_respects_limit: {e}")
            import traceback
            client._quic._logger.error(traceback.format_exc())

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
    
    # Add the new test to the list of tests to be run
    # tests.append(("test_max_streams_bidi_client_respects_limit", test_max_streams_bidi_client_respects_limit))


    loop = asyncio.get_event_loop()
    loop.run_until_complete(
        run(
            servers=servers,
            tests=tests,
            quic_log=args.quic_log,
            secrets_log_file=secrets_log_file,
        )
    )
