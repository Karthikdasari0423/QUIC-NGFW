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
    Server("kdaquic", "172.16.2.1", port=4433, verify_mode=ssl.CERT_NONE),
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
                server.result |= Result.V


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
                server.result |= Result.S


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
            s2="sed -i '423i \ \ \ \ \ \ \ \ \ \ \ \ \ \ \  for i in range(parallel)' /root/aioquic/examples/http3_client.py"
            s3='''sed -i '509i \ \ \ \ parser.add_argument("--parallel", type=int, default=1, help="perform this many requests in parallel")' /root/aioquic/examples/http3_client.py'''
            s4="sed -i '558i \ \ \ \ \ \ \ \ \ \ \ \ parallel=args.parallel,' /root/aioquic/examples/http3_client.py"
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
            server.result |= Result.P


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
    loop.run_until_complete(
        run(
            servers=servers,
            tests=tests,
            quic_log=args.quic_log,
            secrets_log_file=secrets_log_file,
        )
    )
