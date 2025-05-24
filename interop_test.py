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
    MSL = 0x080000
    SDB = 0x100000
    SS = 0x200000

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


async def test_max_streams_handling(server: Server, configuration: QuicConfiguration):
    if server.path is None:  # Path needed for HTTP requests
        return

    configuration.alpn_protocols = H3_ALPN
    async with connect(
        server.host,
        server.http3_port or server.port,
        configuration=configuration,
        create_protocol=HttpClient,
    ) as protocol:
        protocol = cast(HttpClient, protocol)

        await protocol.ping()  # Ensure connection is active

        # Initial check of peer advertised limit (might be 0 or a small number initially)
        # The actual limit is often learned after some initial stream activity or specific frames.
        # For robust testing, we'd ideally know the server's actual initial max_concurrent_streams.
        # However, RFC 9000 states default is 100 for bidi streams if not specified.
        # Let's try to open a number of streams that would likely exceed a common initial limit.
        streams_to_attempt = 150  # A reasonable number to try to exceed typical initial limits

        streams_opened_successfully = 0
        stream_limit_error_caught = False

        try:
            for i in range(streams_to_attempt):
                try:
                    # Attempt to "use" the stream by initiating a request.
                    # get_next_available_stream_id() alone might not be enough
                    # as it doesn't necessarily mean the stream is fully opened or counted
                    # against the server's limit until used.
                    stream_id = protocol._quic.get_next_available_stream_id()
                    
                    # A lightweight way to "use" the stream for H3.
                    # This sends headers, effectively opening the stream.
                    # We don't need to wait for the full response, just initiate.
                    # Using a non-existent path to avoid actual data transfer beyond headers.
                    asyncio.create_task(protocol.get(
                        f"https://{server.host}:{server.port}/attempt_stream_{i}"
                    ))
                    # Give a tiny moment for the task to be scheduled and potentially process initial part of stream opening
                    await asyncio.sleep(0.001) 

                    streams_opened_successfully += 1

                    # Check if we are already at a limit indicated by the QUIC layer's internal state
                    # This is a more direct check if MAX_STREAMS was received and processed.
                    # _peer_max_allowed_stream_id_bidi is calculated based on MAX_STREAMS frames.
                    # The number of active streams is in _streams.
                    # Note: stream IDs are not contiguous numbers of streams.
                    # A better check is if get_next_available_stream_id itself raises an error
                    # or if the number of streams in protocol._quic._streams stops increasing.
                    
                    # If the server is very lenient or we haven't hit a limit yet, this loop might complete.
                    # The primary check is the QuicConnectionError below.

                except QuicConnectionError as e:
                    if e.error_code == ErrorCode.STREAM_LIMIT_ERROR or \
                       e.error_code == ErrorCode.H3_STREAM_CREATION_ERROR: # H3_STREAM_CREATION_ERROR can also be relevant
                        protocol._quic._logger.info(
                            f"Caught expected stream limit error: {e.error_code} - {e.reason_phrase}"
                        )
                        stream_limit_error_caught = True
                        server.result |= Result.MSL
                        break  # Stop trying to open more streams
                    else:
                        protocol._quic._logger.warning(
                            f"Caught QuicConnectionError but not stream limit related: {e.error_code} - {e.reason_phrase}"
                        )
                        raise # Re-throw if it's not the one we are looking for
                except Exception as e:
                    # Catch any other exception during stream opening attempt
                    protocol._quic._logger.error(f"Unexpected exception during stream {i} creation: {e}")
                    # Depending on policy, could break or continue. For now, let's break.
                    break
            
            if not stream_limit_error_caught:
                # If no specific stream limit error was caught, we need to assess other conditions.
                # This could happen if the server is very permissive, or if our attempt count wasn't high enough.
                # Check the number of streams actually created vs the peer's advertised limit.
                # This is a fallback check. The primary check is catching STREAM_LIMIT_ERROR.
                # protocol._quic._streams contains active streams.
                # protocol._quic._peer_max_allowed_stream_id_bidi reflects the max stream ID the peer allows.
                # Stream IDs are not 0-indexed counts but rather specific numbers (0, 4, 8 for client bidi).
                # A simple check: if we opened many streams without error, it's a weak pass.
                # A more robust check would involve inspecting logger for MAX_STREAMS or if _streams count matches a known limit.
                
                # If we opened all attempted streams without hitting a STREAM_LIMIT_ERROR,
                # it implies the server is either very generous or the limit wasn't triggered by these actions.
                # For this test, catching the explicit STREAM_LIMIT_ERROR is the strongest signal.
                # If not caught, we might not be able to definitively say MSL is handled unless we analyze logs
                # for MAX_STREAMS frames, which is more complex.
                # For now, we only set MSL if the specific error is caught.
                # Alternatively, if the number of streams is clearly limited by _peer_max_allowed_stream_id_bidi
                # (e.g. next get_next_available_stream_id() would exceed it or already did and failed silently before)
                # This part needs careful consideration.
                
                # Let's check if the number of streams is somewhat constrained,
                # even if no explicit error was raised.
                # This is a weaker heuristic.
                # `_local_max_streams_bidi` is our advertised limit, `_peer_max_streams_bidi` is what peer advertised to us.
                # `_stream_count_bidi` is number of active bidi streams.
                if protocol._quic._stream_count_bidi > 0 and \
                   protocol._quic._stream_count_bidi <= protocol._quic._peer_max_streams_bidi:
                    protocol._quic._logger.info(
                        f"Loop completed. Active bidi streams ({protocol._quic._stream_count_bidi}) "
                        f"within peer advertised limit ({protocol._quic._peer_max_streams_bidi}). "
                        "This might indicate graceful handling if limit was implicitly hit."
                    )
                    # This is a softer condition for MSL. The explicit error is better.
                    # server.result |= Result.MSL # Potentially add this if desired for "silent" limiting
                elif streams_opened_successfully == streams_to_attempt:
                     protocol._quic._logger.info(
                        f"Opened all {streams_to_attempt} streams without explicit stream limit error."
                    )
                else:
                    protocol._quic._logger.warning(
                        f"Stream limit error not caught, and stream count ({protocol._quic._stream_count_bidi}) "
                        f"vs peer limit ({protocol._quic._peer_max_streams_bidi}) is inconclusive or limit not reached."
                    )


        except QuicConnectionError as e:
            # This outer catch is for errors not caught by the inner stream creation loop's specific handler
            protocol._quic._logger.error(
                f"Outer QuicConnectionError: {e.error_code} - {e.reason_phrase}"
            )
            if e.error_code == ErrorCode.STREAM_LIMIT_ERROR or \
               e.error_code == ErrorCode.H3_STREAM_CREATION_ERROR:
                if not stream_limit_error_caught: # If not already set
                    server.result |= Result.MSL
        except Exception as e:
            protocol._quic._logger.error(f"Unexpected exception in test_max_streams_handling: {e}")
        finally:
            # Ensure the connection is closed gracefully, releasing resources.
            # The `async with` block handles this, but explicit close can be added if needed for specific scenarios.
            pass


async def test_stream_data_blocked_handling(server: Server, configuration: QuicConfiguration):
    if server.path is None:  # Path needed for HTTP requests
        return

    # Ensure quic_logger is available and can be inspected.
    # The main runner script already sets up QuicFileLogger or QuicLogger.
    if configuration.quic_logger is None:
        print("QuicLogger not configured, cannot verify STREAM_DATA_BLOCKED frame.")
        return

    configuration.alpn_protocols = H3_ALPN
    async with connect(
        server.host,
        server.http3_port or server.port,
        configuration=configuration,
        create_protocol=HttpClient,
    ) as protocol:
        protocol = cast(HttpClient, protocol)
        http_client = cast(HttpClient, protocol) # Alias for clarity

        await http_client.ping() # Ensure connection is active

        # Perform a simple GET request to open a stream
        request_path = server.path
        if not request_path or request_path == "/":
            request_path = "/test_sdb_init" # Use a specific path if default is too generic

        events = await http_client.get(
            "https://{}:{}{}".format(server.host, server.port, request_path)
        )
        
        # Identify the stream ID used for the GET request.
        # This is a bit indirect. We need to find the stream associated with the HTTP GET.
        # H3Connection maps request IDs to stream IDs.
        # A simpler way for a single client might be to find the first client-initiated bidi stream.
        client_stream_id = None
        if hasattr(http_client._http, '_stream_id_for_request_data'): # internal detail, might change
            # Find a stream that was used for sending data (i.e. our GET request)
            for stream_id, data_sent in http_client._http._stream_id_for_request_data.items():
                if data_sent:
                    client_stream_id = stream_id
                    break
        
        if client_stream_id is None:
            # Fallback: Iterate through QUIC streams to find a client-initiated bidirectional stream
            # that has sent some data and is still open or recently closed by us.
            # Client-initiated bidi streams are 0, 4, 8, ...
            for stream_id, stream in protocol._quic._streams.items():
                if stream_id % 4 == 0 and not stream.is_closed and stream.sender.bytes_sent > 0:
                    client_stream_id = stream_id
                    protocol._quic._logger.info(f"Found active client stream {client_stream_id} via fallback.")
                    break
        
        if client_stream_id is None:
            protocol._quic._logger.error("Could not identify a suitable client stream for SDB test.")
            return

        protocol._quic._logger.info(f"Using stream {client_stream_id} for STREAM_DATA_BLOCKED test.")

        # Attempt to send a large amount of data to trigger flow control limits
        # Default initial stream flow control window is often ~256KB (RFC 9000 default is 2^16 = 65536, but can be higher)
        # Let's try to send more than that.
        # Sending 1MB of data should be enough to hit typical initial limits.
        # We send it in chunks to allow the QUIC stack to process.
        data_to_send = b"D" * (1 * 1024 * 1024) # 1 MB
        chunk_size = 64 * 1024 # 64KB chunks
        data_sent_total = 0

        try:
            for i in range(0, len(data_to_send), chunk_size):
                chunk = data_to_send[i:i + chunk_size]
                protocol._quic.send_stream_data(client_stream_id, chunk, end_stream=False)
                data_sent_total += len(chunk)
                # Allow some processing time, especially if the send buffer fills up
                await asyncio.sleep(0.01) 
            
            # Try to send one final small piece of data that might be the one to get blocked
            protocol._quic.send_stream_data(client_stream_id, b"final_chunk", end_stream=False)
            data_sent_total += len(b"final_chunk")
            protocol._quic._logger.info(f"Attempted to send {data_sent_total} bytes on stream {client_stream_id}.")

        except QuicConnectionError as e:
            # This might happen if the connection closes due to some other issue during send.
            protocol._quic._logger.error(f"QuicConnectionError during send_stream_data: {e}")
            return # Cannot proceed if send fails catastrophically

        # Allow time for the client to process its send queue and for the server to potentially
        # send MAX_STREAM_DATA frames (or not, if we are blocked).
        # A ping forces an RTT and processing of ack/control frames.
        await http_client.ping()
        await asyncio.sleep(0.2) # Additional grace time for logger events

        # Inspect logger for STREAM_DATA_BLOCKED frame sent by the client
        found_sdb_frame = False
        try:
            log_data = configuration.quic_logger.to_dict()
            traces = log_data.get("traces", [])
            if not traces:
                protocol._quic._logger.warning("No traces found in QUIC log for SDB check.")
                return

            for event in traces[0].get("events", []):
                # Events can be at different levels, "transport:packet_sent" or "transport:frame_sent"
                # Let's check for "transport:packet_sent" as it's more common in examples
                if event.get("name") == "transport:packet_sent":
                    packet_data = event.get("data", {})
                    for frame in packet_data.get("frames", []):
                        if frame.get("frame_type") == "stream_data_blocked":
                            # Check if it's for the stream we are interested in
                            if frame.get("stream_id") == client_stream_id:
                                protocol._quic._logger.info(
                                    f"STREAM_DATA_BLOCKED frame sent for stream {client_stream_id} found in log."
                                )
                                found_sdb_frame = True
                                server.result |= Result.SDB
                                break # Found relevant SDB frame
                if found_sdb_frame:
                    break
            
            if not found_sdb_frame:
                protocol._quic._logger.warning(
                    f"STREAM_DATA_BLOCKED frame for stream {client_stream_id} not observed in QUIC log. "
                    "This might be due to generous server flow control or logger verbosity."
                )

        except Exception as e:
            protocol._quic._logger.error(f"Error inspecting QUIC log for SDB frame: {e}")


async def test_stop_sending_handling(server: Server, configuration: QuicConfiguration):
    # Determine path for GET request; prefer throughput_path for potentially larger/streamable content.
    request_path = None
    if server.throughput_path:
        # Use a moderate size for the throughput path to ensure it's streamable but not excessively slow.
        # 500KB or 1MB should be sufficient. Let's use 500KB.
        try:
            request_path = server.throughput_path % {"size": 500000} # 500KB
        except TypeError: # Path might not have a size parameter
            protocol._quic._logger.warning(f"Could not format throughput_path: {server.throughput_path}, falling back.")
            request_path = server.path
    else:
        request_path = server.path

    if request_path is None:
        print("No suitable path for GET request in test_stop_sending_handling.")
        return

    if configuration.quic_logger is None:
        print("QuicLogger not configured, cannot verify RESET_STREAM frame.")
        return

    configuration.alpn_protocols = H3_ALPN
    async with connect(
        server.host,
        server.http3_port or server.port,
        configuration=configuration,
        create_protocol=HttpClient,
    ) as protocol:
        protocol = cast(HttpClient, protocol)
        http_client = cast(HttpClient, protocol)

        await http_client.ping() # Ensure connection is active

        # Initiate the GET request but don't await its full completion yet.
        # This allows us to send STOP_SENDING while the server is likely still sending data.
        get_task = asyncio.create_task(
            http_client.get(
                "https://{}:{}{}".format(server.host, server.port, request_path)
            )
        )

        # Allow the GET request to start and the client to determine the stream ID.
        # This is a bit of a race, but usually the stream ID is assigned quickly.
        await asyncio.sleep(0.1) # Small delay for request initiation and stream ID assignment.

        client_stream_id = None
        # Try to find the stream ID associated with the ongoing GET request.
        # Iterating _streams is a common way if a direct mapping isn't public.
        # Client-initiated bidi streams are 0, 4, 8, ...
        # We need the one that was just opened for our GET.
        # The highest numbered stream is likely the most recent.
        max_client_stream_id = -1
        for stream_id, stream in protocol._quic._streams.items():
            if stream_id % 4 == 0 and not stream.is_closed: # Client bidi stream, not yet closed
                 # Check if it's an HTTP/3 stream by looking at H3 connection's internal streams
                if http_client._http._stream_is_pending(stream_id) or http_client._http._stream_exists(stream_id):
                    if stream_id > max_client_stream_id:
                        max_client_stream_id = stream_id
        
        if max_client_stream_id != -1:
            client_stream_id = max_client_stream_id
        
        if client_stream_id is None:
            protocol._quic._logger.error("Could not identify client stream ID for STOP_SENDING test.")
            get_task.cancel() # Clean up the pending GET task
            try:
                await get_task
            except asyncio.CancelledError:
                pass
            return

        protocol._quic._logger.info(f"Identified stream {client_stream_id} for STOP_SENDING test. Path: {request_path}")

        # Send STOP_SENDING for this stream.
        # H3_REQUEST_CANCELLED is an appropriate error code.
        protocol._quic.stop_stream(client_stream_id, error_code=ErrorCode.H3_REQUEST_CANCELLED)
        protocol._quic._logger.info(f"STOP_SENDING (error {ErrorCode.H3_REQUEST_CANCELLED}) sent for stream {client_stream_id}.")

        # Allow time for server to process STOP_SENDING and respond (hopefully with RESET_STREAM)
        # A ping can help ensure packets are exchanged.
        await http_client.ping()
        await asyncio.sleep(0.3) # Additional grace time

        # Now, check the logs for a RESET_STREAM from the server.
        found_reset_stream = False
        try:
            log_data = configuration.quic_logger.to_dict()
            traces = log_data.get("traces", [])
            if not traces:
                protocol._quic._logger.warning("No traces found in QUIC log for SS check.")
            else:
                for event in traces[0].get("events", []):
                    if event.get("name") == "transport:packet_received":
                        packet_data = event.get("data", {})
                        for frame in packet_data.get("frames", []):
                            if frame.get("frame_type") == "reset_stream" and \
                               frame.get("stream_id") == client_stream_id:
                                # We need to ensure this RESET_STREAM was sent by the server.
                                # The log event "transport:packet_received" implies it's from the peer.
                                protocol._quic._logger.info(
                                    f"RESET_STREAM frame received from server for stream {client_stream_id}."
                                )
                                found_reset_stream = True
                                server.result |= Result.SS
                                break
                    if found_reset_stream:
                        break
            
            if not found_reset_stream:
                protocol._quic._logger.warning(
                    f"RESET_STREAM frame not observed from server for stream {client_stream_id} "
                    "after sending STOP_SENDING."
                )

        except Exception as e:
            protocol._quic._logger.error(f"Error inspecting QUIC log for RESET_STREAM frame: {e}")
        
        # Finally, ensure the GET task is completed or cancelled to clean up resources.
        if not get_task.done():
            get_task.cancel()
        try:
            await get_task # Await to propagate any exceptions if not cancelled.
        except asyncio.CancelledError:
            protocol._quic._logger.info(f"GET task for stream {client_stream_id} cancelled as part of cleanup.")
        except Exception as e:
            # Log other exceptions from the GET task if it wasn't cancelled and failed.
            protocol._quic._logger.error(f"Exception from GET task for stream {client_stream_id}: {e}")


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
