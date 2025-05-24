#
# !!! WARNING !!!
#
# This example uses some private APIs.
#

import argparse
import asyncio
import logging
import os
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

    MSL = 0x080000
    SDB = 0x100000
    SS = 0x200000
    PVH = 0x400000
    SCSE = 0x800000
    MWL = 0x1000000
    H3SE = 0x2000000
    ZRF = 0x4000000
    QTC = 0x8000000
    MSU = 0x10000000
    three = 0x010000
    d = 0x020000
    p = 0x040000
    CID_RETIREMENT_OK = 0x4000000
    PATH_VALIDATION_INITIATED_OK = 0x8000000
    MAX_DATA_UPDATE_OK = 0x10000000
    HANDSHAKE_DONE_RECEIVED_OK = 0x20000000

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

async def test_client_path_validation_response(
    server: Server, configuration: QuicConfiguration
):
    port = server.http3_port or server.port
    if server.path is None: # Not strictly for path val, but http client needs it
        return

    quic_logger = QuicLogger()
    configuration.quic_logger = quic_logger
    configuration.alpn_protocols = H3_ALPN 

    async with connect(
        server.host,
        port,
        configuration=configuration,
        create_protocol=HttpClient,
    ) as protocol:
        protocol = cast(HttpClient, protocol)
        logger = protocol._quic._logger

        # Wait for the handshake to be confirmed so 1-RTT keys are available
        await protocol._quic.wait_handshake_confirmed()
        logger.info("Handshake confirmed. Proceeding with PATH_CHALLENGE.")

        challenge_data = os.urandom(8)
        logger.info(f"Sending PATH_CHALLENGE with data: {challenge_data.hex()}")
        
        protocol._quic._send_frame(PathChallengeFrame(data=challenge_data))
        
        # Send a PING to help ensure the PATH_CHALLENGE is flushed quickly
        await protocol.ping() 
        logger.info("PATH_CHALLENGE sent, ping also sent to flush.")

        # Wait for the server to respond
        await asyncio.sleep(2.0) # Allow time for server processing and network RTT

        path_response_received_correctly = False
        try:
            log_dict = quic_logger.to_dict()
            if log_dict and "traces" in log_dict and log_dict["traces"]:
                for event in log_dict["traces"][0].get("events", []):
                    if event.get("name") == "transport:frame_received":
                        for frame_data in event.get("data", {}).get("frames", []):
                            if frame_data.get("frame_type") == "path_response":
                                received_payload_hex = frame_data.get("data")
                                if received_payload_hex:
                                    received_payload_bytes = bytes.fromhex(received_payload_hex)
                                    logger.info(
                                        f"QLOG: PATH_RESPONSE frame received with data: {received_payload_bytes.hex()}"
                                    )
                                    if received_payload_bytes == challenge_data:
                                        path_response_received_correctly = True
                                        logger.info("PATH_RESPONSE data matches PATH_CHALLENGE data.")
                                        break 
                                    else:
                                        logger.warning(
                                            f"PATH_RESPONSE data mismatch. Expected: {challenge_data.hex()}, Got: {received_payload_bytes.hex()}"
                                        )
                                else:
                                    logger.warning("PATH_RESPONSE frame in QLOG missing 'data' field.")
                        if path_response_received_correctly:
                            break 
        except Exception as e:
            logger.error(f"Error processing QLOG for PATH_RESPONSE: {e}")

        if path_response_received_correctly:
            server.result |= Result.PATH_VALIDATION_INITIATED_OK
            logger.info("Path validation response test successful.")
        else:
            logger.warning("Matching PATH_RESPONSE was not found in QLOG.")

        # Final health check
        await protocol.ping()
        logger.info("Client path validation test finished.")


async def test_max_data_frame_handling(
    server: Server, configuration: QuicConfiguration
):
    port = server.http3_port or server.port
    if server.path is None: # Path needed for POST requests
        return

    # quic_logger = QuicLogger() # Not strictly needed for this test as we check internal state
    # configuration.quic_logger = quic_logger
    configuration.alpn_protocols = H3_ALPN 

    async with connect(
        server.host,
        port,
        configuration=configuration,
        create_protocol=HttpClient,
    ) as protocol:
        protocol = cast(HttpClient, protocol)
        logger = protocol._quic._logger

        await protocol._quic.wait_handshake_confirmed()
        logger.info("Handshake confirmed for MAX_DATA test.")

        initial_max_data = protocol._quic.peer_params.initial_max_data
        logger.info(f"Initial peer initial_max_data: {initial_max_data}")

        min_data_to_send = 1024  # 1KB
        if initial_max_data == 0:
            logger.warning("Peer's initial_max_data is 0. This test may not be effective. Sending minimal data.")
            data_to_send_size = min_data_to_send 
        elif initial_max_data < min_data_to_send * 2: # If it's too small to trigger ~85% rule effectively
             logger.warning(f"Peer's initial_max_data ({initial_max_data}) is very small. Sending a small chunk.")
             data_to_send_size = int(initial_max_data * 0.5) if initial_max_data > min_data_to_send else min_data_to_send
             if data_to_send_size == 0 and initial_max_data > 0 : data_to_send_size = initial_max_data # send all if it's tiny but non-zero
             elif data_to_send_size == 0 : data_to_send_size = min_data_to_send # fallback
        else:
            data_to_send_size = int(initial_max_data * 0.85)
            if data_to_send_size == 0: # Ensure we send something if 85% rounds down to 0
                data_to_send_size = min_data_to_send if initial_max_data > min_data_to_send else initial_max_data


        logger.info(f"Attempting to send {data_to_send_size} bytes of data to consume flow control window.")
        
        try:
            # Using a POST request to send data. This will use one stream.
            # HttpClient handles stream creation and sending data.
            initial_post_path = f"https://{server.host}:{port}{server.path}max_data_initial_send"
            response_events_initial = await protocol.post(
                initial_post_path,
                content=b'D' * data_to_send_size,
                headers=[(b"content-length", b"%d" % data_to_send_size)]
            )
            if not response_events_initial or not isinstance(response_events_initial[0], HeadersReceived):
                logger.warning(f"Initial POST request for MAX_DATA test did not get valid response headers. Path: {initial_post_path}")
                # Test might still proceed if data was sent, but this is not ideal.
            else:
                 logger.info(f"Initial POST request to {initial_post_path} completed (status: {dict(response_events_initial[0].headers).get(b':status')}).")

        except Exception as e:
            logger.error(f"Error during initial data send for MAX_DATA test: {e}")
            await protocol.ping() # Check if connection is still alive
            return # Cannot proceed if initial send fails

        limit_before_wait = protocol._quic.flow_control._remote_max_data
        logger.info(f"Connection flow control limit from peer (before wait): {limit_before_wait}")

        logger.info("Waiting for 3 seconds for server to potentially send MAX_DATA frame...")
        await asyncio.sleep(3.0)

        new_max_data_after_wait = protocol._quic.flow_control._remote_max_data
        logger.info(f"Connection flow control limit from peer (after wait): {new_max_data_after_wait}")

        if new_max_data_after_wait > limit_before_wait:
            logger.info(
                f"MAX_DATA update detected. Limit increased from {limit_before_wait} to {new_max_data_after_wait}."
            )
            
            additional_data_size = 10 * 1024 # 10KB
            logger.info(f"Attempting to send an additional {additional_data_size} bytes of data.")
            try:
                extra_post_path = f"https://{server.host}:{port}{server.path}max_data_extra_send"
                response_events_extra = await protocol.post(
                    extra_post_path,
                    content=b'M' * additional_data_size,
                    headers=[(b"content-length", b"%d" % additional_data_size)]
                )
                if response_events_extra and isinstance(response_events_extra[0], HeadersReceived):
                    logger.info(
                        f"Successfully sent additional data after MAX_DATA update. "
                        f"Extra POST to {extra_post_path} status: {dict(response_events_extra[0].headers).get(b':status')}."
                    )
                    server.result |= Result.MAX_DATA_UPDATE_OK
                else:
                    logger.warning(f"Additional POST for MAX_DATA test did not get valid response headers. Path: {extra_post_path}")

            except Exception as e:
                logger.error(f"Error sending additional data after MAX_DATA update: {e}")
        else:
            logger.warning(
                f"Connection flow control limit did not increase. "
                f"Before wait: {limit_before_wait}, After wait: {new_max_data_after_wait}. "
                "Server might not have sent MAX_DATA or it was not processed."
            )
        
        await protocol.ping()
        logger.info("MAX_DATA frame handling test finished.")


async def test_handshake_done_received(
    server: Server, configuration: QuicConfiguration
):
    port = server.http3_port or server.port
    # server.path is not strictly needed for this test, but HttpClient requires a path for GET/POST.
    # We'll use a simple GET request to ensure the connection proceeds.
    if server.path is None:
        return

    quic_logger = QuicLogger()
    configuration.quic_logger = quic_logger
    configuration.alpn_protocols = H3_ALPN 

    async with connect(
        server.host,
        port,
        configuration=configuration,
        create_protocol=HttpClient,
    ) as protocol:
        protocol = cast(HttpClient, protocol)
        logger = protocol._quic._logger

        # Ensure handshake is confirmed from client's perspective
        await protocol._quic.wait_handshake_confirmed()
        logger.info("Handshake confirmed by client.")
        
        # Perform a simple GET request to ensure data exchange happens and server has opportunity
        # to send HANDSHAKE_DONE if it hasn't already by the time wait_handshake_confirmed() returns.
        # Some servers might send HANDSHAKE_DONE very promptly.
        try:
            await protocol.get(f"https://{server.host}:{port}{server.path}handshake_done_check")
        except Exception as e:
            logger.warning(f"GET request during HANDSHAKE_DONE check failed: {e}")
            # Proceed to check QLOG anyway, as HANDSHAKE_DONE might have been processed.

        handshake_done_frame_found = False
        try:
            log_dict = quic_logger.to_dict()
            if log_dict and "traces" in log_dict and log_dict["traces"]:
                for event in log_dict["traces"][0].get("events", []):
                    if event.get("name") == "transport:frame_received":
                        for frame_data in event.get("data", {}).get("frames", []):
                            if frame_data.get("frame_type") == "handshake_done":
                                handshake_done_frame_found = True
                                logger.info("HANDSHAKE_DONE frame successfully detected in QLOG from server.")
                                break
                        if handshake_done_frame_found:
                            break
        except Exception e:
            logger.error(f"Error processing QLOG for HANDSHAKE_DONE detection: {e}")

        if handshake_done_frame_found:
            server.result |= Result.HANDSHAKE_DONE_RECEIVED_OK
        else:
            logger.warning("HANDSHAKE_DONE frame not detected in QLOG from server.")
            # Note: A server is only REQUIRED to send HANDSHAKE_DONE if it's a TLS 1.3 server
            # and the handshake completes successfully. This test assumes it should be sent.

        await protocol.ping() # Final health check
        logger.info("HANDSHAKE_DONE reception test finished.")
    

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


async def test_protocol_violation_handling(server: Server, configuration: QuicConfiguration):
    if configuration.quic_logger is None:
        print("QuicLogger not configured, cannot verify PROTOCOL_VIOLATION handling.")
        return

    configuration.alpn_protocols = H3_ALPN # Or any common ALPN
    
    # Import necessary enums
    from aioquic.quic.packet import FrameType, QuicErrorCode
    from aioquic.quic.connection import QuicConnectionError

    async with connect(
        server.host,
        server.port, # Using standard port, can be server.http3_port or server.port
        configuration=configuration,
        # Using default create_protocol, but can also be HttpClient if http interaction is needed before violation
    ) as protocol: # protocol is QuicConnection when create_protocol is default
        
        await protocol.ping() # Ensure connection is established and handshake is complete
        protocol._quic._logger.info("Connection established, preparing to send illicit HANDSHAKE_DONE frame.")

        try:
            # Attempt to send HANDSHAKE_DONE frame from client (violates protocol)
            # Server should only send this frame.
            # Accessing internal _send_frame might be fragile but necessary for this kind of test.
            if hasattr(protocol._quic, '_send_frame'):
                protocol._quic._send_frame(FrameType.HANDSHAKE_DONE, b'')
                protocol._quic._logger.info("Sent illicit HANDSHAKE_DONE frame from client.")
                # Ensure the packet containing this frame is actually sent out
                protocol._quic.send_datagram_frame(b'') # Sending an empty datagram forces a packet send if one is pending
                                                       # Or, more directly, trigger transmission if available
                                                       # Forcing a ping will also try to send data
            else:
                protocol._quic._logger.error("_send_frame method not found on QuicConnection. Cannot perform test.")
                return

            # Wait for the server to process the frame and react.
            # The server should close the connection. This ping will likely fail.
            await protocol.ping()
            protocol._quic._logger.warning("Ping after sending illicit frame succeeded, server might not have reacted as expected.")

        except QuicConnectionError as e:
            protocol._quic._logger.info(f"QuicConnectionError caught as expected: {e} (Error Code: {e.error_code}, Reason: {e.reason_phrase})")
            # This is an expected outcome if the server closes the connection due to the violation.
            # We still need to check the logger for the *reason* the server closed.
            # If e.error_code is PROTOCOL_VIOLATION and e.from_client is False (if such a field existed), it'd be a quick check.
            # aioquic's QuicConnectionError typically reflects local conditions or library-detected issues,
            # not always directly the peer's CONNECTION_CLOSE frame error code.
            # So, logger check is more definitive for peer's reason.
            pass
        except Exception as e:
            protocol._quic._logger.error(f"Unexpected exception: {e}")
            # Not necessarily a failure of the test's objective, but unexpected.
            pass
        
        # Inspect logger for server-initiated connection close with PROTOCOL_VIOLATION
        found_protocol_violation_close = False
        try:
            log_data = configuration.quic_logger.to_dict()
            traces = log_data.get("traces", [])
            if not traces:
                protocol._quic._logger.warning("No traces found in QUIC log for PVH check.")
            else:
                for trace in traces: # Iterate over all traces if multiple exist (rare for client)
                    for event in trace.get("events", []):
                        event_name = event.get("name")
                        event_data = event.get("data", {})

                        # Option 1: Explicit connection_terminated event from logger
                        if event_name == "transport:connection_terminated":
                            # Check if error_code matches PROTOCOL_VIOLATION
                            # The integer value for PROTOCOL_VIOLATION is 0x1.
                            # QuicErrorCode.PROTOCOL_VIOLATION.value can be used.
                            if event_data.get("error_code") == QuicErrorCode.PROTOCOL_VIOLATION:
                                # How to confirm server-initiated?
                                # If the client didn't call .close() with this error.
                                # For this test, we assume if we see this after our bad frame, it's server.
                                # A more robust check would be if the event data has a "source" or "trigger"
                                # indicating peer. aioquic logs might not be that detailed for this event.
                                protocol._quic._logger.info(
                                    f"transport:connection_terminated event with PROTOCOL_VIOLATION found."
                                )
                                found_protocol_violation_close = True
                                break
                            elif event_data.get("error_code_str") == "PROTOCOL_VIOLATION": # some loggers might use str
                                protocol._quic._logger.info(
                                    f"transport:connection_terminated event with PROTOCOL_VIOLATION (str) found."
                                )
                                found_protocol_violation_close = True
                                break


                        # Option 2: Inferring from a received CONNECTION_CLOSE frame in a packet
                        elif event_name == "transport:packet_received":
                            for frame in event_data.get("frames", []):
                                if frame.get("frame_type") == "connection_close" and \
                                   frame.get("error_code") == QuicErrorCode.PROTOCOL_VIOLATION:
                                    # This frame being in a "packet_received" event means it came from the peer (server)
                                    protocol._quic._logger.info(
                                        f"Received CONNECTION_CLOSE frame with PROTOCOL_VIOLATION from server."
                                    )
                                    found_protocol_violation_close = True
                                    break
                        if found_protocol_violation_close:
                            break
                    if found_protocol_violation_close:
                        break
            
            if found_protocol_violation_close:
                server.result |= Result.PVH
                protocol._quic._logger.info("Server correctly closed with PROTOCOL_VIOLATION. PVH flag set.")
            else:
                protocol._quic._logger.warning(
                    "Server did not close with PROTOCOL_VIOLATION, or event not found/matched in logs."
                )

        except Exception as e:
            protocol._quic._logger.error(f"Error inspecting QUIC log for PROTOCOL_VIOLATION: {e}")


async def test_server_initiated_close_specific_error(server: Server, configuration: QuicConfiguration):
    if configuration.quic_logger is None:
        print("QuicLogger not configured, cannot verify SCSE test.")
        return
    
    if server.path is None: # Path needed for initial GET request
        print("No server.path defined for SCSE test.")
        return

    configuration.alpn_protocols = H3_ALPN
    
    # Import necessary enums and functions
    from aioquic.h3.connection import ErrorCode, encode_frame, encode_settings
    from aioquic.h3.frames import H3FrameType
    from aioquic.quic.connection import QuicConnectionError

    get_task = None # Define for cleanup in case of early exit

    async with connect(
        server.host,
        server.http3_port or server.port,
        configuration=configuration,
        create_protocol=HttpClient,
    ) as protocol:
        http_client = cast(HttpClient, protocol)
        
        await http_client.ping() # Ensure connection is established
        http_client._quic._logger.info("Connection established for SCSE test.")

        # Initiate a GET request as a task to open a request stream
        get_task = asyncio.create_task(
            http_client.get(
                "https://{}:{}{}".format(server.host, server.http3_port or server.port, server.path)
            )
        )
        await asyncio.sleep(0.1) # Allow request to initiate and stream to be created

        # Identify the stream ID for the GET request
        client_stream_id = None
        max_client_stream_id = -1
        for stream_id, stream in http_client._quic._streams.items():
            if stream_id % 4 == 0 and not stream.is_closed: # Client bidi stream
                if http_client._http._stream_is_pending(stream_id) or http_client._http._stream_exists(stream_id):
                    if stream_id > max_client_stream_id:
                        max_client_stream_id = stream_id
        
        if max_client_stream_id != -1:
            client_stream_id = max_client_stream_id
        
        if client_stream_id is None:
            http_client._quic._logger.error("Could not identify client request stream ID for SCSE test.")
            if get_task and not get_task.done():
                get_task.cancel()
            try:
                if get_task: await get_task
            except asyncio.CancelledError: pass
            return

        http_client._quic._logger.info(f"Identified request stream {client_stream_id} for SCSE test.")

        # Construct an H3 SETTINGS frame
        settings_payload = encode_settings({}) 
        h3_settings_frame_bytes = encode_frame(H3FrameType.SETTINGS, settings_payload)
        http_client._quic._logger.info(f"Constructed H3 SETTINGS frame: {h3_settings_frame_bytes.hex()}")

        try:
            # Send the H3 SETTINGS frame on the request stream (this is the violation)
            http_client._quic.send_stream_data(client_stream_id, h3_settings_frame_bytes, end_stream=False)
            http_client._quic._logger.info(f"Sent illicit H3 SETTINGS frame on request stream {client_stream_id}.")
            
            # Wait for the server to process and react. Expect connection closure.
            await http_client.ping() # This ping should ideally fail
            http_client._quic._logger.warning("Ping after sending illicit SETTINGS frame succeeded, server might not have reacted as expected.")

        except QuicConnectionError as e:
            http_client._quic._logger.info(f"QuicConnectionError caught as expected after sending bad frame: {e}")
            # This is expected. Now verify the reason in the logs.
            pass
        except Exception as e:
            http_client._quic._logger.error(f"Unexpected exception after sending bad frame: {e}")
            # Continue to log inspection, as connection might have closed for the right reason anyway.
            pass
        finally:
            if get_task and not get_task.done():
                get_task.cancel()
            try:
                if get_task: await get_task
            except asyncio.CancelledError:
                http_client._quic._logger.info(f"GET task for stream {client_stream_id} cancelled during cleanup.")
            except Exception as e:
                 http_client._quic._logger.error(f"Exception from GET task during cleanup: {e}")


        # Inspect logger for server-initiated connection close with H3_FRAME_UNEXPECTED
        found_specific_error_close = False
        expected_h3_error_code = ErrorCode.H3_FRAME_UNEXPECTED 
        
        try:
            log_data = configuration.quic_logger.to_dict()
            traces = log_data.get("traces", [])
            if not traces:
                http_client._quic._logger.warning("No traces found in QUIC log for SCSE check.")
            else:
                for trace in traces:
                    for event in trace.get("events", []):
                        event_name = event.get("name")
                        event_data = event.get("data", {})

                        if event_name == "transport:connection_terminated":
                            logged_error_code = event_data.get("error_code")
                            # In qlog, H3 errors might be directly in error_code for connection_terminated
                            if logged_error_code == expected_h3_error_code.value:
                                http_client._quic._logger.info(
                                    f"transport:connection_terminated event with H3_FRAME_UNEXPECTED ({expected_h3_error_code.value}) found."
                                )
                                found_specific_error_close = True
                                break
                        
                        elif event_name == "transport:packet_received":
                            for frame in event_data.get("frames", []):
                                if frame.get("frame_type") == "connection_close":
                                    # For H3, the application error code is in 'error_code' field of CONNECTION_CLOSE in qlog spec for H3.
                                    # Some implementations might use 'application_error_code' but standard qlog for QUIC's CONNECTION_CLOSE
                                    # uses 'error_code' for the QUIC error and 'application_error_code' for the app layer (H3).
                                    # However, aioquic's logger for a CONNECTION_CLOSE frame (non-0x1c type) puts the H3 code in 'error_code'.
                                    # For 0x1d (application close), it's in 'application_error_code'.
                                    # Let's check both common ways it might be logged.
                                    
                                    # Check QUIC CONNECTION_CLOSE frame (type 0x1c or 0x1d)
                                    # If it's 0x1c, error_code is QUIC error, reason_phrase might contain H3 error.
                                    # If it's 0x1d, application_error_code is H3 error.
                                    # aioquic's logger seems to put the H3 error in 'error_code' field of the frame data
                                    # when it's an application error that leads to CONNECTION_CLOSE.
                                    logged_frame_error_code = frame.get("error_code")
                                    if logged_frame_error_code == expected_h3_error_code.value:
                                        http_client._quic._logger.info(
                                            f"Received CONNECTION_CLOSE frame with 'error_code' H3_FRAME_UNEXPECTED ({expected_h3_error_code.value})."
                                        )
                                        found_specific_error_close = True
                                        break
                                    # Also check application_error_code for type 0x1d frames if the above isn't hit
                                    # This might be redundant if aioquic normalizes it, but good for robustness
                                    elif frame.get("close_type") == "application_close" and frame.get("application_error_code") == expected_h3_error_code.value:
                                        http_client._quic._logger.info(
                                            f"Received CONNECTION_CLOSE (application) frame with 'application_error_code' H3_FRAME_UNEXPECTED ({expected_h3_error_code.value})."
                                        )
                                        found_specific_error_close = True
                                        break
                        if found_specific_error_close:
                            break
                    if found_specific_error_close:
                        break
            
            if found_specific_error_close:
                server.result |= Result.SCSE
                http_client._quic._logger.info(f"Server correctly closed with H3_FRAME_UNEXPECTED. SCSE flag set for server {server.name}.")
            else:
                http_client._quic._logger.warning(
                    f"Server {server.name} did not close with H3_FRAME_UNEXPECTED ({expected_h3_error_code.value}), or event not found/matched in logs."
                )

        except Exception as e:
            http_client._quic._logger.error(f"Error inspecting QUIC log for SCSE check: {e}")


async def test_migration_with_loss(server: Server, configuration: QuicConfiguration):
    if configuration.quic_logger is None:
        print("QuicLogger not configured, cannot verify MWL test.")
        return

    # Using H3_ALPN for consistency, though the test primarily uses raw QuicConnection features
    configuration.alpn_protocols = H3_ALPN 
    
    from aioquic.quic.connection import QuicConnectionError

    async with connect(
        server.host,
        server.port, # Using standard port
        configuration=configuration,
        # Default create_protocol gives QuicConnection, which is what we want for this test
    ) as protocol: # protocol is QuicConnection
        
        protocol._quic._logger.info("MWL Test: Connection established, performing initial ping.")
        await protocol.ping()
        protocol._quic._logger.info("MWL Test: Initial ping successful.")

        original_local_addr = protocol._transport.get_extra_info('sockname')
        if original_local_addr is None:
            protocol._quic._logger.error("MWL Test: Could not get original local address.")
            return
        
        # Attempt to migrate to a new port on the same IP
        new_local_addr = (original_local_addr[0], 0)
        protocol._quic._logger.info(f"MWL Test: Original addr {original_local_addr}, attempting migration to new port on same IP ({new_local_addr[0]}:0).")

        # Close current transport
        protocol._transport.close()
        protocol._quic._logger.info("MWL Test: Original transport closed.")

        loop = asyncio.get_event_loop()
        try:
            # Create new transport and rebind protocol
            # The 'protocol' instance itself is reused by the lambda.
            # The `create_datagram_endpoint` will update the transport used by the protocol instance.
            _,_ = await loop.create_datagram_endpoint(
                lambda: protocol, local_addr=new_local_addr
            )
            protocol._quic._logger.info(f"MWL Test: Rebound to new local address {protocol._transport.get_extra_info('sockname')}.")
            
            protocol.change_connection_id() # Recommended during migration
            protocol.probe_new_path()      # Explicitly send PATH_CHALLENGE
            protocol._quic._logger.info("MWL Test: change_connection_id() and probe_new_path() called.")

        except Exception as e:
            protocol._quic._logger.error(f"MWL Test: Error during transport migration: {e}")
            return # Cannot proceed if migration setup fails

        # Post-migration operations to check stability and recovery
        migration_successful_communication = False
        try:
            protocol._quic._logger.info("MWL Test: Attempting first ping after migration.")
            await protocol.ping()
            protocol._quic._logger.info("MWL Test: First ping after migration successful.")

            # Open a new stream and send some data
            # This requires protocol._quic as it's a QuicConnection feature
            new_stream_id = protocol._quic.get_next_available_stream_id(is_unidirectional=False)
            protocol._quic._logger.info(f"MWL Test: Opening new stream {new_stream_id} and sending data.")
            message = b"Data after migration on new stream"
            protocol._quic.send_stream_data(new_stream_id, message, end_stream=True)
            # We might need to ensure this data is flushed / acked for a full test.
            # A subsequent ping helps confirm connectivity for this.

            protocol._quic._logger.info("MWL Test: Attempting second ping after migration and data send.")
            await protocol.ping()
            protocol._quic._logger.info("MWL Test: Second ping after migration successful. Communication appears stable.")
            migration_successful_communication = True

        except QuicConnectionError as e:
            protocol._quic._logger.error(f"MWL Test: QuicConnectionError during post-migration operations: {e}")
        except Exception as e:
            protocol._quic._logger.error(f"MWL Test: Unexpected exception during post-migration operations: {e}")

        # Log inspection for path validation
        path_challenge_sent = False
        path_response_received = False
        # Optional: Check for packet loss and retransmission (harder to guarantee observation)
        # For now, focus on PATH_CHALLENGE/RESPONSE and successful communication.

        try:
            log_data = configuration.quic_logger.to_dict()
            traces = log_data.get("traces", [])
            if not traces:
                protocol._quic._logger.warning("MWL Test: No traces found in QUIC log for inspection.")
            else:
                for trace in traces: # Should typically be one trace for client
                    for event in trace.get("events", []):
                        event_name = event.get("name")
                        event_data = event.get("data", {})
                        
                        if event_name == "transport:packet_sent":
                            for frame in event_data.get("frames", []):
                                if frame.get("frame_type") == "path_challenge":
                                    path_challenge_sent = True
                                    # Could also log frame.get("data") to see the challenge data
                        elif event_name == "transport:packet_received":
                            for frame in event_data.get("frames", []):
                                if frame.get("frame_type") == "path_response":
                                    path_response_received = True
                                    # Could also log frame.get("data") to see the response data
            
            if path_challenge_sent and path_response_received:
                protocol._quic._logger.info("MWL Test: PATH_CHALLENGE sent and PATH_RESPONSE received confirmed in logs.")
            else:
                protocol._quic._logger.warning(
                    f"MWL Test: Path validation status - Challenge Sent: {path_challenge_sent}, Response Received: {path_response_received}."
                )

        except Exception as e:
            protocol._quic._logger.error(f"MWL Test: Error inspecting QUIC log: {e}")

        # Determine overall success
        if migration_successful_communication and path_challenge_sent and path_response_received:
            protocol._quic._logger.info(f"MWL Test: Successful for server {server.name}. Post-migration comms OK & path validated.")
            server.result |= Result.MWL
        elif migration_successful_communication:
            # If comms are fine but path validation log evidence is weak/missing, still a partial success.
            # For this test, we'll require path validation to be observed for the MWL flag.
            protocol._quic._logger.warning(
                f"MWL Test: Post-migration communication for server {server.name} was successful, but path validation (CHALLENGE/RESPONSE) "
                "was not fully confirmed in logs. Not setting MWL flag based on current criteria."
            )
            # If the requirement was softer, this could be server.result |= Result.MWL
        else:
            protocol._quic._logger.warning(f"MWL Test: Failed for server {server.name} due to communication issues post-migration or lack of path validation.")


async def test_h3_settings_error_handling(server: Server, configuration: QuicConfiguration):
    if configuration.quic_logger is None:
        print("QuicLogger not configured, cannot verify H3SE test.")
        return

    configuration.alpn_protocols = H3_ALPN
    
    # Import necessary enums and functions
    from aioquic.h3.connection import ErrorCode, encode_frame
    from aioquic.h3.frames import H3FrameType
    from aioquic.quic.connection import QuicConnectionError

    async with connect(
        server.host,
        server.http3_port or server.port,
        configuration=configuration,
        create_protocol=HttpClient,
    ) as protocol:
        http_client = cast(HttpClient, protocol)
        
        # Ensure H3 handshake completes and control streams are established.
        # A ping often achieves this as HttpClient sets up H3 on first use.
        try:
            await http_client.ping()
            http_client._quic._logger.info("H3SE Test: Initial ping successful, H3 connection should be ready.")
        except QuicConnectionError as e:
            http_client._quic._logger.error(f"H3SE Test: Initial ping failed: {e}. Cannot proceed.")
            return

        # Get the client's local (outgoing) H3 control stream ID.
        # For clients, this is typically stream ID 2.
        control_stream_id = http_client._http._stream_id_control_local
        if control_stream_id is None:
            http_client._quic._logger.error("H3SE Test: Client's local H3 control stream ID is None. Cannot proceed.")
            return
        http_client._quic._logger.info(f"H3SE Test: Client's local H3 control stream ID: {control_stream_id}.")

        # Construct a malformed H3 SETTINGS frame (using a reserved setting ID 0x21).
        # Payload: ID 0x21 (2 bytes, network order for hypothetical value if it had one, but not needed for type)
        # For a setting with ID 0x21 and length 0, the payload is just \x21\x00
        malformed_settings_payload = b'\x21\x00' # Setting ID 0x21 (reserved), length 0
        malformed_settings_frame_bytes = encode_frame(H3FrameType.SETTINGS, malformed_settings_payload)
        http_client._quic._logger.info(f"H3SE Test: Constructed malformed H3 SETTINGS frame: {malformed_settings_frame_bytes.hex()}")

        try:
            # Send the malformed H3 SETTINGS frame on the client's H3 control stream.
            http_client._quic.send_stream_data(control_stream_id, malformed_settings_frame_bytes, end_stream=False)
            http_client._quic._logger.info(f"H3SE Test: Sent malformed H3 SETTINGS frame on control stream {control_stream_id}.")
            
            # Wait for the server to process and react. Expect connection closure.
            await http_client.ping() # This ping should ideally fail.
            http_client._quic._logger.warning("H3SE Test: Ping after sending malformed SETTINGS frame succeeded, server might not have reacted as expected.")

        except QuicConnectionError as e:
            http_client._quic._logger.info(f"H3SE Test: QuicConnectionError caught as expected after sending malformed SETTINGS: {e}")
            # This is expected. Now verify the reason in the logs.
        except Exception as e:
            http_client._quic._logger.error(f"H3SE Test: Unexpected exception after sending malformed SETTINGS: {e}")
            # Continue to log inspection.
            pass

        # Inspect logger for server-initiated connection close with H3_SETTINGS_ERROR
        found_h3_settings_error_close = False
        expected_h3_error_code = ErrorCode.H3_SETTINGS_ERROR
        
        try:
            log_data = configuration.quic_logger.to_dict()
            traces = log_data.get("traces", [])
            if not traces:
                http_client._quic._logger.warning("H3SE Test: No traces found in QUIC log for H3SE check.")
            else:
                for trace in traces:
                    for event in trace.get("events", []):
                        event_name = event.get("name")
                        event_data = event.get("data", {})

                        if event_name == "transport:connection_terminated":
                            logged_error_code = event_data.get("error_code")
                            if logged_error_code == expected_h3_error_code.value:
                                http_client._quic._logger.info(
                                    f"H3SE Test: transport:connection_terminated event with H3_SETTINGS_ERROR ({expected_h3_error_code.value}) found."
                                )
                                found_h3_settings_error_close = True
                                break
                        
                        elif event_name == "transport:packet_received":
                            for frame in event_data.get("frames", []):
                                if frame.get("frame_type") == "connection_close":
                                    # Check based on findings from SCSE test for how H3 errors are logged in CONNECTION_CLOSE
                                    logged_frame_error_code = frame.get("error_code") # for aioquic qlog when app error
                                    application_error_code = frame.get("application_error_code") # for 0x1d type if distinct

                                    if logged_frame_error_code == expected_h3_error_code.value:
                                        http_client._quic._logger.info(
                                            f"H3SE Test: Received CONNECTION_CLOSE frame with 'error_code' H3_SETTINGS_ERROR ({expected_h3_error_code.value})."
                                        )
                                        found_h3_settings_error_close = True
                                        break
                                    elif frame.get("close_type") == "application_close" and application_error_code == expected_h3_error_code.value:
                                        http_client._quic._logger.info(
                                            f"H3SE Test: Received CONNECTION_CLOSE (application) frame with 'application_error_code' H3_SETTINGS_ERROR ({expected_h3_error_code.value})."
                                        )
                                        found_h3_settings_error_close = True
                                        break
                        if found_h3_settings_error_close:
                            break
                    if found_h3_settings_error_close:
                        break
            
            if found_h3_settings_error_close:
                server.result |= Result.H3SE
                http_client._quic._logger.info(f"H3SE Test: Server correctly closed with H3_SETTINGS_ERROR. H3SE flag set for server {server.name}.")
            else:
                http_client._quic._logger.warning(
                    f"H3SE Test: Server {server.name} did not close with H3_SETTINGS_ERROR ({expected_h3_error_code.value}), or event not found/matched in logs."
                )

        except Exception as e:
            http_client._quic._logger.error(f"H3SE Test: Error inspecting QUIC log: {e}")


async def test_0rtt_rejection_fallback(server: Server, configuration: QuicConfiguration):
    if server.path is None: # Path needed for GET requests
        # Using a default path if server.path is None, as GET requests are central to this test.
        request_path = "/0rtt_fallback_test"
        print(f"Server {server.name} has no server.path, using default {request_path} for ZRF test.")
    else:
        request_path = server.path

    if configuration.quic_logger is None: # Base configuration from main, will be cloned.
        print("Main QuicLogger not configured. ZRF test might lack detailed logs but will proceed.")
        # We will ensure phase-specific loggers are set up if possible.

    # Phase 1: Obtain Session Ticket
    saved_ticket_holder = [None]
    def session_ticket_handler(ticket):
        saved_ticket_holder[0] = ticket
        # Log ticket reception for debugging
        # print(f"Session ticket received for {server.name}, length {len(ticket.ticket) if ticket else 'None'}")

    config_phase1 = QuicConfiguration(
        alpn_protocols=H3_ALPN,
        is_client=True,
        session_ticket_handler=session_ticket_handler,
        # Clone quic_logger settings from the main configuration if possible, or create new.
        quic_logger=QuicFileLogger(configuration.quic_logger.path) if hasattr(configuration.quic_logger, 'path') and configuration.quic_logger.path else QuicLogger(),
        secrets_log_file=configuration.secrets_log_file,
        verify_mode=configuration.verify_mode,
    )
    # Ensure secrets log is open if specified, similar to main runner
    phase1_secrets_log_file_obj = None
    if config_phase1.secrets_log_file and isinstance(config_phase1.secrets_log_file, str):
        try:
            phase1_secrets_log_file_obj = open(config_phase1.secrets_log_file, "a")
            config_phase1.secrets_log_file = phase1_secrets_log_file_obj
        except Exception as e:
            print(f"Error opening secrets log for phase 1: {e}")


    print(f"ZRF Test ({server.name}): Starting Phase 1 - Obtain session ticket.")
    try:
        async with connect(
            server.host,
            server.http3_port or server.port,
            configuration=config_phase1,
            create_protocol=HttpClient,
        ) as protocol_phase1:
            http_client_phase1 = cast(HttpClient, protocol_phase1)
            await http_client_phase1.get(
                "https://{}:{}{}".format(server.host, server.http3_port or server.port, request_path)
            )
            await asyncio.sleep(0.5) # Allow time for ticket to be sent
        print(f"ZRF Test ({server.name}): Phase 1 connection closed.")
    except Exception as e:
        print(f"ZRF Test ({server.name}): Error during Phase 1: {e}")
        if phase1_secrets_log_file_obj: phase1_secrets_log_file_obj.close()
        return # Cannot proceed if phase 1 fails

    if phase1_secrets_log_file_obj: phase1_secrets_log_file_obj.close()

    if saved_ticket_holder[0] is None:
        print(f"ZRF Test ({server.name}): Did not receive a session ticket in Phase 1. Cannot test 0-RTT. Server might not support resumption.")
        return

    print(f"ZRF Test ({server.name}): Session ticket obtained. Starting Phase 2 - Attempt 0-RTT.")

    # Phase 2: Attempt 0-RTT and Verify Behavior
    config_phase2 = QuicConfiguration(
        alpn_protocols=H3_ALPN,
        is_client=True,
        session_ticket=saved_ticket_holder[0],
        quic_logger=QuicFileLogger(configuration.quic_logger.path + "_phase2") if hasattr(configuration.quic_logger, 'path') and configuration.quic_logger.path else QuicLogger(),
        secrets_log_file=configuration.secrets_log_file,
        verify_mode=configuration.verify_mode,
    )
    phase2_secrets_log_file_obj = None
    if config_phase2.secrets_log_file and isinstance(config_phase2.secrets_log_file, str):
        try:
            phase2_secrets_log_file_obj = open(config_phase2.secrets_log_file, "a") # Append to same log
            config_phase2.secrets_log_file = phase2_secrets_log_file_obj
        except Exception as e:
            print(f"Error opening secrets log for phase 2: {e}")


    early_get_succeeded = False
    fallback_get_succeeded = False
    
    try:
        async with connect(
            server.host,
            server.http3_port or server.port,
            configuration=config_phase2,
            create_protocol=HttpClient,
        ) as protocol_phase2:
            http_client_phase2 = cast(HttpClient, protocol_phase2)
            logger_phase2 = http_client_phase2._quic._logger # For convenience

            logger_phase2.info(f"ZRF Test ({server.name}): Phase 2 connected. Attempting initial GET (potential 0-RTT).")
            
            try:
                # First GET attempt - this may be 0-RTT or 1-RTT
                response1_events = await http_client_phase2.get(
                     "https://{}:{}{}_0rtt".format(server.host, server.http3_port or server.port, request_path)
                )
                
                if response1_events and isinstance(response1_events[0], HeadersReceived) and \
                   (cast(HeadersReceived, response1_events[0]).status_code // 100 == 2):
                    logger_phase2.info(f"ZRF Test ({server.name}): Initial GET succeeded with status {cast(HeadersReceived, response1_events[0]).status_code}.")
                    if http_client_phase2._quic.tls.early_data_accepted:
                        early_get_succeeded = True
                        logger_phase2.info(f"ZRF Test ({server.name}): 0-RTT data was accepted and GET successful.")
                    else:
                        fallback_get_succeeded = True # GET worked, but was 1-RTT
                        logger_phase2.info(f"ZRF Test ({server.name}): 0-RTT data was NOT accepted (or not sent), but GET successful via 1-RTT.")
                else:
                    status = cast(HeadersReceived, response1_events[0]).status_code if response1_events and isinstance(response1_events[0], HeadersReceived) else "N/A"
                    logger_phase2.warning(f"ZRF Test ({server.name}): Initial GET request failed or non-2xx status: {status}.")

            except QuicConnectionError as e:
                logger_phase2.warning(f"ZRF Test ({server.name}): QuicConnectionError during initial GET: {e}. This might be 0-RTT rejection.")
                # Check if handshake completed and early data was NOT accepted (typical for 0-RTT rejection)
                if http_client_phase2._quic.is_handshake_completed and \
                   not http_client_phase2._quic.tls.early_data_accepted:
                    logger_phase2.info(f"ZRF Test ({server.name}): Handshake completed, 0-RTT rejected. Attempting fallback 1-RTT GET.")
                    try:
                        response2_events = await http_client_phase2.get(
                            "https://{}:{}{}_1rtt_fallback".format(server.host, server.http3_port or server.port, request_path)
                        )
                        if response2_events and isinstance(response2_events[0], HeadersReceived) and \
                           (cast(HeadersReceived, response2_events[0]).status_code // 100 == 2):
                            fallback_get_succeeded = True
                            logger_phase2.info(f"ZRF Test ({server.name}): Fallback 1-RTT GET succeeded.")
                        else:
                            status2 = cast(HeadersReceived, response2_events[0]).status_code if response2_events and isinstance(response2_events[0], HeadersReceived) else "N/A"
                            logger_phase2.warning(f"ZRF Test ({server.name}): Fallback 1-RTT GET failed or non-2xx status: {status2}.")
                    except Exception as e_fallback:
                        logger_phase2.error(f"ZRF Test ({server.name}): Exception during fallback 1-RTT GET: {e_fallback}")
                else:
                    logger_phase2.error(f"ZRF Test ({server.name}): Handshake not completed or early data accepted despite QuicConnectionError. State: HandshakeCompleted={http_client_phase2._quic.is_handshake_completed}, EarlyDataAccepted={http_client_phase2._quic.tls.early_data_accepted}")
            except Exception as e_initial:
                logger_phase2.error(f"ZRF Test ({server.name}): Unexpected exception during initial GET: {e_initial}")


            if early_get_succeeded or fallback_get_succeeded:
                logger_phase2.info(f"ZRF Test ({server.name}): Successfully processed. EarlyGET={early_get_succeeded}, FallbackGET={fallback_get_succeeded}. Setting ZRF flag.")
                server.result |= Result.ZRF
            else:
                logger_phase2.warning(f"ZRF Test ({server.name}): Neither 0-RTT GET nor fallback 1-RTT GET succeeded.")
            
            # Optional: Detailed log inspection for specific TLS events (for debugging/confirmation)
            # This part is for deeper analysis and doesn't change ZRF flag logic above.
            try:
                log_data_phase2 = config_phase2.quic_logger.to_dict()
                early_data_event_found = False
                for trace in log_data_phase2.get("traces", []):
                    for event in trace.get("events", []):
                        if event.get("name") in ["tls:event:client_early_data_accepted", "tls:event:client_early_data_rejected"]:
                            logger_phase2.info(f"ZRF Test ({server.name}): Found TLS event in log: {event.get('name')}")
                            early_data_event_found = True
                            break
                    if early_data_event_found: break
                if not early_data_event_found:
                     logger_phase2.info(f"ZRF Test ({server.name}): No specific early_data_accepted/rejected TLS event in logs.")
            except Exception as e_log:
                logger_phase2.error(f"ZRF Test ({server.name}): Error inspecting Phase 2 QUIC log: {e_log}")


    except Exception as e_phase2_connect:
        print(f"ZRF Test ({server.name}): Error during Phase 2 connect/setup: {e_phase2_connect}")
    finally:
        if phase2_secrets_log_file_obj: phase2_secrets_log_file_obj.close()
        print(f"ZRF Test ({server.name}): Phase 2 finished.")


async def test_qpack_dynamic_table_capacity(server: Server, configuration: QuicConfiguration):
    if server.path is None:
        print(f"QTC Test ({server.name}): No server.path defined. Skipping test.")
        return
    
    if configuration.quic_logger is None:
        # This configuration is the one passed from the main runner.
        # We will use it as a base for our test-specific config.
        print(f"QTC Test ({server.name}): Main QuicLogger not configured. Test will create its own.")
        # If the base logger is None, our new config will also have a default QuicLogger.
        base_logger_path = None
    else:
        base_logger_path = getattr(configuration.quic_logger, 'path', None)


    from aioquic.h3.settings import Setting
    from aioquic.h3.connection import ErrorCode
    from aioquic.h3.events import HeadersReceived
    from aioquic.quic.connection import QuicConnectionError

    # Create a test-specific configuration
    # We are setting the QPACK_MAX_TABLE_CAPACITY that this client *wishes* to use for its decoder.
    # The client will also respect the server's announced QPACK_MAX_TABLE_CAPACITY for its encoder.
    test_config = QuicConfiguration(
        alpn_protocols=H3_ALPN,
        is_client=True,
        quic_logger=QuicFileLogger(base_logger_path + "_qtc") if base_logger_path else QuicLogger(),
        secrets_log_file=configuration.secrets_log_file, # Reuse from main config
        verify_mode=configuration.verify_mode, # Reuse from main config
        http3_settings={Setting.SETTINGS_QPACK_MAX_TABLE_CAPACITY: 1024} # Our client's decoder capacity
    )
    
    # Manage secrets log file if specified as a path
    test_secrets_log_file_obj = None
    if test_config.secrets_log_file and isinstance(test_config.secrets_log_file, str):
        try:
            test_secrets_log_file_obj = open(test_config.secrets_log_file, "a")
            test_config.secrets_log_file = test_secrets_log_file_obj
        except Exception as e:
            print(f"QTC Test ({server.name}): Error opening secrets log: {e}")

    print(f"QTC Test ({server.name}): Starting test with client QPACK capacity set to 1024.")
    
    requests_successful = True
    try:
        async with connect(
            server.host,
            server.http3_port or server.port,
            configuration=test_config,
            create_protocol=HttpClient, # from http3_client import HttpClient
        ) as http_client:
            http_client = cast(HttpClient, http_client)
            logger = http_client._quic._logger # For convenience

            logger.info(f"QTC Test ({server.name}): Connection established. Performing initial ping.")
            await http_client.ping()
            logger.info(f"QTC Test ({server.name}): Initial ping successful. H3 setup complete.")

            num_requests = 7 # Send a series of requests
            for i in range(num_requests):
                current_path = server.path + f"?q={i}"
                headers = [
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", server.host.encode('utf-8')), # Ensure authority is bytes
                    (b":path", current_path.encode('utf-8')),     # Ensure path is bytes
                    (b"user-agent", b"aioquic-interop-runner-qtc/1.0"),
                    (b"x-custom-header", f"value-{i}".encode('utf-8')),
                    (b"accept", b"application/json"),
                    (b"cache-control", b"no-cache"),
                ]
                
                logger.info(f"QTC Test ({server.name}): Sending request {i+1}/{num_requests} to {current_path}")
                
                response_events = await http_client.request(
                    method="GET",
                    url=f"https://{server.host}:{server.http3_port or server.port}{current_path}",
                    headers=headers
                )
                
                if not (response_events and isinstance(response_events[0], HeadersReceived) and \
                        (cast(HeadersReceived, response_events[0]).status_code // 100 == 2)):
                    status_code = cast(HeadersReceived, response_events[0]).status_code if response_events and isinstance(response_events[0], HeadersReceived) else "N/A"
                    logger.error(f"QTC Test ({server.name}): Request {i+1} failed or got non-2xx response. Status: {status_code}")
                    requests_successful = False
                    break # Stop on first failure
                
                logger.info(f"QTC Test ({server.name}): Request {i+1} successful with status {cast(HeadersReceived, response_events[0]).status_code}.")
                await asyncio.sleep(0.05) # Small delay

            if requests_successful:
                logger.info(f"QTC Test ({server.name}): All {num_requests} requests completed successfully.")
                # Primary success is that no QuicConnectionError was raised due to QPACK issues.
                # The absence of such errors implies QPACK handling was correct under the negotiated capacities.
                
                # Optional: Log inspection for specific QPACK error frames (more for debugging, as errors would likely cause QuicConnectionError)
                qpack_errors_found_in_log = False
                try:
                    log_data = test_config.quic_logger.to_dict()
                    qpack_error_codes = {
                        ErrorCode.H3_QPACK_DECOMPRESSION_FAILED.value,
                        ErrorCode.H3_QPACK_ENCODER_STREAM_ERROR.value,
                        ErrorCode.H3_QPACK_DECODER_STREAM_ERROR.value
                    }
                    for trace in log_data.get("traces", []):
                        for event in trace.get("events", []):
                            event_data = event.get("data", {})
                            if event.get("name") == "transport:connection_terminated":
                                if event_data.get("error_code") in qpack_error_codes:
                                    logger.warning(f"QTC Test ({server.name}): Found connection_terminated with QPACK error code {event_data.get('error_code')}.")
                                    qpack_errors_found_in_log = True; break
                            elif event.get("name") == "transport:packet_received":
                                for frame in event_data.get("frames", []):
                                    if frame.get("frame_type") == "connection_close":
                                        if frame.get("error_code") in qpack_error_codes or \
                                           (frame.get("close_type") == "application_close" and frame.get("application_error_code") in qpack_error_codes):
                                            logger.warning(f"QTC Test ({server.name}): Found CONNECTION_CLOSE frame with QPACK error code.")
                                            qpack_errors_found_in_log = True; break
                            if qpack_errors_found_in_log: break
                        if qpack_errors_found_in_log: break
                    
                    if not qpack_errors_found_in_log:
                         logger.info(f"QTC Test ({server.name}): No specific QPACK error codes found in logs' connection termination events.")

                except Exception as e_log:
                    logger.error(f"QTC Test ({server.name}): Error inspecting QUIC log for QPACK errors: {e_log}")

                # If we reached here and requests_successful is True, and no catastrophic QPACK error terminated the connection,
                # we consider the test passed. The log check is mostly for deeper diagnostics.
                if not qpack_errors_found_in_log : # Double check no specific qpack error was the cause of termination if any.
                                                # But requests_successful implies connection was not terminated by such.
                    server.result |= Result.QTC
                    logger.info(f"QTC Test ({server.name}): Test passed. QTC flag set.")
                else:
                    logger.warning(f"QTC Test ({server.name}): Requests were successful, but QPACK error codes found in log termination events. Not setting QTC flag.")


    except QuicConnectionError as e:
        print(f"QTC Test ({server.name}): QuicConnectionError occurred: {e}. Error Code: {e.error_code}, Reason: {e.reason_phrase}")
        requests_successful = False # Explicitly mark as failed
    except AssertionError as e:
        print(f"QTC Test ({server.name}): Assertion failed: {e}")
        requests_successful = False
    except Exception as e:
        print(f"QTC Test ({server.name}): An unexpected error occurred: {e}")
        requests_successful = False
    finally:
        if test_secrets_log_file_obj: test_secrets_log_file_obj.close()
        status_msg = "succeeded" if requests_successful and (server.result & Result.QTC) else "failed"
        print(f"QTC Test ({server.name}): Test run {status_msg}.")


async def test_max_streams_update_usage(server: Server, configuration: QuicConfiguration):
    if server.path is None:
        print(f"MSU Test ({server.name}): No server.path defined. Skipping test.")
        return
    
    if configuration.quic_logger is None:
        print(f"MSU Test ({server.name}): Main QuicLogger not configured. Test will create its own if needed.")
        base_logger_path = None
    else:
        base_logger_path = getattr(configuration.quic_logger, 'path', None)

    from aioquic.quic.packet import QuicErrorCode
    from aioquic.h3.events import HeadersReceived
    from aioquic.quic.connection import QuicConnectionError

    test_config = QuicConfiguration(
        alpn_protocols=H3_ALPN,
        is_client=True,
        quic_logger=QuicFileLogger(base_logger_path + "_msu") if base_logger_path else QuicLogger(),
        secrets_log_file=configuration.secrets_log_file,
        verify_mode=configuration.verify_mode,
    )
    
    test_secrets_log_file_obj = None
    if test_config.secrets_log_file and isinstance(test_config.secrets_log_file, str):
        try:
            test_secrets_log_file_obj = open(test_config.secrets_log_file, "a")
            test_config.secrets_log_file = test_secrets_log_file_obj
        except Exception as e:
            print(f"MSU Test ({server.name}): Error opening secrets log: {e}")

    print(f"MSU Test ({server.name}): Starting test.")
    
    all_tasks = [] # To keep track of all created tasks for cleanup
    extra_task = None
    additional_stream_tasks = []

    try:
        async with connect(
            server.host,
            server.http3_port or server.port,
            configuration=test_config,
            create_protocol=HttpClient,
        ) as http_client:
            http_client = cast(HttpClient, http_client)
            logger = http_client._quic._logger

            logger.info(f"MSU Test ({server.name}): Connection established. Performing initial ping.")
            await http_client.ping()
            logger.info(f"MSU Test ({server.name}): Initial ping successful.")

            max_initial_stream_id = http_client._quic._peer_max_allowed_stream_id_bidi
            if max_initial_stream_id is None: # Should be set by aioquic from transport params (default 0 if not specified by peer)
                logger.error(f"MSU Test ({server.name}): _peer_max_allowed_stream_id_bidi is None. Cannot determine initial limit.")
                return
            
            # Number of client-initiated bidi streams = (ID / 4) + 1. ID 0 = 1 stream. ID 4 = 2 streams.
            initial_limit_count = (max_initial_stream_id // 4) + 1
            logger.info(f"MSU Test ({server.name}): Initial max allowed client bidi stream ID {max_initial_stream_id}, calculated count {initial_limit_count}.")

            if initial_limit_count < 1:
                 logger.warning(f"MSU Test ({server.name}): Initial limit count {initial_limit_count} is less than 1. This might be problematic. Proceeding cautiously.")
                 # Some servers might not send initial_max_streams_bidi, aioquic defaults to 0 (1 stream).
                 # If it's truly 0 from TP, it means no streams allowed initially, which is odd.

            open_stream_tasks = []
            logger.info(f"MSU Test ({server.name}): Opening {initial_limit_count} streams up to initial limit.")
            for i in range(initial_limit_count):
                task = asyncio.create_task(
                    http_client.get(f"https://{server.host}:{server.http3_port or server.port}{server.path}?stream={i}")
                )
                open_stream_tasks.append(task)
            all_tasks.extend(open_stream_tasks)

            # Wait for these initial streams to likely be established (optional, but can help stress the server)
            # For now, we proceed to try and open the extra stream.

            logger.info(f"MSU Test ({server.name}): Attempting to open one extra stream beyond initial limit.")
            extra_stream_succeeded_initially = False
            try:
                extra_task = asyncio.create_task(
                    http_client.get(f"https://{server.host}:{server.http3_port or server.port}{server.path}?extra")
                )
                all_tasks.append(extra_task)
                extra_response_events = await asyncio.wait_for(extra_task, timeout=5.0)
                if extra_response_events and isinstance(extra_response_events[0], HeadersReceived) and \
                   extra_response_events[0].status_code // 100 == 2:
                    extra_stream_succeeded_initially = True
                    logger.info(f"MSU Test ({server.name}): Extra stream request completed successfully *before* explicit MAX_STREAMS check. Server might be lenient or sent update quickly.")
                else:
                    logger.warning(f"MSU Test ({server.name}): Extra stream request got non-2xx or failed before MAX_STREAMS check.")

            except QuicConnectionError as e:
                if e.error_code == QuicErrorCode.STREAM_LIMIT_ERROR:
                    logger.info(f"MSU Test ({server.name}): Correctly hit STREAM_LIMIT_ERROR when trying to exceed initial limit.")
                else:
                    logger.warning(f"MSU Test ({server.name}): Unexpected QuicConnectionError {e.error_code} when trying to exceed initial limit: {e.reason_phrase}")
            except asyncio.TimeoutError:
                logger.info(f"MSU Test ({server.name}): Timeout waiting for extra stream request. Server might not have sent MAX_STREAMS update yet, or request is stalled.")
                # Task will be cancelled in finally block if not already done.
            except Exception as e:
                logger.error(f"MSU Test ({server.name}): Unexpected exception for extra stream request: {e}")


            logger.info(f"MSU Test ({server.name}): Waiting for potential MAX_STREAMS update from server.")
            await asyncio.sleep(1.0) # Give server time to send MAX_STREAMS

            new_limit_count_from_frame = initial_limit_count
            max_streams_frame_found_in_log = False
            
            # Refresh log data
            log_data = test_config.quic_logger.to_dict() 
            for trace in log_data.get("traces", []):
                for event in trace.get("events", []):
                    if event.get("name") == "transport:packet_received":
                        packet_data = event.get("data", {})
                        for frame in packet_data.get("frames", []):
                            # MAX_STREAMS frame can be for bidi or uni. We care about bidi.
                            if frame.get("frame_type") == "max_streams" and frame.get("stream_type") == "bidirectional":
                                updated_max_streams_val = frame.get("maximum_streams") # This is a stream COUNT
                                if updated_max_streams_val > new_limit_count_from_frame:
                                    new_limit_count_from_frame = updated_max_streams_val
                                    max_streams_frame_found_in_log = True
                                    logger.info(f"MSU Test ({server.name}): MAX_STREAMS (bidi) frame received, new limit count: {new_limit_count_from_frame}")
                                    # Keep checking as server might send multiple updates; we want the latest effective one.
                            # Legacy frame type name, some loggers might use it
                            elif frame.get("frame_type") == "max_streams_bidi": 
                                updated_max_streams_val = frame.get("maximum_streams")
                                if updated_max_streams_val > new_limit_count_from_frame:
                                    new_limit_count_from_frame = updated_max_streams_val
                                    max_streams_frame_found_in_log = True
                                    logger.info(f"MSU Test ({server.name}): MAX_STREAMS_BIDI (legacy) frame received, new limit count: {new_limit_count_from_frame}")


            additional_streams_opened_successfully = 0
            if max_streams_frame_found_in_log and new_limit_count_from_frame > initial_limit_count:
                logger.info(f"MSU Test ({server.name}): Server sent MAX_STREAMS update. New limit: {new_limit_count_from_frame}. Initial: {initial_limit_count}.")
                
                streams_to_try_after_update = min(2, new_limit_count_from_frame - initial_limit_count)
                logger.info(f"MSU Test ({server.name}): Attempting to open {streams_to_try_after_update} additional streams.")

                for i in range(streams_to_try_after_update):
                    if http_client._quic._is_closed:
                        logger.warning(f"MSU Test ({server.name}): Connection is closed. Cannot open more streams after update.")
                        break
                    try:
                        task = asyncio.create_task(
                            http_client.get(f"https://{server.host}:{server.http3_port or server.port}{server.path}?updated_stream={i}")
                        )
                        additional_stream_tasks.append(task) # For cleanup
                        all_tasks.append(task)

                        response_events = await asyncio.wait_for(task, timeout=3.0)
                        if response_events and isinstance(response_events[0], HeadersReceived) and \
                           response_events[0].status_code // 100 == 2:
                            additional_streams_opened_successfully += 1
                            logger.info(f"MSU Test ({server.name}): Successfully opened additional stream {i} after MAX_STREAMS update.")
                        else:
                            status = response_events[0].status_code if response_events and isinstance(response_events[0], HeadersReceived) else "N/A"
                            logger.warning(f"MSU Test ({server.name}): Updated stream request {i} got non-2xx ({status}) or failed.")
                            # Don't break here, server might allow next one.
                    except asyncio.TimeoutError:
                         logger.warning(f"MSU Test ({server.name}): Timeout opening additional stream {i} after MAX_STREAMS update.")
                    except QuicConnectionError as e: # Could be STREAM_LIMIT_ERROR if server's update wasn't enough or not processed by us
                        logger.error(f"MSU Test ({server.name}): QuicConnectionError opening additional stream {i} after MAX_STREAMS update: {e.error_code} - {e.reason_phrase}")
                        break # If one fails with connection error, likely others will too.
                    except Exception as e:
                        logger.error(f"MSU Test ({server.name}): Unexpected error opening additional stream {i} after MAX_STREAMS update: {e}")
                        break
            
            if max_streams_frame_found_in_log and new_limit_count_from_frame > initial_limit_count and additional_streams_opened_successfully > 0:
                logger.info(f"MSU Test ({server.name}): Test successful. MSU flag set.")
                server.result |= Result.MSU
            else:
                logger.warning(f"MSU Test ({server.name}): Test conditions not fully met. MAX_STREAMS found: {max_streams_frame_found_in_log}, New limit > Initial: {new_limit_count_from_frame > initial_limit_count}, Additional streams opened: {additional_streams_opened_successfully}.")

    except QuicConnectionError as e:
        print(f"MSU Test ({server.name}): QuicConnectionError occurred during main test execution: {e}. Error Code: {e.error_code}, Reason: {e.reason_phrase}")
    except Exception as e:
        print(f"MSU Test ({server.name}): An unexpected error occurred during main test execution: {e}")
    finally:
        if test_secrets_log_file_obj: test_secrets_log_file_obj.close()
        
        # Cleanup all tasks
        logger.info(f"MSU Test ({server.name}): Cleaning up tasks.")
        for task in all_tasks: # all_tasks includes open_stream_tasks, extra_task (if created), and additional_stream_tasks
            if task and not task.done():
                task.cancel()
            try:
                if task: await task
            except asyncio.CancelledError:
                pass # Expected for cancelled tasks
            except Exception as e_task:
                # Log exceptions from tasks if they weren't handled or were unexpected
                logger.info(f"MSU Test ({server.name}): Exception from awaiting task during cleanup: {e_task}")
        
        status_msg = "succeeded (flag set)" if (server.result & Result.MSU) else "failed or conditions not met"
        print(f"MSU Test ({server.name}): Test run {status_msg}.")


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
