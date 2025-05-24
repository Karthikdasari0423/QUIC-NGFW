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
from aioquic.quic.frames import MaxStreamsFrame, StreamType, RetireConnectionIdFrame, PathChallengeFrame, PathResponseFrame
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
    POST_SUCCESS = 0x080000
    ZERORTT_REJECTED_OK = 0x100000
    APP_CLOSE_OK = 0x200000
    H3_CANCEL_OK = 0x400000
    FLOW_CTRL_OK = 0x800000
    MAX_STREAMS_UPDATE_OK = 0x1000000
    STREAMS_BLOCKED_RECEIVED_OK = 0x2000000
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


async def test_http_3_post(server: Server, configuration: QuicConfiguration):
    if server.path is None:
        return

    configuration.alpn_protocols = H3_ALPN
    port = server.http3_port or server.port
    
    logger = configuration.quic_logger.logger if configuration.quic_logger else logging.getLogger("aioquic")

    async with connect(
        server.host,
        port,
        configuration=configuration,
        create_protocol=HttpClient,
    ) as protocol:
        http_protocol = cast(HttpClient, protocol)
        logger.info(f"H3 POST test: Attempting POST to https://{server.host}:{port}{server.path}")

        payload = b'{"key": "value"}'
        headers = [
            (b":method", b"POST"),
            (b":scheme", b"https"),
            (b":authority", server.host.encode()),
            (b":path", server.path.encode()),
            (b"content-type", b"application/json"),
            (b"content-length", b"%d" % len(payload)),
        ]

        stream_id = http_protocol.get_next_available_stream_id()
        logger.debug(f"H3 POST test: Sending headers on stream {stream_id}: {headers}")
        http_protocol.send_headers(stream_id=stream_id, headers=headers)
        
        logger.debug(f"H3 POST test: Sending data on stream {stream_id}: {payload!r}")
        http_protocol.send_data(stream_id=stream_id, data=payload, end_stream=True)

        logger.info(f"H3 POST test: Waiting for response on stream {stream_id}")
        response_events = await http_protocol.wait_for_response(stream_id)

        if response_events and isinstance(response_events[0], HeadersReceived):
            status_code = -1
            for k, v in response_events[0].headers:
                if k == b":status":
                    status_code = int(v.decode())
                    break
            logger.info(f"H3 POST test: Received status code {status_code} on stream {stream_id}")
            if status_code in [200, 201, 204]: # Common success codes for POST
                server.result |= Result.POST_SUCCESS
                logger.info(f"H3 POST test: SUCCESS - Status {status_code} is valid.")
            else:
                logger.warning(f"H3 POST test: FAILED - Status {status_code} is not a typical success code for POST.")
        else:
            logger.warning(f"H3 POST test: FAILED - No valid HeadersReceived event found for stream {stream_id}. Events: {response_events}")
        
        # Ensure any associated tasks for this stream are cleaned up if necessary by HttpClient
        # (usually handled internally by HttpClient or when connection closes)


async def test_0rtt_rejection(server: Server, configuration: QuicConfiguration):
    logger = configuration.quic_logger.logger if configuration.quic_logger else logging.getLogger("aioquic")
    logger.info("Starting 0-RTT rejection test.")

    configuration.early_data_0rtt = b"attempting 0-RTT"
    # A dummy ticket is often needed to trigger 0-RTT attempt logic,
    # even if it's not a real, valid ticket that would be accepted by the server.
    configuration.session_ticket = b"dummy_ticket_for_0rtt_attempt"
    
    logger.info(f"Attempting 0-RTT connection to {server.host}:{server.port}.")

    try:
        async with connect(
            server.host, server.port, configuration=configuration
        ) as protocol: # Default QuicConnectionProtocol is used
            logger.info("0-RTT test: Connection initiated. Performing initial ping.")
            await protocol.ping()
            logger.info("0-RTT test: Initial ping successful.")

            if not protocol._quic.tls.early_data_accepted:
                logger.info("0-RTT test: Early data was REJECTED by the server (as expected for this test scenario).")
                logger.info("0-RTT test: Performing second ping to confirm connection usability.")
                await protocol.ping()
                logger.info("0-RTT test: Second ping successful. Connection is usable after 0-RTT rejection.")
                server.result |= Result.ZERORTT_REJECTED_OK
            else:
                logger.info("0-RTT test: Early data was ACCEPTED by the server.")
                # This is not the target outcome for ZERORTT_REJECTED_OK, but the connection is up.
                # Another ping to ensure stability.
                await protocol.ping()
                logger.info("0-RTT test: Ping after 0-RTT acceptance successful.")

    except Exception as e:
        logger.error(f"0-RTT rejection test failed with exception: {e}")
    finally:
        logger.info("0-RTT rejection test finished.")


async def test_close_with_application_error(
    server: Server, configuration: QuicConfiguration
):
    logger = configuration.quic_logger.logger if configuration.quic_logger else logging.getLogger("aioquic")
    logger.info("Starting application-initiated close test.")

    app_error_code = 0x1234
    reason_phrase = "Application test close"

    try:
        async with connect(
            server.host, server.port, configuration=configuration
        ) as protocol: # Default QuicConnectionProtocol
            logger.info("Application close test: Connection initiated. Performing initial ping.")
            await protocol.ping()
            logger.info("Application close test: Initial ping successful.")

            logger.info(
                f"Application close test: Closing connection with error_code=0x{app_error_code:x} "
                f"and reason='{reason_phrase}'."
            )
            protocol.close(error_code=app_error_code, reason_phrase=reason_phrase)
            
            logger.info("Application close test: Waiting for connection to close.")
            await protocol.wait_closed()
            logger.info("Application close test: Connection closed as expected.")
            server.result |= Result.APP_CLOSE_OK

    except Exception as e:
        logger.error(f"Application-initiated close test failed with exception: {e}")
    finally:
        logger.info("Application-initiated close test finished.")


async def test_http_3_request_cancellation(
    server: Server, configuration: QuicConfiguration
):
    logger = configuration.quic_logger.logger if configuration.quic_logger else logging.getLogger("aioquic")
    logger.info("Starting H3 request cancellation test.")

    if server.path is None:
        logger.info("H3 request cancellation test: server.path is None, skipping.")
        return

    configuration.alpn_protocols = H3_ALPN
    port = server.http3_port or server.port
    
    stream_id = None # Initialize stream_id to ensure it's always defined for logging

    try:
        async with connect(
            server.host,
            port,
            configuration=configuration,
            create_protocol=HttpClient,
        ) as protocol:
            http_protocol = cast(HttpClient, protocol)
            
            logger.info(f"H3 cancel test: Initiating GET request to https://{server.host}:{port}{server.path}")
            # For HttpClient's manual stream handling, start_request is not an async method itself,
            # but it returns a stream_id that is then used with async event methods.
            # The actual sending of headers happens via _quic.send_stream_data internally when using higher-level methods.
            # To align with the subtask's use of start_request and wait_for_event:
            # We will use the higher-level `get` method which returns an event receiver,
            # then iterate to find HeadersReceived to get the stream_id.

            http_event_receiver = http_protocol.get(
                url=f"https://{server.host}:{port}{server.path}",
                headers=[(b":authority", server.host.encode())] # Ensure authority is set
            )
            stream_id = http_event_receiver.stream_id # HttpClient sets this attribute on the receiver
            logger.info(f"H3 cancel test: GET request initiated on stream {stream_id}.")

            headers_event = None
            try:
                # Wait for headers with a timeout to prevent indefinite blocking
                headers_event = await asyncio.wait_for(
                    http_event_receiver.get_next_event_of_type(HeadersReceived), 
                    timeout=5.0 
                )
            except asyncio.TimeoutError:
                logger.warning(f"H3 cancel test: Timeout waiting for HeadersReceived on stream {stream_id}.")
            except Exception as e: # Catch other potential errors from get_next_event_of_type
                logger.error(f"H3 cancel test: Error waiting for HeadersReceived on stream {stream_id}: {e}")


            if headers_event is not None:
                logger.info(f"H3 cancel test: Headers received on stream {stream_id}: {headers_event.headers}")
                
                logger.info(f"H3 cancel test: Resetting stream {stream_id} with error H3_REQUEST_CANCELLED.")
                # Using protocol._quic.reset_stream as specified in the refined plan
                http_protocol._quic.reset_stream(stream_id, ErrorCode.H3_REQUEST_CANCELLED)
                
                logger.info(f"H3 cancel test: Stream {stream_id} reset sent. Pinging to check connection stability.")
                await http_protocol.ping() # Use http_protocol.ping() for consistency with HttpClient usage
                logger.info(f"H3 cancel test: Ping successful after resetting stream {stream_id}.")
                server.result |= Result.H3_CANCEL_OK
            else:
                logger.warning(
                    f"H3 cancel test: Headers were not received for stream {stream_id} (or timed out). "
                    "Cannot proceed with cancellation part of the test for this stream."
                )

    except Exception as e:
        logger.error(f"H3 request cancellation test failed for stream {stream_id if stream_id is not None else 'unknown'} with exception: {e}")
    finally:
        logger.info("H3 request cancellation test finished.")


async def test_stream_flow_control(server: Server, configuration: QuicConfiguration):
    logger = configuration.quic_logger.logger if configuration.quic_logger else logging.getLogger("aioquic")
    logger.info("Starting stream flow control test.")

    if server.path is None:
        logger.info("Stream flow control test: server.path is None, skipping.")
        return

    configuration.alpn_protocols = H3_ALPN
    port = server.http3_port or server.port
    
    try:
        async with connect(
            server.host,
            port,
            configuration=configuration,
            create_protocol=HttpClient,
        ) as protocol:
            http_protocol = cast(HttpClient, protocol)
            # Use the QUIC connection's logger directly for QUIC specific logs
            quic_logger = http_protocol._quic._logger 

            quic_logger.info("Stream flow control test: Waiting for handshake confirmation.")
            await http_protocol._quic.wait_handshake_confirmed()
            quic_logger.info("Stream flow control test: Handshake confirmed.")

            data_to_send = b'D' * (1024 * 1024)  # 1MB
            
            stream_id = http_protocol.get_next_available_stream_id()
            quic_logger.info(f"Stream flow control test: Obtained stream ID {stream_id}.")

            post_path = server.path + "flowcontrol"
            headers = [
                (b":method", b"POST"),
                (b":scheme", b"https"),
                (b":authority", server.host.encode()),
                (b":path", post_path.encode()),
                (b"content-length", b"%d" % len(data_to_send)),
            ]
            
            quic_logger.info(f"Stream flow control test: Sending headers on stream {stream_id}: {headers}")
            http_protocol.send_headers(stream_id=stream_id, headers=headers)
            
            quic_logger.info(f"Stream flow control test: Sending {len(data_to_send)} bytes of data on stream {stream_id}.")
            http_protocol.send_data(stream_id=stream_id, data=data_to_send, end_stream=True)
            quic_logger.info(f"Stream flow control test: All data passed to send_data for stream {stream_id}.")

            quic_logger.info(f"Stream flow control test: Performing initial ping on stream {stream_id}.")
            await http_protocol.ping()
            quic_logger.info(f"Stream flow control test: Initial ping successful on stream {stream_id}.")

            quic_logger.info("Stream flow control test: Waiting for 3 seconds for data to be sent and acknowledged.")
            await asyncio.sleep(3.0)

            quic_stream = http_protocol._quic._get_stream_by_id(stream_id)
            
            if quic_stream is not None:
                sender_state_ended = quic_stream.sender.stream_ended
                sender_buffer_empty = quic_stream.sender.is_buffer_empty()
                quic_logger.info(
                    f"Stream flow control test: Stream {stream_id} state - ended: {sender_state_ended}, buffer_empty: {sender_buffer_empty}, "
                    f"offset: {quic_stream.sender._offset}, max_offset: {quic_stream.sender._max_offset}"
                )
                if sender_state_ended and sender_buffer_empty:
                    server.result |= Result.FLOW_CTRL_OK
                    quic_logger.info("Stream flow control test: SUCCESS - Stream ended and send buffer is empty.")
                else:
                    quic_logger.warning(
                        f"Stream flow control test: FAILED - Stream state not as expected. Ended: {sender_state_ended}, Buffer Empty: {sender_buffer_empty}"
                    )
            else:
                quic_logger.warning(f"Stream flow control test: FAILED - QUIC stream {stream_id} not found.")

            quic_logger.info(f"Stream flow control test: Performing final ping on stream {stream_id}.")
            await http_protocol.ping()
            quic_logger.info(f"Stream flow control test: Final ping successful on stream {stream_id}.")
            
            # Attempt to wait for the response to clean up the HTTP/3 stream if server sends one
            try:
                logger.info(f"Stream flow control test: Attempting to receive response on stream {stream_id} to clean up.")
                await http_protocol.wait_for_response(stream_id)
                logger.info(f"Stream flow control test: Received response or stream ended for {stream_id}.")
            except Exception as e_resp:
                logger.warning(f"Stream flow control test: Exception while waiting for response on stream {stream_id}: {e_resp}")


    except Exception as e:
        logger.error(f"Stream flow control test failed with exception: {e}")
    finally:
        logger.info("Stream flow control test finished.")


async def test_max_streams_frame_handling(
    server: Server, configuration: QuicConfiguration
):
    logger = configuration.quic_logger.logger if configuration.quic_logger else logging.getLogger("aioquic")
    logger.info("Starting MAX_STREAMS frame handling test.")

    if server.path is None:
        logger.info("MAX_STREAMS test: server.path is None, skipping.")
        return

    configuration.alpn_protocols = H3_ALPN
    port = server.http3_port or server.port
    
    stream_tasks = [] # Define here to be accessible in finally block

    try:
        async with connect(
            server.host,
            port,
            configuration=configuration,
            create_protocol=HttpClient,
        ) as protocol:
            http_protocol = cast(HttpClient, protocol)
            # Use the QUIC connection's logger for QUIC specific logs
            quic_logger = http_protocol._quic._logger

            quic_logger.info("MAX_STREAMS test: Waiting for handshake confirmation.")
            await http_protocol._quic.wait_handshake_confirmed()
            quic_logger.info("MAX_STREAMS test: Handshake confirmed.")

            initial_limit = http_protocol._quic.peer_params.initial_max_streams_bidi
            quic_logger.info(f"MAX_STREAMS test: Initial peer max_streams_bidi from transport parameters: {initial_limit}")

            if initial_limit == 0:
                # This is unusual; servers typically allow at least 1 or 100.
                # If 0, client cannot open any bidi stream until a MAX_STREAMS is received.
                quic_logger.warning(
                    "MAX_STREAMS test: Peer's initial_max_streams_bidi is 0. "
                    "Relying on server to send MAX_STREAMS early. Setting streams_to_open_initially to 1."
                )
                streams_to_open_initially = 1
            else:
                streams_to_open_initially = int(initial_limit)
            
            quic_logger.info(f"MAX_STREAMS test: Will attempt to initiate {streams_to_open_initially} stream(s).")

            for i in range(streams_to_open_initially):
                task = asyncio.create_task(
                    http_protocol.get(
                        f"https://{server.host}:{port}{server.path}max_streams_initial_{i}",
                        headers=[(b":authority", server.host.encode())]
                    )
                )
                stream_tasks.append(task)
            
            quic_logger.info(f"MAX_STREAMS test: {streams_to_open_initially} GET requests initiated. Waiting 0.5s.")
            await asyncio.sleep(0.5) # Allow time for stream initiations to be processed

            limit_before_wait = http_protocol._quic.streams._remote_max_streams_bidi
            quic_logger.info(f"MAX_STREAMS test: Current remote_max_streams_bidi (after initial opens): {limit_before_wait}")

            quic_logger.info("MAX_STREAMS test: Waiting 2.0s for server to potentially send MAX_STREAMS frame.")
            await asyncio.sleep(2.0)

            new_limit_after_wait = http_protocol._quic.streams._remote_max_streams_bidi
            quic_logger.info(
                f"MAX_STREAMS test: remote_max_streams_bidi after wait: {new_limit_after_wait} (was {limit_before_wait})."
            )

            if new_limit_after_wait > limit_before_wait:
                quic_logger.info(
                    f"MAX_STREAMS test: Limit increased. Attempting to open an additional stream."
                )
                additional_stream_url = f"https://{server.host}:{port}{server.path}max_streams_additional"
                additional_stream_task = asyncio.create_task(
                     http_protocol.get(additional_stream_url, headers=[(b":authority", server.host.encode())])
                )
                stream_tasks.append(additional_stream_task) # Add for cleanup

                try:
                    # Await the task directly, HttpClient's get() returns a list of events
                    additional_stream_events = await asyncio.wait_for(additional_stream_task, timeout=5.0)
                    if additional_stream_events and isinstance(additional_stream_events[0], HeadersReceived):
                        quic_logger.info(
                            "MAX_STREAMS test: SUCCESS - Successfully opened an additional stream and received headers."
                        )
                        server.result |= Result.MAX_STREAMS_UPDATE_OK
                    else:
                        quic_logger.warning(
                            "MAX_STREAMS test: FAILED - Additional stream opened, but no HeadersReceived event. "
                            f"Events: {additional_stream_events}"
                        )
                except asyncio.TimeoutError:
                    quic_logger.warning("MAX_STREAMS test: FAILED - Timeout waiting for additional stream response.")
                except Exception as e_add:
                    quic_logger.error(f"MAX_STREAMS test: FAILED - Error opening additional stream: {e_add}")
            else:
                quic_logger.warning(
                    "MAX_STREAMS test: Stream limit did not increase after waiting. "
                    "Server might not have sent MAX_STREAMS or it wasn't processed."
                )
            
            await http_protocol.ping() # Final health check

    except Exception as e:
        logger.error(f"MAX_STREAMS frame handling test failed with exception: {e}")
    finally:
        logger.info(f"MAX_STREAMS test: Cleaning up {len(stream_tasks)} stream tasks.")
        for task in stream_tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*stream_tasks, return_exceptions=True) # Wait for cancellations to complete
        logger.info("MAX_STREAMS frame handling test finished.")


async def test_streams_blocked_frame(
    server: Server, configuration: QuicConfiguration
):
    logger = configuration.quic_logger.logger if configuration.quic_logger else logging.getLogger("aioquic")
    logger.info("Starting STREAMS_BLOCKED frame test.")

    if server.path is None:
        logger.info("STREAMS_BLOCKED test: server.path is None, skipping.")
        return

    # Ensure we have an in-memory logger to inspect events
    quic_logger_for_this_test = QuicLogger()
    original_quic_logger = configuration.quic_logger
    configuration.quic_logger = quic_logger_for_this_test # Override for this test

    configuration.alpn_protocols = H3_ALPN
    port = server.http3_port or server.port
    
    stream_tasks = []

    try:
        async with connect(
            server.host,
            port,
            configuration=configuration,
            create_protocol=HttpClient,
        ) as protocol:
            http_protocol = cast(HttpClient, protocol)
            # Use the QUIC connection's logger for most operational logs
            quic_operational_logger = http_protocol._quic._logger

            quic_operational_logger.info("STREAMS_BLOCKED test: Waiting for handshake confirmation.")
            await http_protocol._quic.wait_handshake_confirmed()
            quic_operational_logger.info("STREAMS_BLOCKED test: Handshake confirmed.")

            current_remote_limit = http_protocol._quic.streams._remote_max_streams_bidi
            quic_operational_logger.info(f"STREAMS_BLOCKED test: Current remote max bidirectional streams limit: {current_remote_limit}")

            if current_remote_limit < 2: # If limit is 0 or 1
                streams_to_attempt = 3 
                quic_operational_logger.info(f"STREAMS_BLOCKED test: Remote limit is {current_remote_limit}, attempting to open {streams_to_attempt} streams.")
            else:
                streams_to_attempt = int(current_remote_limit + 2)
                quic_operational_logger.info(f"STREAMS_BLOCKED test: Attempting to open {streams_to_attempt} streams (limit {current_remote_limit} + 2).")

            for i in range(streams_to_attempt):
                task = asyncio.create_task(
                    http_protocol.get(
                        f"https://{server.host}:{port}{server.path}streams_blocked_attempt_{i}",
                         headers=[(b":authority", server.host.encode())]
                    )
                )
                stream_tasks.append(task)
            
            quic_operational_logger.info(f"STREAMS_BLOCKED test: {streams_to_attempt} GET requests initiated. Waiting 1.5s for server response.")
            await asyncio.sleep(1.5)

            streams_blocked_frame_detected = False
            try:
                log_dict = quic_logger_for_this_test.to_dict()
                if log_dict and "traces" in log_dict and log_dict["traces"]:
                    for event in log_dict["traces"][0].get("events", []):
                        if event.get("name") == "transport:frame_received":
                            for frame_data in event.get("data", {}).get("frames", []):
                                if frame_data.get("frame_type") == "streams_blocked" and frame_data.get("stream_type") == "bidirectional":
                                    streams_blocked_frame_detected = True
                                    quic_operational_logger.info(
                                        f"STREAMS_BLOCKED (bidirectional) frame received from server in QLOG: {frame_data}"
                                    )
                                    break
                            if streams_blocked_frame_detected:
                                break
            except Exception as e_qlog:
                quic_operational_logger.error(f"STREAMS_BLOCKED test: Error processing QLOG for STREAMS_BLOCKED detection: {e_qlog}")

            if streams_blocked_frame_detected:
                server.result |= Result.STREAMS_BLOCKED_RECEIVED_OK
                quic_operational_logger.info("STREAMS_BLOCKED test: SUCCESS - STREAMS_BLOCKED (bidirectional) frame detected.")
            else:
                quic_operational_logger.warning(
                    "STREAMS_BLOCKED test: FAILED - No STREAMS_BLOCKED (bidirectional) frame detected from server in QLOG. "
                    "This could be an issue if the server is expected to send one under these conditions."
                )

            # Send a MAX_STREAMS frame from client to server for server-initiated bidi streams
            try:
                current_local_max_bidi = http_protocol._quic.streams._local_max_streams_bidi
                new_limit_for_server = current_local_max_bidi + 5
                quic_operational_logger.info(
                    f"STREAMS_BLOCKED test: Sending client's MAX_STREAMS (bidirectional) to server, "
                    f"increasing server's allowed bidi streams from {current_local_max_bidi} to {new_limit_for_server}."
                )
                http_protocol._quic._send_frame(
                    MaxStreamsFrame(stream_type=StreamType.BIDIRECTIONAL, maximum_streams=new_limit_for_server)
                )
                await http_protocol.ping()
                quic_operational_logger.info("STREAMS_BLOCKED test: Client's MAX_STREAMS frame sent and pinged successfully.")
            except Exception as e_max_streams:
                quic_operational_logger.error(f"STREAMS_BLOCKED test: Error sending client's MAX_STREAMS frame: {e_max_streams}")

    except Exception as e:
        logger.error(f"STREAMS_BLOCKED frame test failed with exception: {e}")
    finally:
        logger.info(f"STREAMS_BLOCKED test: Cleaning up {len(stream_tasks)} stream tasks.")
        for task in stream_tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*stream_tasks, return_exceptions=True)
        configuration.quic_logger = original_quic_logger # Restore original logger
        logger.info("STREAMS_BLOCKED frame test finished.")


async def test_cid_retirement_interaction(
    server: Server, configuration: QuicConfiguration
):
    port = server.http3_port or server.port
    if server.path is None: # Path needed for HttpClient GET
        return

    quic_logger = QuicLogger()
    configuration.quic_logger = quic_logger
    configuration.alpn_protocols = H3_ALPN # Using H3 for HttpClient convenience

    async with connect(
        server.host,
        port,
        configuration=configuration,
        create_protocol=HttpClient,
    ) as protocol:
        protocol = cast(HttpClient, protocol)
        logger = protocol._quic._logger

        # Identify the server's initial CID (sequence number 0)
        cid_to_retire_seq = 0
        server_initial_cid_obj = None
        for seq, cid_obj in protocol._quic.peer_cids.items():
            if seq == cid_to_retire_seq:
                server_initial_cid_obj = cid_obj
                break
        
        if server_initial_cid_obj is None:
            logger.warning(
                f"Server's initial CID (sequence {cid_to_retire_seq}) not found in peer_cids. "
                "Cannot proceed with retirement test."
            )
            await protocol.ping() # Still check connection health
            return

        logger.info(
            f"Target for retirement: Server CID {server_initial_cid_obj.cid.hex()} (seq: {cid_to_retire_seq}). "
            f"Currently used dest CID by client: {protocol._quic._remote_cid.hex()}"
        )

        # Store known peer CID sequence numbers before retirement
        # Filter out any already retired CIDs if any (should not be the case for seq 0 initially)
        known_peer_cid_seqs_before_retire = {
            c.sequence_number for c in protocol._quic.peer_cids.values() if c.retired_time is None
        }
        logger.info(f"Active peer CID sequences before retirement: {known_peer_cid_seqs_before_retire}")
        
        time_retire_sent_ns = time.time_ns() # Use nanoseconds for better precision
        protocol._quic._send_frame(RetireConnectionIdFrame(sequence_number=cid_to_retire_seq))
        logger.info(f"RETIRE_CONNECTION_ID for seq {cid_to_retire_seq} sent at time_ns {time_retire_sent_ns}.")

        # Wait for the server to process the retirement and potentially issue a new CID
        await asyncio.sleep(2.0)

        new_cid_frame_found_in_qlog = False
        newly_learned_cid_seq = -1

        try:
            log_dict = quic_logger.to_dict()
            if log_dict and "traces" in log_dict and log_dict["traces"]:
                # QLOG time is typically in microseconds relative to trace start, or milliseconds absolute
                # Convert time_retire_sent_ns to the QLOG's relative time if necessary,
                # or compare absolute times if QLOG uses them. AIOQUIC QLogger uses relative time in ms.
                # For simplicity, we'll just check all NEW_CONNECTION_ID frames after sending.
                for event in log_dict["traces"][0].get("events", []):
                    # Assuming event time is relative to trace start in ms for aioquic's QuicLogger
                    # This time comparison is tricky with QLOG. A simpler check is just for any new CID.
                    if event.get("name") == "transport:frame_received": # Check frames _received_ by client
                        for frame_data in event.get("data", {}).get("frames", []):
                            if frame_data.get("frame_type") == "new_connection_id":
                                new_seq = frame_data.get("sequence_number")
                                retire_prior_to = frame_data.get("retire_prior_to", -1) # Default if not present
                                
                                logger.info(
                                    f"QLOG: Detected NEW_CONNECTION_ID frame from server: seq={new_seq}, "
                                    f"retire_prior_to={retire_prior_to}. CID: {frame_data.get('connection_id')}"
                                )
                                # Check if this NEW_CONNECTION_ID is genuinely new and not one we knew before sending RETIRE
                                if new_seq is not None and new_seq not in known_peer_cid_seqs_before_retire:
                                    new_cid_frame_found_in_qlog = True
                                    newly_learned_cid_seq = max(newly_learned_cid_seq, new_seq)
                                    # No break here, log all new CIDs if multiple are sent
        except Exception as e:
            logger.error(f"Error processing QLOG for NEW_CONNECTION_ID: {e}")

        # Check internal state of the retired CID
        cid_obj_after_retire_attempt = protocol._quic.peer_cids.get(cid_to_retire_seq)
        is_cid_marked_retired = False
        if cid_obj_after_retire_attempt and cid_obj_after_retire_attempt.retired_time is not None:
            logger.info(f"Internal check: CID seq {cid_to_retire_seq} is marked as retired.")
            is_cid_marked_retired = True
        elif not cid_obj_after_retire_attempt : # If it was removed
             logger.info(f"Internal check: CID seq {cid_to_retire_seq} was removed from peer_cids list.")
             is_cid_marked_retired = True # Also acceptable
        else:
            logger.warning(f"Internal check: CID seq {cid_to_retire_seq} still present and not marked retired.")
            if cid_obj_after_retire_attempt:
                 logger.warning(f"CID {cid_to_retire_seq} details: {cid_obj_after_retire_attempt}")


        if new_cid_frame_found_in_qlog and is_cid_marked_retired:
            logger.info(
                f"Success: Server sent a new CID (highest new seq: {newly_learned_cid_seq}) "
                f"and client correctly processed retirement of CID seq {cid_to_retire_seq}."
            )
            server.result |= Result.CID_RETIREMENT_OK
        else:
            logger.warning(
                f"CID retirement test conditions not fully met. "
                f"New CID in QLOG: {new_cid_frame_found_in_qlog} (new seq: {newly_learned_cid_seq}). "
                f"Old CID (seq {cid_to_retire_seq}) retired internally: {is_cid_marked_retired}."
            )
            
        # Final connection health check
        await protocol.ping()
        logger.info("CID retirement interaction test finished. Final ping check.")


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
