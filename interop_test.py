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
from aioquic.h3.connection import H3_ALPN, H3Connection, ErrorCode
from aioquic.h3.events import DataReceived, HeadersReceived, PushPromiseReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.logger import QuicFileLogger, QuicLogger
from aioquic.quic.connection import QuicConnectionError
from aioquic.quic.packet import QuicErrorCode, PacketType
from aioquic.quic.frames import NewConnectionIdFrame, RetireConnectionIdFrame, PathChallengeFrame
import os


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


async def test_final_size_error(server: Server, configuration: QuicConfiguration):
    """
    Tests FINAL_SIZE_ERROR as per RFC9000 Section 4.5 and Section 19.9.

    Scenario:
    1. Client establishes a connection and creates a bidirectional stream.
    2. Client sends a STREAM frame with data and the FIN bit set.
    3. Client then sends another STREAM frame on the same stream with offset 0,
       different data, and the FIN bit set, implying a different final size.

    Expected outcome:
    The server should detect this as a stream error and respond with a
    CONNECTION_CLOSE frame containing the FINAL_SIZE_ERROR code (0x06),
    or a STREAM_RESET frame with FINAL_SIZE_ERROR if it processes the
    first FIN before the conflict is detected (though connection close is more likely).
    """
    if not server.http3:
        # This test requires HTTP/3 for stream interactions via HttpClient
        print(f"[{server.name}] Skipping test_final_size_error as it's not an HTTP/3 server.")
        return

    configuration.alpn_protocols = H3_ALPN
    try:
        async with connect(
            server.host,
            server.http3_port or server.port,
            configuration=configuration,
            create_protocol=HttpClient,
        ) as client:
            client = cast(HttpClient, client)

            # Create a client-initiated bidirectional stream
            stream_id = client._quic.get_next_available_stream_id(is_unidirectional=False)

            # Send the first STREAM frame with FIN
            data1 = b"first frame data"
            # final_size_1 is implicitly len(data1) when offset is 0 and FIN is true.
            client._quic.send_stream_data(stream_id, data1, end_stream=True)
            
            # Try to ensure this frame is sent and processed by the server.
            # A ping might help flush buffers or await server ack.
            await client.ping() 
            await asyncio.sleep(0.2) # Small delay for server to process.

            # Send the second STREAM frame with a different final size (by sending different data from offset 0)
            # and FIN set. This should conflict with the first frame's final size.
            data2 = b"second frame, different data"
            
            # Sending data on an already FINished stream (from client's perspective)
            # with a different size from offset 0.
            client._quic.send_stream_data(stream_id, data2, end_stream=True, offset=0)
            
            # We expect the server to detect this and close the connection.
            # The client._quic.send_stream_data might not immediately raise an error,
            # as the error comes from the server. We need to wait for the server's response.
            # Await a PING or some other operation that would receive packets.
            for _ in range(5): # Try a few times to get the close signal
                 await asyncio.sleep(0.1)
                 if client._quic._close_event is not None:
                     break
                 await client.ping()


            # If the connection is still open, the server didn't detect the error.
            if client._quic._close_event is None:
                print(f"[{server.name}] test_final_size_error: Server did not close connection as expected.")
                # Attempt to force log check if available and no error raised yet
                if configuration.quic_logger:
                    log = configuration.quic_logger.to_dict()
                    for event in log["traces"][0]["events"]:
                        if event["name"] == "transport:connection_closed" and event["data"].get("error_code") == ErrorCode.FINAL_SIZE_ERROR:
                            print(f"[{server.name}] test_final_size_error: Verified FINAL_SIZE_ERROR (0x06) in logs, but no exception was raised by client.")
                            server.result |= Result.M 
                            return
                return # Test fails if no error detected

            # This part might not be reached if QuicConnectionError is raised by operations above.
            # However, if client.ping() or sleep finishes and _close_event is set:
            closed_event_data = client._quic._close_event
            if closed_event_data and closed_event_data.error_code == ErrorCode.FINAL_SIZE_ERROR:
                 print(f"[{server.name}] test_final_size_error: Server closed with FINAL_SIZE_ERROR (0x06) as per _close_event.")
                 server.result |= Result.M
            elif closed_event_data:
                 print(f"[{server.name}] test_final_size_error: Server closed with unexpected error code {closed_event_data.error_code} as per _close_event.")
            else:
                 print(f"[{server.name}] test_final_size_error: _close_event not set, but expected closure.")


    except QuicConnectionError as e:
        if e.quic_error_code == ErrorCode.FINAL_SIZE_ERROR:
            print(f"[{server.name}] test_final_size_error: Caught expected QuicConnectionError with FINAL_SIZE_ERROR (0x06).")
            server.result |= Result.M
        else:
            print(f"[{server.name}] test_final_size_error: Caught QuicConnectionError with unexpected code: {e.quic_error_code}, reason: {e.reason_phrase}.")
            # Log the full exception for more details
            import traceback
            traceback.print_exc()
            # Still check logs just in case the error code in exception is masked by a general one
            if configuration.quic_logger:
                log = configuration.quic_logger.to_dict()
                for event in log["traces"][0]["events"]:
                    if event["name"] == "transport:connection_closed" and event["data"].get("error_code") == ErrorCode.FINAL_SIZE_ERROR:
                        print(f"[{server.name}] test_final_size_error: Verified FINAL_SIZE_ERROR (0x06) in logs despite different exception code.")
                        server.result |= Result.M 
                        return

    except ConnectionAbortedError as e: # Often wraps underlying QUIC issues
        print(f"[{server.name}] test_final_size_error: ConnectionAbortedError encountered: {e}.")
        if configuration.quic_logger:
            log = configuration.quic_logger.to_dict()
            found_in_log = False
            for event in log["traces"][0]["events"]:
                if event["name"] == "transport:connection_closed":
                    print(f"Log - transport:connection_closed, data: {event['data']}")
                    if event["data"].get("error_code") == ErrorCode.FINAL_SIZE_ERROR:
                        print(f"[{server.name}] test_final_size_error: Verified FINAL_SIZE_ERROR (0x06) in logs after ConnectionAbortedError.")
                        server.result |= Result.M 
                        found_in_log = True
                        break
            if not found_in_log:
                 print(f"[{server.name}] test_final_size_error: FINAL_SIZE_ERROR not found in logs after ConnectionAbortedError.")
        else:
            print(f"[{server.name}] test_final_size_error: No QuicLogger, cannot confirm error code for ConnectionAbortedError.")

    except Exception as e:
        print(f"[{server.name}] test_final_size_error: An unexpected error occurred: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()


async def test_stream_limit_error_bidi(server: Server, configuration: QuicConfiguration):
    """
    Tests STREAM_LIMIT_ERROR for bidirectional streams as per RFC9000 Section 4.6 and Section 19.10.

    Scenario:
    1. Client establishes a connection.
    2. Client retrieves the server's advertised `initial_max_streams_bidi`.
    3. Client attempts to open `initial_max_streams_bidi + N` (e.g., N=5)
       bidirectional streams by sending initial data on them.

    Expected outcome:
    The server should detect that the client has exceeded the advertised stream limit
    and close the connection with the STREAM_LIMIT_ERROR code (0x04).
    The test skips if the advertised limit is 0 or impractically large.
    """
    if not server.http3:
        print(f"[{server.name}] Skipping test_stream_limit_error_bidi as it's not an HTTP/3 server.")
        return

    configuration.alpn_protocols = H3_ALPN
    try:
        async with connect(
            server.host,
            server.http3_port or server.port,
            configuration=configuration,
            create_protocol=HttpClient,
        ) as client:
            client = cast(HttpClient, client)
            
            # Wait for connection to be established to access peer_transport_parameters
            await client.wait_connected()
            
            if client._quic.peer_transport_parameters is None:
                print(f"[{server.name}] test_stream_limit_error_bidi: Peer transport parameters not available.")
                return

            max_streams_bidi = client._quic.peer_transport_parameters.initial_max_streams_bidi
            if max_streams_bidi is None:
                print(f"[{server.name}] test_stream_limit_error_bidi: initial_max_streams_bidi not advertised by server.")
                return
            
            # If max_streams_bidi is 0, it means client cannot open streams until server sends MAX_STREAMS.
            # This test aims to exceed the *initial* limit.
            if max_streams_bidi == 0:
                print(f"[{server.name}] test_stream_limit_error_bidi: Server advertised initial_max_streams_bidi = 0. Cannot exceed initial limit.")
                # This isn't a failure of the server to enforce a limit, but rather that the limit is 0 initially.
                # The test as designed expects to open N streams then fail on N+1.
                return

            # Limit the number of streams to open to avoid excessive test duration for servers with high limits
            # If a server advertises a limit like 100, opening 105 streams is reasonable.
            # If it advertises 2^60, we can't test that directly.
            # Let's cap the effective number of streams we'll try to open based on the advertised limit.
            # Most servers advertise a reasonable number (e.g., 100-256).
            # If the limit is extremely large, we can't realistically hit it.
            # A practical upper bound for testing:
            streams_to_attempt_cap = 200 
            
            streams_to_open_over_limit = 5 # How many streams to try to open beyond the advertised limit
            
            effective_streams_to_try = max_streams_bidi + streams_to_open_over_limit
            if max_streams_bidi > streams_to_attempt_cap:
                 print(f"[{server.name}] test_stream_limit_error_bidi: Server advertised initial_max_streams_bidi ({max_streams_bidi}) is very large. Capping test effort.")
                 # We won't hit the limit in this case, so the test can't verify the error.
                 # This is more of a test limitation than a server issue.
                 return


            print(f"[{server.name}] test_stream_limit_error_bidi: Server advertised initial_max_streams_bidi = {max_streams_bidi}. Attempting to open up to {effective_streams_to_try} streams.")

            for i in range(effective_streams_to_try):
                try:
                    stream_id = client._quic.get_next_available_stream_id(is_unidirectional=False)
                    client._quic._logger.info(f"Attempting to open stream {i+1}/{effective_streams_to_try}, stream_id: {stream_id}")
                    
                    # Send a small amount of data to ensure the stream is "used" from the server's perspective
                    client._quic.send_stream_data(stream_id, b"test data", end_stream=False)
                    
                    # Ensure data is flushed and server has a chance to react
                    await client.ping() 
                    await asyncio.sleep(0.05) # Short delay

                    if i >= max_streams_bidi:
                        # We've opened more streams than initially allowed.
                        # If the server hasn't closed the connection by now, it's an issue.
                        # Check if _close_event is set by server without raising QuicConnectionError
                        if client._quic._close_event is not None:
                            if client._quic._close_event.error_code == QuicErrorCode.STREAM_LIMIT_ERROR:
                                client._quic._logger.info(f"Server closed with STREAM_LIMIT_ERROR after opening {i+1} streams (limit was {max_streams_bidi}). Error found in _close_event.")
                                server.result |= Result.M
                                return
                            else:
                                client._quic._logger.warning(f"Server closed with unexpected error {client._quic._close_event.error_code} in _close_event after exceeding stream limit.")
                                return # Test failed

                except QuicConnectionError:
                    # This is where we expect to land if the client library itself prevents opening too many streams
                    # based on its count vs peer_transport_parameters. However, the server should be the one enforcing.
                    # This exception might occur if get_next_available_stream_id itself fails locally.
                    # We are more interested in the server sending STREAM_LIMIT_ERROR.
                    # The subsequent client.ping() or send_stream_data is more likely to raise if the server closes.
                    raise # Re-raise to be caught by the outer handler

            # If the loop completes without any error, it means we opened all 'effective_streams_to_try'
            # streams, including those over the limit, without the server stopping us.
            if client._quic._close_event is None:
                 client._quic._logger.warning(f"[{server.name}] test_stream_limit_error_bidi: Opened {effective_streams_to_try} streams (limit was {max_streams_bidi}) but server did not close the connection.")
            else:
                # Connection closed, but not via an exception during the loop. Check the reason.
                if client._quic._close_event.error_code == QuicErrorCode.STREAM_LIMIT_ERROR:
                    client._quic._logger.info(f"Server closed with STREAM_LIMIT_ERROR. Error found in _close_event after loop completion.")
                    server.result |= Result.M
                else:
                    client._quic._logger.warning(f"Server closed with unexpected error {client._quic._close_event.error_code} in _close_event after loop completion.")
            return # Test fails if not already returned with Result.M

    except QuicConnectionError as e:
        if e.quic_error_code == QuicErrorCode.STREAM_LIMIT_ERROR:
            client._quic._logger.info(f"[{server.name}] test_stream_limit_error_bidi: Caught expected QuicConnectionError with STREAM_LIMIT_ERROR (0x04).")
            server.result |= Result.M
        else:
            client._quic._logger.warning(f"[{server.name}] test_stream_limit_error_bidi: Caught QuicConnectionError with unexpected code: {e.quic_error_code} (expected 0x04), reason: {e.reason_phrase}.")
            # Log the full exception for more details
            import traceback
            traceback.print_exc()
            # Fallback: check logs for the actual error from server if exception is misleading
            if configuration.quic_logger:
                log = configuration.quic_logger.to_dict()
                for event in log["traces"][0]["events"]:
                    if event["name"] == "transport:connection_closed" and event["data"].get("error_code") == QuicErrorCode.STREAM_LIMIT_ERROR:
                        client._quic._logger.info(f"[{server.name}] test_stream_limit_error_bidi: Verified STREAM_LIMIT_ERROR (0x04) in logs despite different exception code.")
                        server.result |= Result.M 
                        return
    
    except ConnectionAbortedError as e: # Often wraps underlying QUIC issues
        client._quic._logger.warning(f"[{server.name}] test_stream_limit_error_bidi: ConnectionAbortedError encountered: {e}.")
        if configuration.quic_logger:
            log = configuration.quic_logger.to_dict()
            found_in_log = False
            for event in log["traces"][0]["events"]:
                if event["name"] == "transport:connection_closed":
                    client._quic._logger.info(f"Log - transport:connection_closed, data: {event['data']}")
                    if event["data"].get("error_code") == QuicErrorCode.STREAM_LIMIT_ERROR:
                        client._quic._logger.info(f"[{server.name}] test_stream_limit_error_bidi: Verified STREAM_LIMIT_ERROR (0x04) in logs after ConnectionAbortedError.")
                        server.result |= Result.M 
                        found_in_log = True
                        break
            if not found_in_log:
                 client._quic._logger.info(f"[{server.name}] test_stream_limit_error_bidi: STREAM_LIMIT_ERROR not found in logs after ConnectionAbortedError.")
        else:
            client._quic._logger.info(f"[{server.name}] test_stream_limit_error_bidi: No QuicLogger, cannot confirm error code for ConnectionAbortedError.")

    except Exception as e:
        client._quic._logger.error(f"[{server.name}] test_stream_limit_error_bidi: An unexpected error occurred: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()


async def test_invalid_retry_token(server: Server, initial_configuration: QuicConfiguration):
    """
    Tests server handling of an invalid Retry token, as per RFC9000 Section 8.1.2 and Section 19.7.

    Scenario:
    1. Client attempts an initial connection to the server. The goal is to solicit a Retry
       packet from the server, which includes a retry token.
    2. If a retry token is successfully obtained from the server's Retry packet,
       the client modifies this token (e.g., by appending a byte) to make it invalid.
    3. Client attempts a new connection using this modified (invalid) retry token in
       its Initial packet.

    Expected outcome:
    The server should detect that the presented token is invalid and abort the handshake.
    This typically results in the server sending a CONNECTION_CLOSE frame with the
    INVALID_TOKEN error code (0x0b) or simply dropping the connection without an explicit error.
    The test verifies if the INVALID_TOKEN error is received.
    """
    print(f"\n[{server.name}] Starting test_invalid_retry_token")
    original_retry_token = None
    
    # --- First connection attempt to get a Retry token ---
    print(f"[{server.name}] test_invalid_retry_token: Attempt 1 - Trying to obtain a retry token.")
    
    # Use a logger for the first attempt, separate if possible.
    logger_s1 = QuicLogger()
    # path_s1 = None
    # if initial_configuration.quic_logger and hasattr(initial_configuration.quic_logger, 'path') and initial_configuration.quic_logger.path:
    #     try:
    #         path_s1 = initial_configuration.quic_logger.path + "_retry_attempt1"
    #         logger_s1 = QuicFileLogger(path_s1)
    #     except Exception: # Fallback if path is invalid or QuicFileLogger fails
    #         logger_s1 = QuicLogger()

    config_step1 = QuicConfiguration(
        alpn_protocols=initial_configuration.alpn_protocols,
        is_client=True,
        quic_logger=logger_s1,
        secrets_log_file=initial_configuration.secrets_log_file,
        verify_mode=initial_configuration.verify_mode,
        supported_versions=initial_configuration.supported_versions[:] 
        # token field is deliberately not set
    )

    client_step1 = None
    try:
        # We don't use `async with` here as we need to inspect the client 
        # even if connect fails, and ensure it's closed in `finally`.
        # `wait_for_retry=False` (default) is crucial.
        # The timeout needs to be long enough for a retry packet exchange, but not too long.
        client_step1 = await asyncio.wait_for(
            connect(
                server.host,
                server.port, 
                configuration=config_step1,
                create_protocol=HttpClient,
                wait_for_retry=False 
            ),
            timeout=5.0 # seconds
        )
        
        # If connect() returns, it means the connection succeeded or some complex scenario.
        # Check if a retry token was processed and stored.
        if client_step1 and client_step1._quic._retry_token:
            original_retry_token = client_step1._quic._retry_token
            print(f"[{server.name}] test_invalid_retry_token: Attempt 1 - Connection completed, token found: {original_retry_token.hex()}")
        else:
            print(f"[{server.name}] test_invalid_retry_token: Attempt 1 - Connection completed but no retry token found internally.")
            # This could mean the server doesn't issue Retry or our condition for it wasn't met.

    except asyncio.TimeoutError:
        print(f"[{server.name}] test_invalid_retry_token: Attempt 1 - Timeout during connection.")
        # Check if client_step1 was partially initialized and has a token
        if client_step1 and client_step1._quic._retry_token:
            original_retry_token = client_step1._quic._retry_token
            print(f"[{server.name}] test_invalid_retry_token: Attempt 1 - Token found after timeout: {original_retry_token.hex()}")
        else: # Check logger for retry packet
            if hasattr(logger_s1, 'to_dict'):
                log_data = logger_s1.to_dict()
                for event in log_data["traces"][0]["events"]:
                    if event["name"] == "transport:packet_received" and event["data"]["header"]["packet_type"] == "retry":
                        print(f"[{server.name}] test_invalid_retry_token: Attempt 1 - Timeout, but Retry packet logged. Token extraction from log not implemented. Cannot proceed reliably.")
                        # Ideally, if a retry packet is logged, we should be able to get the token.
                        # This points to a potential difficulty in capturing the token if the client doesn't store it upon early failure.
                        break 
    except QuicConnectionError as e:
        print(f"[{server.name}] test_invalid_retry_token: Attempt 1 - QuicConnectionError: {e.reason_phrase} (Code: {e.quic_error_code})")
        # This is a likely path if a Retry is issued. The client might close itself.
        # Check if client_step1 (if it got assigned before error) or its underlying _quic object has the token.
        # Note: client_step1 might not be assigned if connect() raises exception before returning protocol.
        # This is a fundamental challenge with accessing the protocol instance on early failure from connect().
        # For now, we rely on the logger primarily in this exception block.
        if hasattr(logger_s1, 'to_dict'):
            log_data = logger_s1.to_dict()
            retry_logged = False
            for event in log_data["traces"][0]["events"]:
                if event["name"] == "transport:packet_received" and event["data"]["header"]["packet_type"] == "retry":
                    print(f"[{server.name}] test_invalid_retry_token: Attempt 1 - QuicConnectionError, Retry packet logged.")
                    retry_logged = True
                    # If we had a way to extract token from qlog event['data']['frames'][0]['token_data_here'] that would be great.
                    # For now, we assume if retry is logged, the test *might* proceed if token was captured by other means.
                    # client._quic._retry_token is the most direct, but client may not be available.
                    break
            if not retry_logged:
                 print(f"[{server.name}] test_invalid_retry_token: Attempt 1 - QuicConnectionError, but no Retry packet found in log.")
        # If client_step1 was somehow assigned and then an error occurred, check it.
        if client_step1 and client_step1._quic._retry_token:
             original_retry_token = client_step1._quic._retry_token
             print(f"[{server.name}] test_invalid_retry_token: Attempt 1 - Token found in client after QuicConnectionError: {original_retry_token.hex()}")


    except ConnectionRefusedError:
        print(f"[{server.name}] test_invalid_retry_token: Attempt 1 - Connection refused. Cannot obtain token.")
    except Exception as e:
        print(f"[{server.name}] test_invalid_retry_token: Attempt 1 - Unexpected error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if client_step1:
            # Check for token one last time before closing, in case it's set during close or by a late event.
            if not original_retry_token and client_step1._quic._retry_token:
                original_retry_token = client_step1._quic._retry_token
                print(f"[{server.name}] test_invalid_retry_token: Attempt 1 - Token found in finally block: {original_retry_token.hex()}")
            await client_step1.close()

    if not original_retry_token:
        print(f"[{server.name}] test_invalid_retry_token: No retry token obtained in Attempt 1. Test cannot proceed.")
        # One final check on the logger if no token was ever found on the client instance
        if hasattr(logger_s1, 'to_dict'):
            log_data = logger_s1.to_dict()
            for event in log_data["traces"][0]["events"]:
                if event["name"] == "transport:packet_received" and event["data"]["header"]["packet_type"] == "retry":
                    print(f"[{server.name}] test_invalid_retry_token: Retry packet was logged, but token was not captured on the client object. This indicates a limitation in token capture for this test setup.")
                    break
        return

    # --- Modify the token ---
    modified_token = original_retry_token + b"\xAA" # Append/modify to invalidate
    print(f"[{server.name}] test_invalid_retry_token: Original token: {original_retry_token.hex()}, Modified token: {modified_token.hex()}")

    # --- Second connection attempt with the modified token ---
    print(f"[{server.name}] test_invalid_retry_token: Attempt 2 - Connecting with modified token.")
    
    logger_s2 = QuicLogger()
    # path_s2 = None
    # if initial_configuration.quic_logger and hasattr(initial_configuration.quic_logger, 'path') and initial_configuration.quic_logger.path:
    #     try:
    #         path_s2 = initial_configuration.quic_logger.path + "_invalid_token_attempt2"
    #         logger_s2 = QuicFileLogger(path_s2)
    #     except Exception:
    #         logger_s2 = QuicLogger()


    config_step2 = QuicConfiguration(
        alpn_protocols=initial_configuration.alpn_protocols,
        is_client=True,
        quic_logger=logger_s2, 
        secrets_log_file=initial_configuration.secrets_log_file,
        verify_mode=initial_configuration.verify_mode,
        token=modified_token, 
        supported_versions=initial_configuration.supported_versions[:]
    )

    try:
        async with connect( 
            server.host,
            server.port, 
            configuration=config_step2,
            create_protocol=HttpClient,
        ) as client_step2: # client_step2 is distinct from client_step1
            await client_step2.wait_connected() 
            print(f"[{server.name}] test_invalid_retry_token: Attempt 2 - Connection SUCCEEDED with modified token. This is UNEXPECTED behavior.")
            # Check if server sent a close event immediately after connection, e.g. in HTTP/3 GOAWAY or QUIC CLOSE
            if client_step2._quic._close_event and client_step2._quic._close_event.error_code == QuicErrorCode.INVALID_TOKEN:
                 print(f"[{server.name}] test_invalid_retry_token: Attempt 2 - Connection succeeded but _close_event shows INVALID_TOKEN. Marking as success.")
                 server.result |= Result.M
            # else: Test fails here due to unexpected success without the correct error.

    except QuicConnectionError as e:
        if e.quic_error_code == QuicErrorCode.INVALID_TOKEN:
            print(f"[{server.name}] test_invalid_retry_token: Attempt 2 - Caught expected QuicConnectionError with INVALID_TOKEN (0x0b).")
            server.result |= Result.M
        else:
            print(f"[{server.name}] test_invalid_retry_token: Attempt 2 - Caught QuicConnectionError with unexpected code: {e.quic_error_code} (expected 0x0b), reason: {e.reason_phrase}.")
            if hasattr(logger_s2, 'to_dict'): # Check logs for fallback
                log_data = logger_s2.to_dict()
                for event in log_data["traces"][0]["events"]:
                    if event["name"] == "transport:connection_closed" and event["data"].get("error_code") == QuicErrorCode.INVALID_TOKEN:
                        print(f"[{server.name}] test_invalid_retry_token: Attempt 2 - Verified INVALID_TOKEN (0x0b) in logs despite different exception code.")
                        server.result |= Result.M 
                        break 
    
    except ConnectionAbortedError as e: 
        print(f"[{server.name}] test_invalid_retry_token: Attempt 2 - ConnectionAbortedError: {e}.")
        if hasattr(logger_s2, 'to_dict'):
            log_data = logger_s2.to_dict()
            found_in_log = False
            for event in log_data["traces"][0]["events"]:
                if event["name"] == "transport:connection_closed" and event["data"].get("error_code") == QuicErrorCode.INVALID_TOKEN:
                    print(f"[{server.name}] test_invalid_retry_token: Attempt 2 - Verified INVALID_TOKEN (0x0b) in logs after ConnectionAbortedError.")
                    server.result |= Result.M 
                    found_in_log = True
                    break
            if not found_in_log:
                 print(f"[{server.name}] test_invalid_retry_token: Attempt 2 - INVALID_TOKEN not found in logs after ConnectionAbortedError.")
    
    except Exception as e:
        print(f"[{server.name}] test_invalid_retry_token: Attempt 2 - An unexpected error occurred: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
    
    print(f"[{server.name}] Finished test_invalid_retry_token. Result: {server.result & Result.M == Result.M}")


async def test_retire_prior_to(server: Server, configuration: QuicConfiguration):
    """
    Tests the client's handling of the Retire Prior To field in NEW_CONNECTION_ID frames
    sent by the server. This is an opportunistic test.
    """
    if not server.http3: # Most tests use H3 context
        print(f"[{server.name}] Skipping test_retire_prior_to as it's not an HTTP/3 server (for consistency).")
        return

    print(f"\n[{server.name}] Starting test_retire_prior_to")
    configuration.alpn_protocols = H3_ALPN

    if not configuration.quic_logger or not hasattr(configuration.quic_logger, "to_dict"):
        print(f"[{server.name}] test_retire_prior_to: QuicLogger with to_dict() method is required. Skipping.")
        return

    # Clear previous events if the logger object allows, to focus on this test's events.
    # This is a bit of a hack; ideally, each test run would get a fresh logger instance
    # or a logger that can be scoped. The current interop_test framework reuses `configuration`.
    if hasattr(configuration.quic_logger, "_events") and isinstance(configuration.quic_logger._events, list):
        configuration.quic_logger._events.clear()
    elif hasattr(configuration.quic_logger, "events") and isinstance(configuration.quic_logger.events, list):
         configuration.quic_logger.events.clear()


    try:
        async with connect(
            server.host,
            server.http3_port or server.port,
            configuration=configuration,
            create_protocol=HttpClient,
        ) as client:
            client = cast(HttpClient, client)
            
            print(f"[{server.name}] test_retire_prior_to: Performing GET request.")
            request_path = server.path if server.path and server.path != "/" else "/"
            if not request_path.startswith("/"): request_path = "/" + request_path
            # Ensure there's a scheme for HttpClient.get if not in server.host
            url_host = server.host
            if "://" not in url_host:
                url_host = f"https://{server.host}"
            
            await client.get(f"{url_host}{request_path}")
            
            print(f"[{server.name}] test_retire_prior_to: Waiting for potential NEW_CONNECTION_ID frames from server...")
            await asyncio.sleep(2.5) # Increased wait time slightly more

            print(f"[{server.name}] test_retire_prior_to: Closing connection.")
        # Connection closed by async with context manager
    except Exception as e:
        print(f"[{server.name}] test_retire_prior_to: An error occurred during connection/request: {type(e).__name__}: {e}")
        # Do not return yet, try to analyze logs up to the point of failure.
        pass 

    print(f"[{server.name}] test_retire_prior_to: Analyzing QuicLogger trace...")
    
    try:
        log_data = configuration.quic_logger.to_dict()
    except Exception as e:
        print(f"[{server.name}] test_retire_prior_to: Failed to convert quic_logger to dict: {e}. Cannot analyze.")
        return

    server_sent_nci_frames = [] 
    client_sent_rci_seqs = set()  
    client_own_cids_seq_space = {0} # Client's initial CID used for the server has sequence 0.

    for trace_wrapper in log_data.get("traces", []):
        vantage_point_type = trace_wrapper.get("vantage_point", {}).get("type", "").lower()
        # We are interested in the client's log.
        if vantage_point_type != "client": 
            # If logs might contain both client and server, ensure we only process client's view.
            # However, aioquic's logger is typically from one perspective.
            # If the logger is shared or from server, this check might be important.
            # For now, assume logger is client's.
            pass

        for event_entry in trace_wrapper.get("events", []):
            event_name = event_entry.get("name")
            event_data = event_entry.get("data")
            
            if not event_name or not event_data:
                continue

            if event_name == "transport:packet_received": 
                for frame in event_data.get("frames", []):
                    if frame.get("frame_type") == "new_connection_id":
                        seq = frame.get("sequence_number")
                        rpt = frame.get("retire_prior_to")
                        if seq is not None and rpt is not None:
                            server_sent_nci_frames.append({"seq": int(seq), "rpt": int(rpt)})
                            print(f"[{server.name}] Log: Client RX NEW_CONNECTION_ID from server: new_cid_seq={seq}, rpt={rpt}")
            
            elif event_name == "transport:packet_sent": 
                for frame in event_data.get("frames", []):
                    if frame.get("frame_type") == "new_connection_id":
                        seq = frame.get("sequence_number")
                        if seq is not None:
                            # This means the client issued a new CID for itself to the server.
                            client_own_cids_seq_space.add(int(seq))
                            print(f"[{server.name}] Log: Client TX NEW_CONNECTION_ID to server: its_new_cid_seq={seq}")
                    elif frame.get("frame_type") == "retire_connection_id":
                        seq = frame.get("sequence_number")
                        if seq is not None:
                            client_sent_rci_seqs.add(int(seq))
                            print(f"[{server.name}] Log: Client TX RETIRE_CONNECTION_ID for its own CID seq={seq}")
    
    if not server_sent_nci_frames:
        print(f"[{server.name}] test_retire_prior_to: Server did not send any NEW_CONNECTION_ID frames. Cannot verify client behavior.")
        return

    processed_any_effective_rpt = False
    all_observed_rpt_scenarios_passed = True

    for nci_frame in server_sent_nci_frames:
        server_rpt_value = nci_frame["rpt"]
        
        if server_rpt_value > 0: 
            processed_any_effective_rpt = True
            expected_to_be_retired_by_client = set()
            for client_cid_seq in client_own_cids_seq_space:
                if client_cid_seq < server_rpt_value:
                    expected_to_be_retired_by_client.add(client_cid_seq)
            
            print(f"[{server.name}] test_retire_prior_to: Server NCI rpt={server_rpt_value}. Client's known own CID seqs: {client_own_cids_seq_space}. Expected client to retire these: {expected_to_be_retired_by_client}")

            if not expected_to_be_retired_by_client.issubset(client_sent_rci_seqs):
                missing_retirements = expected_to_be_retired_by_client - client_sent_rci_seqs
                if missing_retirements: 
                    print(f"[{server.name}] test_retire_prior_to: FAILED. For server NCI rpt={server_rpt_value}, client did NOT send RETIRE_CONNECTION_ID for its own CID seqs: {missing_retirements}. Actual retired by client: {client_sent_rci_seqs}")
                    all_observed_rpt_scenarios_passed = False
                    break 
            else:
                 print(f"[{server.name}] test_retire_prior_to: Client correctly handled NCI rpt={server_rpt_value}. Expected retirements {expected_to_be_retired_by_client} were found in client's sent RCIs {client_sent_rci_seqs}.")

    if not processed_any_effective_rpt:
        print(f"[{server.name}] test_retire_prior_to: Server sent NEW_CONNECTION_ID frames, but none had retire_prior_to > 0. Cannot fully verify client's retire logic.")
        return

    if all_observed_rpt_scenarios_passed:
        print(f"[{server.name}] test_retire_prior_to: PASSED. Client correctly handled all observed NEW_CONNECTION_ID frames with retire_prior_to > 0.")
        server.result |= Result.M
    else:
        print(f"[{server.name}] test_retire_prior_to: FAILED as client did not correctly handle at least one retire_prior_to > 0 scenario.")


async def test_nci_invalid_length(server: Server, configuration: QuicConfiguration):
    """
    Tests the server's handling of NEW_CONNECTION_ID frames with invalid Length
    fields, as per RFC9000 Section 19.15 (frame formats) and general frame processing rules.
    Specifically, NEW_CONNECTION_ID frame validation is detailed in Section 19.11.

    Scenario:
    The client sends two NEW_CONNECTION_ID frames, each in a separate connection:
    1. Case 1: A NEW_CONNECTION_ID frame with Connection ID Length = 0.
    2. Case 2: A NEW_CONNECTION_ID frame with Connection ID Length = 21 (which is > 20).

    Expected outcome:
    For both cases, the server should detect the invalid frame length and respond by
    closing the connection with a FRAME_ENCODING_ERROR (0x07).
    """
    if not server.http3: # Using H3 context for consistency
        print(f"[{server.name}] Skipping test_nci_invalid_length as it's not an HTTP/3 server.")
        return

    print(f"\n[{server.name}] Starting test_nci_invalid_length")
    
    # Use a unique logger suffix for this test if file logging is on, to avoid mixing with other tests.
    # This is tricky because the configuration object is reused.
    # For simplicity, we'll rely on the passed logger and clear it if possible.

    original_logger = configuration.quic_logger # Keep a reference

    async def _run_case(nci_length: int, case_name: str, current_config: QuicConfiguration) -> bool:
        print(f"[{server.name}] test_nci_invalid_length: Running case: {case_name} (Length={nci_length})")

        # Setup a new logger for each sub-case to keep logs clean if possible
        # This is complex with the current test runner structure.
        # Instead, we will try to clear the main logger before each run.
        if hasattr(current_config.quic_logger, "_events") and isinstance(current_config.quic_logger._events, list):
            current_config.quic_logger._events.clear()
        elif hasattr(current_config.quic_logger, "events") and isinstance(current_config.quic_logger.events, list):
            current_config.quic_logger.events.clear()

        case_passed = False
        try:
            async with connect(
                server.host,
                server.http3_port or server.port,
                configuration=current_config, # Use the passed (potentially fresh) config
                create_protocol=HttpClient,
            ) as client:
                client = cast(HttpClient, client)
                await client.wait_connected() # Ensure handshake is complete
                print(f"[{server.name}] {case_name}: Connection established.")

                # Construct the NewConnectionIdFrame
                # Sequence number for client's new CID. Client's initial CID is 0.
                # So, the first new CID it offers would be sequence 1.
                # This sequence number space is for CIDs *client provides to server*.
                client_cid_sequence_number = 1 
                
                # Ensure this sequence number is higher than any existing CIDs the client has.
                # aioquic's QuicConnection manages its own CID sequence numbers via _next_local_connection_id_sequence_number
                # It's safer to use what the connection thinks is next, but _send_frame doesn't auto-manage this.
                # For a test sending a raw frame, we must pick a plausible one.
                # If the client has already issued NCIs, client._quic._next_local_connection_id_sequence_number would be > 0 or 1.
                # Let's try to use the internal counter if available, otherwise default.
                if hasattr(client._quic, '_next_local_connection_id_sequence_number'):
                    client_cid_sequence_number = client._quic._next_local_connection_id_sequence_number
                else: # Fallback if attribute name changes or not accessible
                    print(f"[{server.name}] {case_name}: _next_local_connection_id_sequence_number not found, defaulting CID sequence to 1.")
                    client_cid_sequence_number = 1


                nci_frame = NewConnectionIdFrame(
                    sequence_number=client_cid_sequence_number,
                    retire_prior_to=0, # Client isn't asking server to retire server's CIDs with this frame
                    connection_id=os.urandom(nci_length), # Length will be 0 or 21
                    stateless_reset_token=os.urandom(16)
                )
                
                print(f"[{server.name}] {case_name}: Sending NEW_CONNECTION_ID frame with length {nci_length}, seq {nci_frame.sequence_number}.")
                client._quic._send_frame(nci_frame, packet_type=PacketType.ONE_RTT)
                
                # Increment the internal counter to reflect a new CID was "issued"
                # This is important if the connection were to survive and send another NCI.
                if hasattr(client._quic, '_next_local_connection_id_sequence_number'):
                    client._quic._next_local_connection_id_sequence_number +=1

                # Wait for server to process and hopefully send a CONNECTION_CLOSE
                print(f"[{server.name}] {case_name}: Frame sent. Waiting for server reaction...")
                for _ in range(10): # Try pinging/sleeping a few times
                    await asyncio.sleep(0.1)
                    if client._quic._close_event is not None and client._quic._close_event.error_code == QuicErrorCode.FRAME_ENCODING_ERROR:
                        print(f"[{server.name}] {case_name}: Server closed with FRAME_ENCODING_ERROR (from _close_event).")
                        case_passed = True
                        break
                    await client.ping() # Send something to elicit response / check if connection is alive
                
                if not case_passed and client._quic._close_event is not None:
                     print(f"[{server.name}] {case_name}: Server closed with different error: {client._quic._close_event.error_code} (expected {QuicErrorCode.FRAME_ENCODING_ERROR})")
                elif not case_passed:
                     print(f"[{server.name}] {case_name}: Server did not close connection as expected after invalid NCI frame.")


        except QuicConnectionError as e:
            if e.quic_error_code == QuicErrorCode.FRAME_ENCODING_ERROR:
                print(f"[{server.name}] {case_name}: Caught expected QuicConnectionError with FRAME_ENCODING_ERROR (0x07).")
                case_passed = True
            else:
                print(f"[{server.name}] {case_name}: Caught QuicConnectionError with unexpected code: {e.quic_error_code} (expected 0x07), reason: {e.reason_phrase}.")
        except ConnectionAbortedError as e: # Can happen if server just drops
            print(f"[{server.name}] {case_name}: ConnectionAbortedError: {e}.")
        except Exception as e:
            print(f"[{server.name}] {case_name}: An unexpected error occurred: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()

        # Fallback log check if not passed via direct exception or _close_event
        if not case_passed and hasattr(current_config.quic_logger, "to_dict"):
            try:
                log_data = current_config.quic_logger.to_dict()
                for trace_wrapper in log_data.get("traces", []):
                    for event_entry in trace_wrapper.get("events", []):
                        event_name = event_entry.get("name")
                        event_data = event_entry.get("data")
                        if event_name == "transport:connection_closed" and event_data.get("error_code") == QuicErrorCode.FRAME_ENCODING_ERROR:
                            print(f"[{server.name}] {case_name}: Verified FRAME_ENCODING_ERROR (0x07) in logs.")
                            case_passed = True
                            break
                    if case_passed: break
            except Exception as log_e:
                print(f"[{server.name}] {case_name}: Error analyzing QuicLogger for fallback: {log_e}")
        
        print(f"[{server.name}] test_nci_invalid_length: Case {case_name} result: {'PASSED' if case_passed else 'FAILED'}")
        return case_passed

    # Create a base configuration for the test runs.
    # Each run of _run_case will use a configuration derived from this.
    # This is important because `token` or other connection-specific state might be in `configuration`.
    
    # Case 1: Length = 0
    # Create a fresh config for this case based on the initial one.
    config_case1 = QuicConfiguration(
        alpn_protocols=configuration.alpn_protocols,
        is_client=True,
        quic_logger=QuicLogger() if original_logger is None else original_logger, # Reuse or make new
        secrets_log_file=configuration.secrets_log_file,
        verify_mode=configuration.verify_mode,
        supported_versions=configuration.supported_versions[:]
    )
    passed_case_len0 = await _run_case(nci_length=0, case_name="NCI Length 0", current_config=config_case1)
    
    # Brief pause between cases if needed, though new connection should isolate them.
    await asyncio.sleep(0.2)

    # Case 2: Length = 21
    config_case2 = QuicConfiguration(
        alpn_protocols=configuration.alpn_protocols,
        is_client=True,
        quic_logger=QuicLogger() if original_logger is None else original_logger, # Reuse or make new
        secrets_log_file=configuration.secrets_log_file,
        verify_mode=configuration.verify_mode,
        supported_versions=configuration.supported_versions[:]
    )
    passed_case_len21 = await _run_case(nci_length=21, case_name="NCI Length 21", current_config=config_case2)

    if passed_case_len0 and passed_case_len21:
        print(f"[{server.name}] test_nci_invalid_length: PASSED for both invalid lengths (0 and 21).")
        server.result |= Result.M
    else:
        print(f"[{server.name}] test_nci_invalid_length: FAILED. Length 0: {'Pass' if passed_case_len0 else 'Fail'}. Length 21: {'Pass' if passed_case_len21 else 'Fail'}.")
    
    # Restore original logger to configuration if it was temporarily replaced or cleared for sub-cases.
    # This is tricky; ideally, configuration object shouldn't be modified in place by tests,
    # or test runner should provide fresh configs.
    configuration.quic_logger = original_logger


async def test_retire_cid_out_of_range(server: Server, configuration: QuicConfiguration):
    """
    Tests server handling of a RETIRE_CONNECTION_ID frame with an out-of-range
    sequence number, as per RFC9000 Section 19.16 and Section 10.3.

    Scenario:
    1. Client establishes an HTTP/3 connection.
    2. Client sends a RETIRE_CONNECTION_ID frame with a very large sequence number
       (e.g., 99999) that the server could not have issued.

    Expected outcome:
    The server should treat this as a connection error of type PROTOCOL_VIOLATION
    and close the connection with error code 0x0a.
    """
    if not server.http3: # Using H3 context for consistency
        print(f"[{server.name}] Skipping test_retire_cid_out_of_range as it's not an HTTP/3 server.")
        return

    print(f"\n[{server.name}] Starting test_retire_cid_out_of_range")
    
    # Clear logger events if possible, to focus on this test's events.
    if hasattr(configuration.quic_logger, "_events") and isinstance(configuration.quic_logger._events, list):
        configuration.quic_logger._events.clear()
    elif hasattr(configuration.quic_logger, "events") and isinstance(configuration.quic_logger.events, list):
         configuration.quic_logger.events.clear()

    test_passed = False
    try:
        async with connect(
            server.host,
            server.http3_port or server.port,
            configuration=configuration,
            create_protocol=HttpClient,
        ) as client:
            client = cast(HttpClient, client)
            await client.wait_connected() # Ensure handshake is complete
            print(f"[{server.name}] test_retire_cid_out_of_range: Connection established.")

            out_of_range_sequence_number = 99999
            rci_frame = RetireConnectionIdFrame(sequence_number=out_of_range_sequence_number)
            
            print(f"[{server.name}] test_retire_cid_out_of_range: Sending RETIRE_CONNECTION_ID frame with seq={out_of_range_sequence_number}.")
            client._quic._send_frame(rci_frame, packet_type=PacketType.ONE_RTT)
            
            print(f"[{server.name}] test_retire_cid_out_of_range: Frame sent. Waiting for server reaction...")
            for _ in range(10): # Try pinging/sleeping a few times
                await asyncio.sleep(0.1)
                if client._quic._close_event is not None and client._quic._close_event.error_code == QuicErrorCode.PROTOCOL_VIOLATION:
                    print(f"[{server.name}] test_retire_cid_out_of_range: Server closed with PROTOCOL_VIOLATION (from _close_event).")
                    test_passed = True
                    break
                await client.ping()
            
            if not test_passed and client._quic._close_event is not None:
                 print(f"[{server.name}] test_retire_cid_out_of_range: Server closed with different error: {client._quic._close_event.error_code} (expected {QuicErrorCode.PROTOCOL_VIOLATION})")
            elif not test_passed:
                 print(f"[{server.name}] test_retire_cid_out_of_range: Server did not close connection as expected after invalid RCI frame.")

    except QuicConnectionError as e:
        if e.quic_error_code == QuicErrorCode.PROTOCOL_VIOLATION:
            print(f"[{server.name}] test_retire_cid_out_of_range: Caught expected QuicConnectionError with PROTOCOL_VIOLATION (0x0a).")
            test_passed = True
        else:
            print(f"[{server.name}] test_retire_cid_out_of_range: Caught QuicConnectionError with unexpected code: {e.quic_error_code} (expected 0x0a), reason: {e.reason_phrase}.")
    except ConnectionAbortedError as e:
        print(f"[{server.name}] test_retire_cid_out_of_range: ConnectionAbortedError: {e}.")
    except Exception as e:
        print(f"[{server.name}] test_retire_cid_out_of_range: An unexpected error occurred: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()

    # Fallback log check
    if not test_passed and hasattr(configuration.quic_logger, "to_dict"):
        try:
            log_data = configuration.quic_logger.to_dict()
            for trace_wrapper in log_data.get("traces", []):
                for event_entry in trace_wrapper.get("events", []):
                    event_name = event_entry.get("name")
                    event_data = event_entry.get("data")
                    if event_name == "transport:connection_closed" and event_data.get("error_code") == QuicErrorCode.PROTOCOL_VIOLATION:
                        print(f"[{server.name}] test_retire_cid_out_of_range: Verified PROTOCOL_VIOLATION (0x0a) in logs.")
                        test_passed = True
                        break
                if test_passed: break
        except Exception as log_e:
            print(f"[{server.name}] test_retire_cid_out_of_range: Error analyzing QuicLogger for fallback: {log_e}")

    if test_passed:
        print(f"[{server.name}] test_retire_cid_out_of_range: PASSED.")
        server.result |= Result.M
    else:
        print(f"[{server.name}] test_retire_cid_out_of_range: FAILED.")


async def test_path_challenge_response_initial_addr(server: Server, configuration: QuicConfiguration):
    """
    Tests server response to a PATH_CHALLENGE frame sent after handshake confirmation
    to the server's initial address, as per RFC9000 Section 8.2.

    Scenario:
    1. Client establishes an HTTP/3 connection and waits for handshake confirmation.
    2. Client sends a PATH_CHALLENGE frame with unique data to the server.
    3. Client monitors received packets (via QuicLogger) for a PATH_RESPONSE frame.

    Expected outcome:
    The server should respond with a PATH_RESPONSE frame containing the exact same
    data as sent in the PATH_CHALLENGE frame. The test verifies this by checking
    the QuicLogger output.
    """
    if not server.http3: # Using H3 context for consistency
        print(f"[{server.name}] Skipping test_path_challenge_response_initial_addr as it's not an HTTP/3 server.")
        return

    print(f"\n[{server.name}] Starting test_path_challenge_response_initial_addr")
    
    # Clear logger events if possible
    if hasattr(configuration.quic_logger, "_events") and isinstance(configuration.quic_logger._events, list):
        configuration.quic_logger._events.clear()
    elif hasattr(configuration.quic_logger, "events") and isinstance(configuration.quic_logger.events, list):
         configuration.quic_logger.events.clear()

    test_passed = False
    challenge_data_sent = os.urandom(8)

    try:
        async with connect(
            server.host,
            server.http3_port or server.port,
            configuration=configuration,
            create_protocol=HttpClient,
        ) as client:
            client = cast(HttpClient, client)
            
            print(f"[{server.name}] test_path_challenge_response_initial_addr: Waiting for handshake confirmed...")
            await client.wait_handshake_confirmed()
            print(f"[{server.name}] test_path_challenge_response_initial_addr: Handshake confirmed.")

            pc_frame = PathChallengeFrame(data=challenge_data_sent)
            
            print(f"[{server.name}] test_path_challenge_response_initial_addr: Sending PATH_CHALLENGE frame with data: {challenge_data_sent.hex()}.")
            client._quic._send_frame(pc_frame, packet_type=PacketType.ONE_RTT)
            
            print(f"[{server.name}] test_path_challenge_response_initial_addr: Frame sent. Waiting for PATH_RESPONSE (up to 5s)...")
            
            # Wait for server response by checking logger periodically
            # Total wait time: 5 seconds (50 * 0.1s)
            for _ in range(50): 
                await asyncio.sleep(0.1)
                if hasattr(configuration.quic_logger, "to_dict"):
                    try:
                        log_data = configuration.quic_logger.to_dict()
                        for trace_wrapper in log_data.get("traces", []):
                            for event_entry in trace_wrapper.get("events", []):
                                event_name = event_entry.get("name")
                                event_data = event_entry.get("data")
                                if event_name == "transport:packet_received":
                                    for frame in event_data.get("frames", []):
                                        if frame.get("frame_type") == "path_response":
                                            response_data_hex = frame.get("data")
                                            if response_data_hex:
                                                response_data = bytes.fromhex(response_data_hex)
                                                print(f"[{server.name}] test_path_challenge_response_initial_addr: Received PATH_RESPONSE with data: {response_data.hex()}")
                                                if response_data == challenge_data_sent:
                                                    print(f"[{server.name}] test_path_challenge_response_initial_addr: PATH_RESPONSE data matches sent PATH_CHALLENGE data.")
                                                    test_passed = True
                                                    break
                                    if test_passed: break
                            if test_passed: break
                        if test_passed: break
                    except Exception as log_e:
                        print(f"[{server.name}] test_path_challenge_response_initial_addr: Error analyzing QuicLogger during wait: {log_e}")
                if test_passed:
                    break
            
            if not test_passed:
                print(f"[{server.name}] test_path_challenge_response_initial_addr: Timed out waiting for matching PATH_RESPONSE frame.")
            
            # Allow connection to close gracefully via async with
            print(f"[{server.name}] test_path_challenge_response_initial_addr: Test actions complete, closing connection.")

    except QuicConnectionError as e:
        print(f"[{server.name}] test_path_challenge_response_initial_addr: QuicConnectionError: {e.reason_phrase} (Code: {e.quic_error_code}).")
    except ConnectionAbortedError as e:
        print(f"[{server.name}] test_path_challenge_response_initial_addr: ConnectionAbortedError: {e}.")
    except Exception as e:
        print(f"[{server.name}] test_path_challenge_response_initial_addr: An unexpected error occurred: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()

    # Final verification based on test_passed flag set during the wait loop
    if test_passed:
        print(f"[{server.name}] test_path_challenge_response_initial_addr: PASSED.")
        server.result |= Result.M
    else:
        print(f"[{server.name}] test_path_challenge_response_initial_addr: FAILED. No matching PATH_RESPONSE received or an error occurred.")


async def test_nci_retire_prior_to_non_applicable(server: Server, configuration: QuicConfiguration):
    """
    Tests client handling of server NEW_CONNECTION_ID frame with a Retire Prior To (RPT)
    value higher than any client-issued CID sequence number.
    Relevant RFC9000 sections include Section 5.1.2 (CID Management),
    Section 19.11 (NEW_CONNECTION_ID frame), and Section 10.3 (Error Handling for CIDs,
    implicitly testing client does not generate errors).

    Scenario:
    1. Client establishes an HTTP/3 connection and confirms handshake.
    2. Client issues a few of its own CIDs to the server (e.g., seq 1, seq 2).
       The highest client-issued CID sequence is now 2.
    3. Client performs some activity (e.g., GET request) and waits.
    4. Test observes (via QuicLogger) if the server sends a NEW_CONNECTION_ID frame
       with a `retire_prior_to` value > 2 (e.g., RPT=5).

    Expected outcome:
    If such an NCI frame is received from the server:
    - The client (aioquic) should correctly process the new CID provided by the server.
    - Crucially, the client should NOT send RETIRE_CONNECTION_ID frames for any
      sequence numbers it has not actually issued. For example, if its highest issued
      CID sequence was 2 and the server's NCI has RPT=5, the client should retire
      its CIDs with sequence numbers 0, 1, and 2 (if not already retired), but it
      MUST NOT send RCI frames for sequence numbers 3 or 4.
    - The connection should remain open and functional, without the client erroneously
      closing it due to a misinterpretation of the RPT value or by sending invalid RCI frames.
    The test is opportunistic and passes if this specific scenario is observed and the
    client (aioquic) handles it correctly by not retiring CIDs it hasn't issued.
    """
    if not server.http3:
        print(f"[{server.name}] Skipping test_nci_retire_prior_to_non_applicable as it's not an HTTP/3 server.")
        return

    print(f"\n[{server.name}] Starting test_nci_retire_prior_to_non_applicable")

    if hasattr(configuration.quic_logger, "_events") and isinstance(configuration.quic_logger._events, list):
        configuration.quic_logger._events.clear()
    elif hasattr(configuration.quic_logger, "events") and isinstance(configuration.quic_logger.events, list):
        configuration.quic_logger.events.clear()

    max_client_cid_seq_issued = 0 # Client's initial CID for the server is seq 0
    client_cids_issued_to_server = {0} # Track sequence numbers client has used for CIDs it sent

    scenario_observed_and_passed = False
    scenario_could_not_be_verified = True # Assume we can't verify until specific NCI is seen

    try:
        async with connect(
            server.host,
            server.http3_port or server.port,
            configuration=configuration,
            create_protocol=HttpClient,
        ) as client:
            client = cast(HttpClient, client)
            
            print(f"[{server.name}] test_nci_rpt_non_applicable: Waiting for handshake confirmed...")
            await client.wait_handshake_confirmed()
            print(f"[{server.name}] test_nci_rpt_non_applicable: Handshake confirmed.")

            # Client issues a couple of its own CIDs
            next_client_cid_seq = 1
            for _ in range(2): # Issue two CIDs, seq 1 and seq 2
                if hasattr(client._quic, '_next_local_connection_id_sequence_number'):
                     # Use the connection's internal counter if available and higher
                     next_client_cid_seq = max(next_client_cid_seq, client._quic._next_local_connection_id_sequence_number)
                
                nci_frame_to_server = NewConnectionIdFrame(
                    sequence_number=next_client_cid_seq,
                    retire_prior_to=0, # Client isn't asking server to retire anything yet
                    connection_id=os.urandom(8), 
                    stateless_reset_token=os.urandom(16)
                )
                print(f"[{server.name}] test_nci_rpt_non_applicable: Client sending NCI (seq={next_client_cid_seq}) to server.")
                client._quic._send_frame(nci_frame_to_server, packet_type=PacketType.ONE_RTT)
                client_cids_issued_to_server.add(next_client_cid_seq)
                max_client_cid_seq_issued = max(max_client_cid_seq_issued, next_client_cid_seq)
                
                if hasattr(client._quic, '_next_local_connection_id_sequence_number'):
                    client._quic._next_local_connection_id_sequence_number = next_client_cid_seq + 1
                next_client_cid_seq +=1
            
            print(f"[{server.name}] test_nci_rpt_non_applicable: Max client CID sequence issued: {max_client_cid_seq_issued}. Client CIDs: {client_cids_issued_to_server}")

            # Perform some activity
            request_path = server.path if server.path and server.path != "/" else "/"
            if not request_path.startswith("/"): request_path = "/" + request_path
            url_host = server.host
            if "://" not in url_host: url_host = f"https://{server.host}"
            await client.get(f"{url_host}{request_path}")
            
            print(f"[{server.name}] test_nci_rpt_non_applicable: Waiting for server NCI (up to 3s)...")
            await asyncio.sleep(3.0) # Wait for server to potentially send NCIs

            print(f"[{server.name}] test_nci_rpt_non_applicable: Test actions complete, closing connection.")
            # Connection closes via async with

    except Exception as e:
        print(f"[{server.name}] test_nci_rpt_non_applicable: An error occurred during connection phase: {type(e).__name__}: {e}")
        # Fall through to log analysis, as some relevant frames might have been exchanged.
        pass

    print(f"[{server.name}] test_nci_rpt_non_applicable: Analyzing QuicLogger trace...")
    if not hasattr(configuration.quic_logger, "to_dict"):
        print(f"[{server.name}] test_nci_rpt_non_applicable: QuicLogger not available or cannot be parsed. Skipping analysis.")
        return

    try:
        log_data = configuration.quic_logger.to_dict()
    except Exception as e:
        print(f"[{server.name}] test_nci_rpt_non_applicable: Failed to convert quic_logger to dict: {e}")
        return

    client_sent_rci_seqs_after_target_nci = set() 
    target_nci_observed_time = float('inf')

    for trace_wrapper in log_data.get("traces", []):
        for event_entry in trace_wrapper.get("events", []):
            event_name = event_entry.get("name")
            event_data = event_entry.get("data")
            event_time = event_entry.get("time", 0) # Assuming time is in ms or comparable units

            if not event_name or not event_data: continue

            if event_name == "transport:packet_received":
                for frame in event_data.get("frames", []):
                    if frame.get("frame_type") == "new_connection_id":
                        server_nci_seq = frame.get("sequence_number")
                        server_nci_rpt = frame.get("retire_prior_to")
                        if server_nci_seq is not None and server_nci_rpt is not None:
                            print(f"[{server.name}] Log: Client RX NCI from server: nci_seq={server_nci_seq}, rpt={server_nci_rpt} at t={event_time}ms")
                            if server_nci_rpt > max_client_cid_seq_issued:
                                scenario_could_not_be_verified = False # Target scenario observed
                                target_nci_observed_time = min(target_nci_observed_time, event_time)
                                print(f"[{server.name}] test_nci_rpt_non_applicable: Server sent NCI with RPT={server_nci_rpt} > max_client_cid_seq_issued ({max_client_cid_seq_issued}). This is the target scenario.")
                                # For this NCI, client should retire CIDs in client_cids_issued_to_server with seq < server_nci_rpt.
                                # It should NOT retire any other CIDs due to this specific RPT.
                                # We will check client_sent_rci_seqs_after_target_nci later.
                                # For now, assume client behaves correctly if no explicit error/crash.
                                scenario_observed_and_passed = True # Tentatively true, will verify RCI behavior below
            
            elif event_name == "transport:packet_sent":
                if event_time >= target_nci_observed_time: # Only consider RCIs sent after observing the target NCI
                    for frame in event_data.get("frames", []):
                        if frame.get("frame_type") == "retire_connection_id":
                            rci_seq = frame.get("sequence_number")
                            if rci_seq is not None:
                                client_sent_rci_seqs_after_target_nci.add(int(rci_seq))
                                print(f"[{server.name}] Log: Client TX RCI for seq={rci_seq} at t={event_time}ms (after target NCI)")


    if scenario_could_not_be_verified:
        print(f"[{server.name}] test_nci_rpt_non_applicable: Server did not send a NEW_CONNECTION_ID frame with Retire Prior To > max client CID sequence ({max_client_cid_seq_issued}). Cannot verify specific scenario.")
        return
    
    if scenario_observed_and_passed: # Target NCI was observed
        # Verify client's RCI behavior
        # Client should only have retired CIDs from `client_cids_issued_to_server`
        # No RCI should be for a sequence number `s` such that `max_client_cid_seq_issued < s < server_nci_rpt_that_triggered_this_check`
        # This check is implicitly handled if client_sent_rci_seqs_after_target_nci only contains CIDs from client_cids_issued_to_server.
        spurious_rcis_found = False
        for retired_seq in client_sent_rci_seqs_after_target_nci:
            if retired_seq not in client_cids_issued_to_server:
                # This means client retired a CID it never told the server about. This is a protocol violation on client side.
                # Or, more relevant to this test: retired a CID it *thinks* it should retire due to high RPT, but hasn't actually issued.
                print(f"[{server.name}] test_nci_rpt_non_applicable: FAILED. Client sent RETIRE_CONNECTION_ID for seq={retired_seq} which was not in its issued set {client_cids_issued_to_server} after observing a high RPT.")
                spurious_rcis_found = True
                scenario_observed_and_passed = False # Override previous optimistic pass
                break
        
        if not spurious_rcis_found:
             print(f"[{server.name}] test_nci_rpt_non_applicable: Client correctly did not send spurious RCI frames for unissued CIDs after server's high RPT NCI.")
             # Check if connection remained alive (e.g. no unexpected close with error code)
             # This is harder to check post-facto without more active probing after the event.
             # For this test, absence of spurious RCIs is the primary pass condition.
             # If an error occurred, it would have been caught in the main try-except or the test runner would show it.
             pass


    if scenario_observed_and_passed:
        print(f"[{server.name}] test_nci_rpt_non_applicable: PASSED. Client correctly handled server NCI with non-applicable RPT.")
        server.result |= Result.M
    elif not scenario_could_not_be_verified: # Scenario was observed but failed
        print(f"[{server.name}] test_nci_rpt_non_applicable: FAILED. Client did not correctly handle server NCI with non-applicable RPT.")
    # else: scenario_could_not_be_verified is true, already handled.


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

    # Add new test to the list of tests to run
    # Ensure it's not duplicated if script is run multiple times with modifications
    if not any(item[0] == "test_final_size_error" for item in tests):
        tests.append(("test_final_size_error", test_final_size_error))
    if not any(item[0] == "test_stream_limit_error_bidi" for item in tests):
        tests.append(("test_stream_limit_error_bidi", test_stream_limit_error_bidi))
    if not any(item[0] == "test_invalid_retry_token" for item in tests):
        tests.append(("test_invalid_retry_token", test_invalid_retry_token))
    if not any(item[0] == "test_retire_prior_to" for item in tests):
        tests.append(("test_retire_prior_to", test_retire_prior_to))
    if not any(item[0] == "test_nci_invalid_length" for item in tests):
        tests.append(("test_nci_invalid_length", test_nci_invalid_length))
    if not any(item[0] == "test_retire_cid_out_of_range" for item in tests):
        tests.append(("test_retire_cid_out_of_range", test_retire_cid_out_of_range))
    if not any(item[0] == "test_path_challenge_response_initial_addr" for item in tests):
        tests.append(("test_path_challenge_response_initial_addr", test_path_challenge_response_initial_addr))
    if not any(item[0] == "test_nci_retire_prior_to_non_applicable" for item in tests):
        tests.append(("test_nci_retire_prior_to_non_applicable", test_nci_retire_prior_to_non_applicable))
    
    loop = asyncio.get_event_loop()
    loop.run_until_complete(
        run(
            servers=servers,
            tests=tests,
            quic_log=args.quic_log,
            secrets_log_file=secrets_log_file,
        )
    )
