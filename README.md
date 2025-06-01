# AIOQUIC-NGFW Test Scripts

This repository contains a collection of Python scripts designed for testing negative scenarios and specific functionalities of NGFW (Next-Generation Firewall) deployments using the aioquic library.

## Prerequisites

*   Python 3.x installed.
*   aioquic library installed. You can typically install it using pip:
    ```bash
    pip install aioquic
    ```
*   Familiarity with aioquic examples and basic QUIC/HTTP3 concepts.
*   Access to client and server machines for testing, with appropriate network configuration to allow traffic between them.

## 1. Testing Custom First Flight Connection ID (`connection_ff.py`)

This script allows you to send the initial QUIC packet (first flight) with a custom-defined Connection ID.

**Purpose:** To test how the NGFW handles or logs specific Connection IDs in the first flight.

**Steps:**

1.  **Backup Original Connection File:**
    It's crucial to back up the original `connection.py` file from your `aioquic` library installation.
    ```bash
    sudo mv /usr/local/lib/python3.8/dist-packages/aioquic/quic/connection.py /usr/local/lib/python3.8/dist-packages/aioquic/quic/connection_orig.py
    ```
    *(Note: The exact path might vary based on your Python version and installation environment.)*

2.  **Replace Connection File:**
    Copy the provided `connection_ff.py` from this repository to your `aioquic` library directory, renaming it to `connection.py`.
    ```bash
    sudo cp connection_ff.py /usr/local/lib/python3.8/dist-packages/aioquic/quic/connection.py
    ```

3.  **Customize Connection ID (Optional):**
    If you wish to use a specific Connection ID, modify line 314 in `/usr/local/lib/python3.8/dist-packages/aioquic/quic/connection.py` (which is now your `connection_ff.py`):
    ```python
    # Example:
    peer_cid = ConnectionID(b"\x00\x11\x22\x33\x44\x55\x66\x77") 
    ```
    Replace `"\x00\x11\x22\x33\x44\x55\x66\x77"` with your desired byte string. If you don't modify it, the script will use the default Connection ID specified in `connection_ff.py`.

4.  **Run Client and Server:**
    Start your standard aioquic HTTP3 server and then run the `http3_client.py` (from the aioquic examples).
    *   On the server machine: `python examples/http3_server.py --certificate <your_cert.pem> --private-key <your_key.pem>`
    *   On the client machine: `python examples/http3_client.py https://<server_ip>:<port>/`

5.  **Observe:**
    You should observe that the peer (server) receives the custom Connection ID you specified (or the default from `connection_ff.py`).

**Restoring Original Functionality:**
To revert to the standard `aioquic` behavior, restore your backup:
```bash
sudo mv /usr/local/lib/python3.8/dist-packages/aioquic/quic/connection_orig.py /usr/local/lib/python3.8/dist-packages/aioquic/quic/connection.py
```

## 2. Testing File Transfer with Multiple Streams (`http3_client_fd.py`, `http3_server_fd.py`)

These scripts are modified versions of the standard aioquic `http3_client.py` and `http3_server.py` examples. They are designed to send a large file (e.g., 100MB, named `10Gigfile1.pdf` by default) in chunks using multiple streams (though not QUIC multiplexing in the traditional sense, but rather sequential streams for different chunks).

**Purpose:** To test how the NGFW handles large file transfers broken into chunks over separate streams and to observe the data transfer pattern.

**Steps:**

1.  **Modify Scripts (Optional):**
    You can customize the file name, size, and chunking behavior by modifying the following lines:
    *   In `http3_client_fd.py`: Lines around 502, 464, 468 (adjust according to script content for file handling).
    *   In `http3_server_fd.py`: Line around 485 (adjust according to script content for file handling).

2.  **Place Scripts in Examples Folder:**
    *   Copy `http3_client_fd.py` to the `aioquic/examples/` directory on your **client machine**.
    *   Copy `http3_server_fd.py` to the `aioquic/examples/` directory on your **server machine**.
    ```bash
    # On client machine
    cp http3_client_fd.py <path_to_aioquic>/examples/

    # On server machine
    cp http3_server_fd.py <path_to_aioquic>/examples/
    ```
    *(Replace `<path_to_aioquic>` with the actual path to your aioquic library installation, e.g., `~/aioquic` or `/usr/local/lib/python3.8/dist-packages/aioquic`)*

3.  **Run Server and Client:**
    *   On the server machine, start the modified server:
        ```bash
        python <path_to_aioquic>/examples/http3_server_fd.py --certificate <your_cert.pem> --private-key <your_key.pem>
        ```
    *   On the client machine, run the modified client, pointing to your server:
        ```bash
        python <path_to_aioquic>/examples/http3_client_fd.py https://<server_ip>:<port>/10Gigfile1.pdf --ca-certs <your_ca_certs.pem>
        ```
        *(Ensure the filename in the URL matches the one configured in the scripts if you changed it.)*

4.  **Observe:**
    You will observe the file being transferred in parts. The scripts simulate breaking the file into chunks and sending them.

## 3. Testing Various QUIC Parameters (`connection_cid.py`, `interop_test.py`)

These scripts are used to test the NGFW's behavior with various QUIC parameters, such as different Connection IDs, stream IDs, padding, and frame types, using a series of predefined test cases.

**Purpose:** To systematically test NGFW responses to manipulated QUIC protocol fields and behaviors.

**Steps:**

1.  **Backup Original Connection File:**
    As with `connection_ff.py`, back up your original `aioquic` `connection.py` file.
    ```bash
    sudo mv /usr/local/lib/python3.8/dist-packages/aioquic/quic/connection.py /usr/local/lib/python3.8/dist-packages/aioquic/quic/connection_orig.py
    ```
    *(Note: The exact path might vary based on your Python version and installation environment.)*

2.  **Replace Connection File:**
    Copy the provided `connection_cid.py` from this repository to your `aioquic` library directory, renaming it to `connection.py`. This modified file is used by `interop_test.py` to alter QUIC parameters.
    ```bash
    sudo cp connection_cid.py /usr/local/lib/python3.8/dist-packages/aioquic/quic/connection.py
    ```

3.  **Place Interoperability Test Script:**
    Copy `interop_test.py` to the `aioquic/examples/` directory on the machine that will run the test cases (usually the client).
    ```bash
    cp interop_test.py <path_to_aioquic>/examples/
    ```

4.  **Configure Server Details in `interop_test.py`:**
    Modify line 96 in `<path_to_aioquic>/examples/interop_test.py` to specify your server's details.
    ```python
    # Original line 96 (example):
    # Server("kdaquic", '172.16.2.2', port=4433, retry_port=4433, verify_mode=ssl.CERT_NONE),

    # Modify it to match your server hostname/IP and port:
    # Example: If your server IP is 192.168.1.100 and it's running on port 4433:
    Server("my-server-name", '192.168.1.100', port=4433, retry_port=4433, verify_mode=ssl.CERT_NONE),
    ```
    Replace `"kdaquic"` with a name for your server (used in test output) and `'172.16.2.2'` with your server's actual IP address.

5.  **Run an HTTP3 Server:**
    On your server machine, start a standard aioquic `http3_server.py` (or your `http3_server_fd.py` if testing file transfers in conjunction, though standard server is typical for interop tests).
    ```bash
    python <path_to_aioquic>/examples/http3_server.py --certificate <your_cert.pem> --private-key <your_key.pem>
    ```
    **Note for `test_retry`:** If you intend to run the `test_retry` case from `interop_test.py`, you must start the `http3_server.py` with the `--retry` option:
    ```bash
    python <path_to_aioquic>/examples/http3_server.py --certificate <your_cert.pem> --private-key <your_key.pem> --retry
    ```


6.  **Run a Test Case:**
    On the client machine, execute `interop_test.py` specifying the server name (as configured in step 4) and the test case you want to run.
    ```bash
    python <path_to_aioquic>/examples/interop_test.py --server my-server-name --test test_cid_not_in_list -v
    ```
    Replace `my-server-name` with the server name you set in `interop_test.py` and `test_cid_not_in_list` with the specific test method name from `interop_test.py`. The `-v` flag provides verbose output.

7.  **Observe Output:**
    The output will indicate the status of the test case (e.g., `my-server-name -------- M------- ---`). The specific format depends on the test.

**Notes:**
*   You can use `interop_test.py` as a general purpose QUIC test script. However, test cases specifically designed to manipulate Connection IDs via `connection_cid.py` will not function as intended if you haven't replaced `connection.py` as described in step 2.
*   To run the `"test_retry"` interop test case, you need to provide the `--retry` command-line argument when starting `http3_server.py`.

**Restoring Original Functionality:**
To revert to the standard `aioquic` behavior, restore your backup:
```bash
sudo mv /usr/local/lib/python3.8/dist-packages/aioquic/quic/connection_orig.py /usr/local/lib/python3.8/dist-packages/aioquic/quic/connection.py
```

## 4. Testing Connection Migration (`http3_client_conn_mig.py`)

This script is a modified version of `http3_client.py` designed to test QUIC connection migration.

**Purpose:** To observe how the NGFW handles a QUIC client changing its network address (IP address/port) mid-connection.

**Steps:**

1.  **Place Script in Examples Folder:**
    Copy `http3_client_conn_mig.py` to the `aioquic/examples/` directory on your **client machine**.
    ```bash
    cp http3_client_conn_mig.py <path_to_aioquic>/examples/
    ```

2.  **Run Server:**
    Start a standard aioquic `http3_server.py` on your server machine.
    ```bash
    python <path_to_aioquic>/examples/http3_server.py --certificate <your_cert.pem> --private-key <your_key.pem>
    ```

3.  **Run Client with Migration:**
    Execute the `http3_client_conn_mig.py` script from the client machine. You will typically need to ensure the client has multiple network interfaces or a way to change its source IP/port for migration to occur.
    ```bash
    python <path_to_aioquic>/examples/http3_client_conn_mig.py --ca-certs <your_ca_certs.pem> https://<server_ip>:<port>/<requested_path> -v
    ```
    *(e.g., `python examples/http3_client_conn_mig.py --ca-certs tests/pycacert.pem https://172.16.2.2:4433/ -v`)*

4.  **Observe:**
    The script is designed to initiate a connection migration. You should observe the client attempting to continue the QUIC session from a new address. The comments within the script (`http3_client_conn_mig.py`) provide guidance on when the migration is triggered:
    *   By default, it might be configured to migrate just before the start of content download.
    *   You can uncomment/comment sections of the code to change the migration timing (e.g., after content download completion).

**Notes:**
*   Effective testing of connection migration requires a client environment where changing the underlying network path (source IP/port) is possible and will result in packets being routed differently to the server.
*   The server must be configured to accept migrations (this is usually default behavior in aioquic).
