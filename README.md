# AIOQUIC-NGFW
Negative scenarios to test NGFW using AIOQUIC

1.How to use connection_ff.py and why

This will be used to send the first flight connection id with your own given number as connection id

move /usr/local/lib/python3.8/dist-packages/aioquic/quic/connection.py as connection_orig.py for backup purpose
(mv /usr/local/lib/python3.8/dist-packages/aioquic/quic/connection.py connection_orig.py)
Replace /usr/local/lib/python3.8/dist-packages/aioquic/quic/connection.py with connection_ff.py on the machine where you will run http3_client.py
(mv connection_ff.py /usr/local/lib/python3.8/dist-packages/aioquic/quic/connection.py)
Start running server and client
You will notice peer connection id will be "0011223344556677"
(change line number 314 with with own number)

2.How to use http3_client_fd.py and http3_server_fd.py and why

This will send the random file of size 100MB with name 10Gigfile1.pdf in chucks of data with multiple stream id(not multiplexing)
make changes in line number 
502,464,468(http3_client_fd.py):
485 (http3_server_fd.py)according to your wish

Copy  http3_client_fd.py and place it in the aioquic/examples folder on your client machine
Copy http3_server_fd.py and place it in the aioquic/examples folder on your sever machine
Start the server(http3_server_fd.py) and client(http3_client_fd.py

You will notice file being copied(not actual file but breaking it into parts and transfering)

3.How to use connection_cid.py and interop_test.py and why

This files will be used to run multiple cases like stream id ,connection id, padding , frame types

move /usr/local/lib/python3.8/dist-packages/aioquic/quic/connection.py as connection_orig.py for backup purpose
(mv /usr/local/lib/python3.8/dist-packages/aioquic/quic/connection.py connection_orig.py)
Replace /usr/local/lib/python3.8/dist-packages/aioquic/quic/connection.py with connection_cid.py on the machine where you will run http3_client.py
(mv connection_cid.py /usr/local/lib/python3.8/dist-packages/aioquic/quic/connection.py)
Move interop_test.py to aioquic/examples folder
(mv interop_test.py aioquic/examples)
Start running server
Make changes in the line 96 on interop_test.py
96 Server("kdaquic", '172.16.2.2', port=4433, retry_port=4433, verify_mode=ssl.CERT_NONE),
here "kdaquic" is my server name and "172.16.2.2" is my ip on which server started running

Run which ever testcase you want with 
python aioquic/examples/interop_test.py --server kdaquic --test test_cid_not_in_list -v
here "kdaquic" is my server name and "test_cid_not_in_list" is method present in interop_test.py

You will get an output as 
kdaquic             -------- M------- ---

here kdaquic is my server name
 
Note:-
You can use interop_test.py as a script with out even replacing /usr/local/lib/python3.8/dist-packages/aioquic/quic/connection.py with connection_cid.py but note that connection id cases will not work

Note:-
To run the "test_retry" interop testcase,you need to provide "--retry" command line argument on machine where your "http3_server.py" is running.
(--retry demo:app)

4.How to use http3_client_conn_mig.py and Why

Run this file same like as the http3_client.py(python3 examples/http3_client_conn_mig.py --ca-certs tests/pycacert.pem https://172.16.2.2:4433/ -v).
This script will do the connection migration and will use the new ip address to download the contents.
This script will do connection migration just before start of content download and not in the middle(Uncomment & comment code depending when you wanted to do connection migration(before start of contents download or after completion of contents download))





