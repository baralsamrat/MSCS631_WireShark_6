import os
import argparse
import pyshark
import requests
import zipfile
import io
import sys

# -------------------------------
# Helper Functions for Packet Analysis
# -------------------------------

def get_initial_syn_packet(capture):
    """
    Returns the packet number for the initial TCP SYN message
    (i.e. SYN flag is set and ACK flag is not set).
    Handles cases where flags are represented as "1"/"0" or "True"/"False".
    """
    for packet in capture:
        if 'TCP' in packet:
            try:
                syn_val = str(packet.tcp.flags_syn).strip()
                ack_val = str(packet.tcp.flags_ack).strip()
                # Check for both numeric and boolean string representations.
                if ((syn_val == "1" or syn_val.lower() == "true") and 
                    (ack_val == "0" or ack_val.lower() == "false")):
                    return int(packet.number)
            except AttributeError:
                continue
    return None

def get_tls_packet_by_handshake_type(capture, handshake_type_val):
    """
    Returns the first TLS packet with a handshake type matching handshake_type_val.
    Use:
      '1'  -> Client Hello,
      '2'  -> Server Hello,
      '11' -> Certificate,
      '14' -> Server Hello Done.
    """
    for packet in capture:
        if 'TLS' in packet:
            try:
                field = packet.tls.get_field('handshake_type')
                if field:
                    if isinstance(field, list):
                        if handshake_type_val in field:
                            return packet
                    else:
                        if field == handshake_type_val:
                            return packet
            except Exception:
                continue
    return None

def get_first_packet_by_content_type(capture, content_type_val):
    """
    Returns the first packet with the given TLS record content type.
    Examples:
      '20' for Change Cipher Spec,
      '23' for Application Data.
    """
    for packet in capture:
        if 'TLS' in packet:
            try:
                ctype = packet.tls.get_field('record_content_type')
                if ctype == content_type_val:
                    return packet
            except Exception:
                continue
    return None

def get_tls_close_notify_packet(capture):
    """
    Returns the first packet that appears to contain a TLS alert with 'close notify'.
    """
    for packet in capture:
        if 'TLS' in packet:
            try:
                if hasattr(packet.tls, 'alert_message'):
                    if "close notify" in packet.tls.alert_message.lower():
                        return packet
            except Exception:
                continue
    return None

def answer_lab6_questions_from_capture(capture):
    """
    Process a capture (live or offline) to extract fields needed for answering lab questions.
    Returns a dictionary with answers for questions 1–24.
    """
    answers = {}

    # Q1. Packet number with initial TCP SYN message.
    answers['Q1_initial_tcp_syn'] = get_initial_syn_packet(capture)

    # Q2. When is the TCP connection set up relative to TLS messages?
    answers['Q2_tcp_before_tls'] = (
        "The TCP three-way handshake is completed before the TLS Client Hello is sent."
    )

    # Q3. Packet number containing TLS Client Hello (handshake type 1).
    client_hello_pkt = get_tls_packet_by_handshake_type(capture, '1')
    answers['Q3_tls_client_hello'] = int(client_hello_pkt.number) if client_hello_pkt else None

    # Q4. TLS version from the Client Hello message.
    tls_version = None
    if client_hello_pkt:
        try:
            tls_version = client_hello_pkt.tls.handshake_version
        except AttributeError:
            tls_version = "Unknown"
    answers['Q4_tls_version'] = tls_version

    # Q5. Number of cipher suites supported by the client.
    num_cipher_suites = None
    if client_hello_pkt:
        try:
            cipher_suites = client_hello_pkt.tls.get_multiple_values('handshake_ciphersuite')
            num_cipher_suites = len(cipher_suites) if cipher_suites else 0
        except Exception as e:
            num_cipher_suites = f"Error: {e}"
    answers['Q5_cipher_suites_count'] = num_cipher_suites

    # Q6. First two hexadecimal digits of the client random bytes (skipping the 4-byte timestamp).
    client_random_bytes = None
    if client_hello_pkt:
        try:
            client_random = client_hello_pkt.tls.handshake_random.replace(":", "")
            if len(client_random) > 8:
                client_random_bytes = client_random[8:10]
            else:
                client_random_bytes = "N/A"
        except Exception as e:
            client_random_bytes = f"Error: {e}"
    answers['Q6_client_random_first_two'] = client_random_bytes

    # Q7. Purpose(s) of the client’s random bytes field.
    answers['Q7_client_random_purpose'] = (
        "They ensure that session keys are fresh and unpredictable by contributing randomness to key generation, "
        "thus protecting against replay attacks."
    )

    # Q8. Packet number containing TLS Server Hello (handshake type 2).
    server_hello_pkt = get_tls_packet_by_handshake_type(capture, '2')
    answers['Q8_tls_server_hello'] = int(server_hello_pkt.number) if server_hello_pkt else None

    # Q9. Which cipher suite has been chosen by the server.
    chosen_cipher_suite = None
    if server_hello_pkt:
        try:
            chosen_cipher_suite = server_hello_pkt.tls.handshake_ciphersuite
        except AttributeError:
            chosen_cipher_suite = "Unknown"
    answers['Q9_chosen_cipher_suite'] = chosen_cipher_suite

    # Q10. Does Server Hello contain random bytes and what are their purposes?
    answers['Q10_server_random_info'] = (
        "Yes, the Server Hello contains its own random field that ensures session uniqueness and contributes to key generation."
    )

    # Q11. Packet number for the TLS message containing the server's public key certificate (handshake type 11).
    certificate_pkt = get_tls_packet_by_handshake_type(capture, '11')
    answers['Q11_certificate_packet'] = int(certificate_pkt.number) if certificate_pkt else None

    # Q12. Are all certificates for the server? If not, who are the others for?
    answers['Q12_certificate_info'] = (
        "Typically, the first certificate is for the server (www.cics.umass.edu) and additional certificates are for intermediate CAs "
        "that build the chain of trust."
    )

    # Q13. Certification authority name issuing the certificate for www.cics.umass.edu.
    answers['Q13_ca_name'] = "DigiCert"  # Sample answer; may vary.

    # Q14. Digital signature algorithm used by the CA.
    answers['Q14_signature_algorithm'] = "sha256WithRSAEncryption"  # Sample answer.

    # Q15. First four hexadecimal digits of the modulus of the server’s public key.
    answers['Q15_public_key_modulus_first_four'] = "a3b1"  # Sample answer; adjust per your trace.

    # Q16. CA’s public key retrieval: is there a message from client to CA?
    answers['Q16_ca_public_key_message'] = (
        "No; the client uses its local trusted CA store to verify the certificate, so no direct message is sent."
    )

    # Q17. Packet number for the Server Hello Done record (handshake type 14).
    server_hello_done_pkt = get_tls_packet_by_handshake_type(capture, '14')
    answers['Q17_server_hello_done'] = int(server_hello_done_pkt.number) if server_hello_done_pkt else None

    # Q18. Packet number for the TLS message from the client that includes key info, Change Cipher Spec, and Encrypted Handshake.
    change_cipher_pkt = get_first_packet_by_content_type(capture, '20')
    answers['Q18_client_key_info_packet'] = int(change_cipher_pkt.number) if change_cipher_pkt else None

    # Q19. Does the client provide its own CA-signed public key certificate?
    answers['Q19_client_certificate'] = (
        "No – in typical HTTPS sessions, the client does not provide a certificate."
    )

    # Q20. Symmetric key algorithm used to encrypt application data.
    answers['Q20_symmetric_algorithm'] = (
        "AES 128 in CBC mode (as negotiated via the cipher suite, e.g., TLS_RSA_WITH_AES_128_CBC_SHA)."
    )

    # Q21. In which TLS message is the symmetric algorithm declared?
    answers['Q21_algorithm_declaration'] = (
        "It is declared during the handshake, typically in the Server Hello message."
    )

    # Q22. Packet number for the first encrypted application-data message (content type 23).
    app_data_pkt = get_first_packet_by_content_type(capture, '23')
    answers['Q22_first_app_data_packet'] = int(app_data_pkt.number) if app_data_pkt else None

    # Q23. Likely content of the encrypted application data.
    answers['Q23_app_data_content'] = (
        "The encrypted data likely contains the HTML content of the homepage fetched from www.cics.umass.edu."
    )

    # Q24. Packet number for the client-to-server TLS shutdown message (close_notify alert).
    close_notify_pkt = get_tls_close_notify_packet(capture)
    answers['Q24_tls_shutdown_packet'] = int(close_notify_pkt.number) if close_notify_pkt else None

    return answers

def download_zip(url, dest_zip):
    """
    Downloads a ZIP file from the specified URL and saves it as dest_zip.
    """
    try:
        print(f"Downloading ZIP file from {url} ...")
        r = requests.get(url)
        r.raise_for_status()
        with open(dest_zip, "wb") as f:
            f.write(r.content)
        print("Download completed.")
        return True
    except Exception as e:
        print(f"Error downloading ZIP file: {e}")
        return False

def extract_pcap_from_zip(dest_zip, target_filename, extract_to="."):
    """
    Extracts the target_filename from the ZIP file into the extract_to directory.
    If the file is found, returns True; otherwise, returns False.
    """
    try:
        with zipfile.ZipFile(dest_zip, 'r') as z:
            file_list = z.namelist()
            print("Files in ZIP:", file_list)
            if target_filename in file_list:
                print(f"Extracting {target_filename} ...")
                z.extract(target_filename, path=extract_to)
                print("Extraction completed.")
                return True
            else:
                print(f"{target_filename} not found in the ZIP archive.")
                return False
    except Exception as e:
        print(f"Error extracting from ZIP file: {e}")
        return False

# -------------------------------
# Main Execution
# -------------------------------

def main():
    parser = argparse.ArgumentParser(description="Wireshark Lab 6 Analysis Script")
    parser.add_argument("--mode", choices=["live", "offline"], default="offline",
                        help="Choose 'live' for live capture or 'offline' for pcap analysis.")
    parser.add_argument("--interface", default=None, help="Network interface for live capture (if applicable).")
    parser.add_argument("--duration", type=int, default=30, help="Duration (in seconds) for live capture.")
    parser.add_argument("--download", action="store_true", help="Download and extract pcap file if not found.")
    args = parser.parse_args()

    # Define the target capture file (the correct file for answering questions).
    pcap_file = "tls-wireshark-trace1.pcapng"  # Using the modern .pcapng file.
    zip_url = "http://gaia.cs.umass.edu/wireshark-labs/wireshark-traces-8.1.zip"
    zip_file = "wireshark-traces-8.1.zip"

    if args.mode == "live":
        print("Starting live capture ...")
        try:
            capture = pyshark.LiveCapture(interface=args.interface, display_filter="ip.addr==128.119.240.84")
            capture.sniff(timeout=args.duration)
        except Exception as e:
            print(f"Error during live capture: {e}")
            sys.exit(1)
        print("Live capture complete. Analyzing captured packets ...")
        answers = answer_lab6_questions_from_capture(capture)
        capture.close()
    else:
        # Offline mode: Check if the required pcap file exists.
        if not os.path.exists(pcap_file):
            print(f"PCAP file '{pcap_file}' not found in the current directory.")
            if args.download:
                if download_zip(zip_url, zip_file):
                    if not extract_pcap_from_zip(zip_file, pcap_file):
                        print("Extraction failed. Exiting.")
                        sys.exit(1)
                    if not os.path.exists(pcap_file):
                        print(f"After extraction, '{pcap_file}' still not found. Please verify the ZIP contents.")
                        sys.exit(1)
                else:
                    print("Download failed. Exiting.")
                    sys.exit(1)
            else:
                user_input = input("Do you want to download and extract the required pcap file? (y/n): ")
                if user_input.lower() == 'y':
                    if download_zip(zip_url, zip_file):
                        if not extract_pcap_from_zip(zip_file, pcap_file):
                            print("Extraction failed. Exiting.")
                            sys.exit(1)
                    else:
                        print("Download failed. Exiting.")
                        sys.exit(1)
                else:
                    print("No pcap file available. Exiting.")
                    sys.exit(1)
        print(f"Processing offline pcap file '{pcap_file}' ...")
        try:
            capture = pyshark.FileCapture(pcap_file, keep_packets=False)
        except Exception as e:
            print(f"Error opening pcap file: {e}")
            sys.exit(1)
        answers = answer_lab6_questions_from_capture(capture)
        capture.close()

    print("\nWireshark Lab 6 Answers:")
    for question, answer in answers.items():
        print(f"{question}: {answer}")

if __name__ == "__main__":
    main()
