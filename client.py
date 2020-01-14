import datetime
import select
import socket
import logging as log
import sys
import threading
import tkinter as tk

from dhcp_packet import DHCP_PACKET, DHCP_Message_Type, DHCP_Opcode, DHCP_Options

FORMAT = '[%(asctime)s] [%(levelname)s] : %(message)s'
log.basicConfig(stream=sys.stdout, level=log.DEBUG, format=FORMAT)

serverPort = 67
clientPort = 68
MAX_BYTES = 1024

UDP_IP = '0.0.0.0'

class DHCP_Client:
    def __init__(self, gui=None):
        self.dst = ('<broadcast>', serverPort)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ip = '0.0.0.0'
        self.mac = None
        self.waiting_response_time = 3
        self.sock.bind((UDP_IP, clientPort))
        self.time_ip_was_received = None
        self.gui = gui
        self.requested_options = []
        self.history_ip = set()
        check_lease_thread = threading.Thread(target=self.check_for_lease)
        check_lease_thread.daemon = True
        check_lease_thread.start()

    def configure_packet(self, packet: DHCP_PACKET):
        packet.opcode = DHCP_Opcode.REQUEST
        packet.client_hardware_address = self.mac
        packet.client_ip_address = self.ip

    def run(self, starting_message=DHCP_Message_Type.DHCP_DISCOVER, requested_ip=None):
        log.info("Sending DHCP_DISCOVER packet:")
        dhcp_packet = DHCP_PACKET(None)
        self.configure_packet(dhcp_packet)
        if self.requested_options:
            dhcp_packet.set_requested_options(self.requested_options)
            print(self.requested_options)
        if starting_message == DHCP_Message_Type.DHCP_DISCOVER:
            self.send_discover()
        elif starting_message == DHCP_Message_Type.DHCP_REQUEST:
            self.send_request(dhcp_packet, requested_ip)
        elif starting_message == DHCP_Message_Type.DHCP_RELEASE:
            self.send_release()
            self.gui.change_button_status(tk.NORMAL)
            return
        else:
            self.gui.change_button_status(tk.NORMAL)
            return

        #asteptam raspunsul
        try:
            while True:
                r, _, _ = select.select([self.sock], [], [], self.waiting_response_time)
                if not r:
                    self.gui.change_button_status(tk.NORMAL)
                    log.info("Nu s-a receptionat nimic de la server")
                    break
                else:
                    data = self.sock.recv(MAX_BYTES)
                    packet_received = DHCP_PACKET(data)
                    if packet_received.message_type == DHCP_Message_Type.DHCP_OFFER:
                        log.info("Offer received")
                        print(packet_received)

                        log.info("Send REQUEST")
                        self.send_request(packet_received)
                    elif packet_received.message_type == DHCP_Message_Type.DHCP_ACK:
                        log.info("Acknowledge received")
                        print(packet_received)
                        self.acknowledge_received(packet_received)
                    elif packet_received.message_type == DHCP_Message_Type.DHCP_NAK:
                        log.info("Negative Acknowledge received")
                        print(packet_received)
        except socket.timeout as e:
            log.info("Timpul de asteptare a expirat.")
            self.gui.change_button_status(tk.NORMAL)
            exit(1)

    def acknowledge_received(self, dhcp_packet):
        log.info("Am primit aprobare de la server. Pot folosi adresa {}".format(dhcp_packet.client_ip_address))
        self.ip = dhcp_packet.client_ip_address
        self.history_ip.add(self.ip)
        print(self.history_ip)
        self.lease = dhcp_packet.lease_time
        #test pentru release
        #self.lease = 10 #peste 10 secunde trimite release
        self.time_ip_was_received = datetime.datetime.now()
        if self.gui:
            self.gui.ip_label_var.set(self.ip)
            self.gui.lease_label_var.set(self.lease)
            self.gui.time_leased_label_var.set(self.time_ip_was_received)
            self.gui.complete_history_viewer()

    def send_discover(self):
        log.info("Sending Discover")
        dhcp_packet = DHCP_PACKET(None)
        if self.requested_options:
            dhcp_packet.set_requested_options(self.requested_options)
        self.configure_packet(dhcp_packet)
        dhcp_packet.message_type = DHCP_Message_Type.DHCP_DISCOVER
        print(dhcp_packet)

        message = dhcp_packet.encode()
        self.sock.sendto(message, self.dst)
        self.requested_options = []

    def send_request(self, dhcp_packet, requested_ip=None):
        log.info("Sending Request")
        self.configure_packet(dhcp_packet)
        dhcp_packet.message_type = DHCP_Message_Type.DHCP_REQUEST
        if requested_ip:
            dhcp_packet.your_ip_address = requested_ip
        print(dhcp_packet)

        message = dhcp_packet.encode()
        self.sock.sendto(message, self.dst)
        self.requested_options = []

    def send_decline(self, dhcp_packet):
        log.info("Sending Decline")

        self.configure_packet(dhcp_packet)
        dhcp_packet.message_type = DHCP_Message_Type.DHCP_DECLINE
        print(dhcp_packet)

        message = dhcp_packet.encode()
        self.sock.sendto(message, self.dst)

    def send_release(self):
        log.info("Sending Release")
        dhcp_packet = DHCP_PACKET(None)
        if self.requested_options:
            dhcp_packet.set_requested_options(self.requested_options)
        self.configure_packet(dhcp_packet)
        dhcp_packet.message_type = DHCP_Message_Type.DHCP_RELEASE
        dhcp_packet.client_ip_address = self.ip
        print(dhcp_packet)

        message = dhcp_packet.encode()
        self.sock.sendto(message, self.dst)
        self.ip = '0.0.0.0'
        self.gui.ip_label_var.set('None')
        self.gui.time_leased_label_var.set('None')
        self.requested_options = []

    def check_for_lease(self, time_sleep=3):
        import time
        while True:
            if self.ip != '0.0.0.0':
                if self.lease <= (datetime.datetime.now() - self.time_ip_was_received).total_seconds():
                    log.info("Lease time has expired. Sending RELEASE")
                    self.run(DHCP_Message_Type.DHCP_RELEASE)
                    self.run(DHCP_Message_Type.DHCP_DISCOVER)
                if self.lease * 7//8 <= self.lease <= (datetime.datetime.now() - self.time_ip_was_received).total_seconds():
                    log.info("Rebinding state. Sending REQUEST to other servers")
                    self.run(DHCP_Message_Type.DHCP_REQUESt)
                if self.lease // 2 <= self.lease <= (datetime.datetime.now() - self.time_ip_was_received).total_seconds():
                    log.info("Renewing state. Sending REQUEST")
                    self.run(DHCP_Message_Type.DHCP_REQUEST)

            time.sleep(time_sleep)
