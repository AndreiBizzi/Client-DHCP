import re
import threading
import tkinter as tk
import logging as log
from client import *
from tkinter import font as tkfont, messagebox, ttk

FORMAT = '[%(asctime)s] [%(levelname)s] : %(message)s'
log.basicConfig(stream=sys.stdout, level=log.DEBUG, format=FORMAT)

class DHCP_Client_GUI(tk.Frame):
    def __init__(self, master=None):
        self.master = master
        tk.Frame.__init__(self, master, bg="black")

        self.title_font = tkfont.Font(family='arial', size=18, weight="bold")
        self.text_label_title = tkfont.Font(family='arial', size=12)
        self.button_text_font = tkfont.Font(family='arial', size=12)
        self.text_label = tkfont.Font(family='Arial', size=11)

        self.client = DHCP_Client(self)
        self.requested_ip = None


        self.init_window()


    def init_window(self):
        label_frame_bg = 'royalblue2'
        label_frame_txt = 'black'
        txt_color = 'black'#'#00FF41'

        button_bg = 'blue4'
        button_fg = '#ffffff'

        self.master.title("Client")
        self.pack(fill=tk.BOTH, expand=1)

        label_client_intro = tk.Label

        titleLabel = tk.Label(self, text="DHCP CLIENT", font='arial', bg=self['bg'], fg='white')
        titleLabel.pack(pady=2, padx=2)

        #RIGHT FRAME
        self.client_right_frame = tk.Frame(master=self, bg="black")
        self.client_right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=1, padx=10)

        client_info_label = tk.LabelFrame(self.client_right_frame, text="Client Info", bg=label_frame_bg,
                                          fg=label_frame_txt,
                                          font=self.text_label_title)
        client_info_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")

        self.mac_label_var = tk.StringVar()
        self.mac_label_var.set("None")
        tk.Label(client_info_label, text="MAC: ", bg=client_info_label["bg"], fg=txt_color,
                 font=self.text_label).grid(row=0, column=0, sticky='w')
        tk.Label(client_info_label, textvariable=self.mac_label_var, bg=client_info_label["bg"], fg=button_fg,
                 font=self.text_label, width=20).grid(row=0, column=1, sticky='w')

        self.ip_label_var = tk.StringVar()
        self.ip_label_var.set("None")
        tk.Label(client_info_label, text="IP: ", bg=client_info_label["bg"], fg=txt_color,
                 font=self.text_label).grid(row=1, column=0, sticky='w')
        tk.Label(client_info_label, textvariable=self.ip_label_var, bg=client_info_label["bg"], fg=button_fg,
                 font=self.text_label, width=20).grid(row=1, column=1, sticky='w')

        self.time_leased_label_var = tk.StringVar()
        self.time_leased_label_var.set("None")
        tk.Label(client_info_label, text="Time Leased: ", bg=client_info_label["bg"], fg=txt_color,
                 font=self.text_label).grid(row=2, column=0, sticky='w')

        tk.Label(client_info_label, textvariable=self.time_leased_label_var, bg=client_info_label["bg"], fg=button_fg,
                 font=self.text_label, width=20).grid(row=2, column=1, sticky='w')

        self.lease_label_var = tk.StringVar()
        self.lease_label_var.set("None")
        tk.Label(client_info_label, text="Lease: ", bg=client_info_label["bg"], fg=txt_color,
                 font=self.text_label).grid(row=3, column=0, sticky='w')
        tk.Label(client_info_label, textvariable=self.lease_label_var, bg=client_info_label["bg"], fg=button_fg,
                 font=self.text_label, width=20).grid(row=3, column=1, sticky='w')

        self.ip_requested_label_var = tk.StringVar()
        self.ip_requested_label_var.set("None")
        tk.Label(client_info_label, text="Ip Requested: ", bg=client_info_label["bg"], fg=txt_color,
                 font=self.text_label).grid(row=4, column=0, sticky='w')
        tk.Label(client_info_label, textvariable=self.ip_requested_label_var, bg=client_info_label["bg"], fg=button_fg,
                 font=self.text_label, width=20).grid(row=4, column=1, sticky='w')

        address_history_viewer_label = tk.LabelFrame(self.client_right_frame, text="Address History Viewer", bg=label_frame_bg,
                                                  fg='black', font=self.text_label)
        address_history_viewer_label.grid(row=1, column=0, padx=10, pady=10, sticky='w')

        self.ip_address_history_text = tk.Text(address_history_viewer_label, height=25, width=50, bg="#101010",
                                               fg='light green')
        ip_address_history_scroll = tk.Scrollbar(address_history_viewer_label, command=self.ip_address_history_text.yview)
        self.ip_address_history_text['yscrollcommand'] = ip_address_history_scroll.set
        self.ip_address_history_text.grid(row=0, column=0, sticky=tk.N + tk.S)
        ip_address_history_scroll.grid(row=0, column=1, sticky=tk.N + tk.S + tk.W)


        #LEFT FRAME
        self.client_left_frame = tk.Frame(master=self, bg="black")
        self.client_left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=1, padx=10)

        #client configurations frame
        mac_label_frame = tk.LabelFrame(self.client_left_frame, text="Client Configurations", bg=label_frame_bg, fg=label_frame_txt, font=self.text_label_title)
        mac_label_frame.grid(row=0, column=0, sticky='ew')

        tk.Label(mac_label_frame, text='MAC Address', bg=mac_label_frame["bg"], fg='black',
                 font=self.text_label).grid(row=0, column=0)
        self.mac_entry = ttk.Combobox(mac_label_frame, width=30, values=['aa:bb:cc:dd:ee:ff'])
        self.mac_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        self.set_mac = tk.Button(mac_label_frame, text='Set MAC',
                                                 command=self.set_mac, bg=button_bg, fg=button_fg,
                                                 font=self.button_text_font)
        self.set_mac.grid(row=0, column=2, padx=5, pady=5)

        # ----------client request frame
        request_label_frame = tk.LabelFrame(self.client_left_frame, text="Actions", bg=label_frame_bg,
                                            fg=label_frame_txt, font=self.text_label_title)
        request_label_frame.grid(row=3, column=0, pady=10, sticky='we')

        tk.Label(request_label_frame, text='IP Requested', bg=mac_label_frame["bg"], fg='black',
                 font=self.text_label).grid(row=0, column=0)
        self.ip_entry = tk.Entry(request_label_frame, width=30)
        self.ip_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        self.set_ip_requested = tk.Button(request_label_frame, text='Set IP to request',
                                          command=self.set_requested_ip, bg=button_bg, fg=button_fg,
                                          font=self.button_text_font)
        self.set_ip_requested.grid(row=0, column=2, padx=5, pady=5)


        #first row of options
        self.dns_var = tk.IntVar()
        self.dns_checkbutton = tk.Checkbutton(request_label_frame, text="DNS", onvalue=1,
                                                  offvalue=0, command=self.check_dns, variable=self.dns_var,
                                                  bg=request_label_frame["bg"], fg='white')
        self.dns_checkbutton.grid(row=1, column=0, padx=5, pady=5)

        self.server_var = tk.IntVar()
        self.server_checkbutton = tk.Checkbutton(request_label_frame, text="Server", onvalue=1,
                                              offvalue=0, command=self.check_server, variable=self.server_var,
                                              bg=request_label_frame["bg"], fg='white')
        self.server_checkbutton.grid(row=1, column=1, padx=5, pady=5)

        self.router_var = tk.IntVar()
        self.router_checkbutton = tk.Checkbutton(request_label_frame, text="Router", onvalue=1,
                                              offvalue=0, command=self.check_router, variable=self.router_var,
                                              bg=request_label_frame["bg"], fg='white')
        self.router_checkbutton.grid(row=1, column=2, padx=5, pady=5)

        #second row of options
        self.broadcast_var = tk.IntVar()
        self.broadcast_checkbutton = tk.Checkbutton(request_label_frame, text="Broadcast Address", onvalue=1,
                                              offvalue=0, command=self.check_broadcast, variable=self.broadcast_var,
                                              bg=request_label_frame["bg"], fg='white')
        self.broadcast_checkbutton.grid(row=2, column=0, padx=5, pady=5)

        self.subnet_mask_var = tk.IntVar()
        self.subnet_mask_checkbutton = tk.Checkbutton(request_label_frame, text="Subnet Mask", onvalue=1,
                                                 offvalue=0, command=self.check_subnet_mask, variable=self.subnet_mask_var,
                                                 bg=request_label_frame["bg"], fg='white')
        self.subnet_mask_checkbutton.grid(row=2, column=1, padx=5, pady=5)

        self.req_ip_var = tk.IntVar()
        self.req_ip_checkbutton = tk.Checkbutton(request_label_frame, text="Requested IP", onvalue=1,
                                                 offvalue=0, command=self.check_req_ip, variable=self.req_ip_var,
                                                 bg=request_label_frame["bg"], fg='white')
        self.req_ip_checkbutton.grid(row=2, column=2, padx=5, pady=5)

        self.send_request_btn = tk.Button(request_label_frame, text='Send REQUEST',
                  command=self.send_request, bg=button_bg, fg=button_fg,
                  font=self.button_text_font)
        self.send_request_btn.grid(row=3, column=0, padx=5, pady=5)

        self.send_discover_btn = tk.Button(request_label_frame, text='Send DISCOVER',
                  command=self.send_discover, bg=button_bg, fg=button_fg,
                  font=self.button_text_font)
        self.send_discover_btn.grid(row=3, column=1, padx=5, pady=5)

        self.send_release_btn = tk.Button(request_label_frame, text='Send RELEASE',
                  command=self.send_release, bg=button_bg, fg=button_fg,
                  font=self.button_text_font)
        self.send_release_btn.grid(row=3, column=2, padx=5, pady=5)

    def check_dns(self):
        if self.dns_var.get() == 1:
            self.dns_checkbutton["fg"] = 'red'
            #TODO
        else:
            self.dns_checkbutton["fg"] = 'white'

    def check_router(self):
        if self.router_var.get() == 1:
            self.router_checkbutton["fg"] = 'red'
            #TODO
        else:
            self.router_checkbutton["fg"] = 'white'

    def check_server(self):
        if self.server_var.get() == 1:
            self.server_checkbutton["fg"] = 'red'
            #TODO
        else:
            self.server_checkbutton["fg"] = 'white'

    def check_broadcast(self):
        if self.broadcast_var.get() == 1:
            self.broadcast_checkbutton["fg"] = 'red'
            # TODO
        else:
            self.broadcast_checkbutton["fg"] = 'white'

    def check_subnet_mask(self):
        if self.subnet_mask_var.get() == 1:
            self.subnet_mask_checkbutton["fg"] = 'red'
            # TODO
        else:
            self.subnet_mask_checkbutton["fg"] = 'white'

    def check_req_ip(self):
        if self.req_ip_var.get() == 1:
            self.req_ip_checkbutton["fg"] = 'red'
            # TODO
        else:
            self.req_ip_checkbutton["fg"] = 'white'

    def complete_history_viewer(self):
        self.ip_address_history_text.delete(1.0, tk.END)
        self.ip_address_history_text.insert(tk.END, "----IP HISTORY-----\n")
        for ip in self.client.history_ip:
            self.ip_address_history_text.insert(tk.END, ip + '\n')

    def set_requested_ip(self):
        ip = self.ip_entry.get()
        if not self.check_if_ip_is_valid(ip):
            messagebox.showinfo("IP ERRROR", "IP is not valid")
            return
        self.requested_ip = ip
        self.ip_requested_label_var.set(ip)

    def send_request(self):
        if self.client.mac is None:
            messagebox.showinfo("Message Error", "Could not send message. MAC is invalid or not set.")
            return
        self.change_button_status(tk.DISABLED)
        self.get_requested_options()
        log.info('Created thread for sending request')
        if self.requested_ip:
            args = (DHCP_Message_Type.DHCP_REQUEST, self.requested_ip)
        else:
            args = (DHCP_Message_Type.DHCP_REQUEST,)
        self.discover_thread = threading.Thread(target=self.client.run, args=args)
        self.discover_thread.daemon = True
        self.discover_thread.start()

        pass

    def send_discover(self):
        if self.client.mac is None:
            messagebox.showinfo("Message Error", "Could not send message. MAC is invalid or not set.")
            return
        self.change_button_status(tk.DISABLED)
        self.get_requested_options()
        log.info('Created thread for sending discover')
        self.discover_thread = threading.Thread(target=self.client.run, args=(DHCP_Message_Type.DHCP_DISCOVER,))
        self.discover_thread.daemon = True
        self.discover_thread.start()


    def change_button_status(self, status=tk.DISABLED):
        self.send_discover_btn['state'] = status
        self.send_release_btn['state'] = status
        self.send_request_btn['state'] = status

    def send_release(self):
        if self.client.mac is None:
            messagebox.showinfo("Message Error", "Could not send message. MAC is invalid or not set.")
            return
        self.change_button_status(tk.DISABLED)
        log.info('Created thread for sending release')
        self.get_requested_options()
        self.discover_thread = threading.Thread(target=self.client.run, args=(DHCP_Message_Type.DHCP_RELEASE,))
        self.discover_thread.daemon = True
        self.discover_thread.start()


    def get_requested_options(self):
        if self.dns_var.get():
            self.client.requested_options.append(DHCP_Options.OP_DNS)
        if self.server_var.get():
            self.client.requested_options.append(DHCP_Options.OP_SERVER_NAME)
        if self.router_var.get():
            self.client.requested_options.append(DHCP_Options.OP_ROUTER)
        if self.broadcast_var.get():
            self.client.requested_options.append(DHCP_Options.OP_BROADCAST_ADDRESS)
        if self.subnet_mask_var.get():
            self.client.requested_options.append(DHCP_Options.OP_SUBNETMASK)
        if self.req_ip_var.get():
            self.client.requested_options.append(DHCP_Options.OP_REQUESTED_IP)


    def set_mac(self):
        #validare mac
        mac_unk = (self.mac_entry.get()).lower()
        mac_checker = lambda mac: re.match("([0-9a-f]{2}[:]){5}([0-9a-f]{2})", mac)
        if mac_checker(mac_unk) is None:
            from tkinter import messagebox
            messagebox.showinfo("MAC format error", "MAC format is xx:xx:xx:xx:xx:xx where x in [0-9a-f]")
            return

        self.client.mac = mac_unk
        self.mac_label_var.set(self.client.mac)
        if mac_unk not in self.mac_entry['values']:
            self.mac_entry['values'] += (mac_unk,)
        log.info("MAC Set Succesfully : {}".format(self.client.mac))
        self.mac_entry['state'] = tk.DISABLED


    @staticmethod
    def gui_exit():
        log.info('Stopping Client')
        exit()

    @staticmethod
    def check_if_ip_is_valid(ip):
        try:
            socket.inet_aton(ip)
        except socket.error:
            return False
        return True
