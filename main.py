import socket
import tkinter as tk
import logging as log
from client import DHCP_Client
from dhcp_gui import DHCP_Client_GUI, DHCP_Message_Type

def start_gui():
    root = tk.Tk()
    root.geometry("1024x768")
    root.title("DHCP CLIENT")
    DHCP_Client_GUI(root)
    root.mainloop()

def Main():

    start_gui()
    #client = DHCP_Client()



if __name__ == '__main__':
    Main()
