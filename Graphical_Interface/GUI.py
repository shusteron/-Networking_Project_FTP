import tkinter
from tkinter import NORMAL, DISABLED, filedialog
import customtkinter
from Application.FTP_client import *
from Application.FTP_server import *
from Graphical_Interface.Download import Download
from Graphical_Interface.StopUpload import StopUpload
from Graphical_Interface.UploadType import UploadType
from Application.Send import *


class GUI:
    def __init__(self, client_ip, dns_ip):
        self.radio = None
        self.tcpRadio = None
        self.rudpRadio = None
        self.okButton = None
        self.root = None
        self.uploadButton = None
        self.downloadButton = None
        self.entry = None
        self.domain_ip = None
        self.client_ip = client_ip
        self.dns_ip = dns_ip

    def createGUI(self):
        # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> CREATE GUI <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< #
        # Define the window appearance.
        customtkinter.set_appearance_mode("dark")
        customtkinter.set_default_color_theme("dark-blue")
        self.root = customtkinter.CTk()
        self.root.title("FTPlace")
        self.root.geometry("500x500")
        # Remember to delete later.
        self.root.geometry("+1920+0")
        # Define protocol when closing GUI.
        self.root.protocol("WM_DELETE_WINDOW", self.root.quit())

        # Define the frame.
        frame = customtkinter.CTkFrame(master=self.root)
        frame.pack(pady=20, padx=60, fill="both", expand=True)

        # ---------------------------------- GUI LABELS ----------------------------------#

        label_client_ip = customtkinter.CTkLabel(master=frame, text="Your IP: " + self.client_ip)
        label_client_ip.pack(pady=1, padx=10)

        label_dns_ip = customtkinter.CTkLabel(master=frame, text="DNS IP: " + self.dns_ip)
        label_dns_ip.pack(pady=8, padx=10)

        self.entry = customtkinter.CTkEntry(master=frame, placeholder_text="FTP Server Address")
        self.entry.pack(pady=12, padx=10)

        # ---------------------------------- GUI BUTTONS ----------------------------------#
        # Checks if the domain is correct via 'ok' button or 'ENTER' key.
        self.okButton = customtkinter.CTkButton(master=frame, text="OK", command=self.connectDomain, state=DISABLED)
        self.okButton.pack(pady=12, padx=10)
        self.root.bind('<Return>', lambda event: self.okButton.invoke())

        # Opens a new window for downloading files.
        self.downloadButton = customtkinter.CTkButton(master=frame, text="Download", command=self.download_win
                                                      , state=DISABLED)
        self.downloadButton.pack(pady=12, padx=10)

        # Opens a new window for uploading files.
        self.uploadButton = customtkinter.CTkButton(master=frame, text="Upload", command=self.upload_win,
                                                    state=DISABLED)
        self.uploadButton.pack()

        # ---------------------------------- GUI RADIO BUTTONS ----------------------------------#
        self.radio = tkinter.IntVar()

        # RUDP radio button.
        self.rudpRadio = customtkinter.CTkRadioButton(frame, text="RUDP", variable=self.radio, value=2,
                                                      command=self.chooseRUDP)
        self.rudpRadio.pack(side="bottom")

        # TCP radio button.
        self.tcpRadio = customtkinter.CTkRadioButton(frame, text="TCP", variable=self.radio, value=1,
                                                     command=self.chooseTCP)
        self.tcpRadio.pack(side="bottom")

    # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> GUI METHODS <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< #

    # Function that calls connectDNS().
    def connectDomain(self):
        self.domain_ip = connectDNS(self, self.client_ip, self.dns_ip)
        if self.domain_ip:
            print("\n*********************************")
            # Create UDP socket.
            print("(*) Creating UDP socket...")
            client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Make the ports reusable.
            client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Send the chosen protocol to the server.
            client_sock.sendto(self.getDomain().encode(), SERVER_ADDRESS)
            print("(+) Sent the server the domain.")
            # Close the socket.
            client_sock.close()

    # Downloads file from the server.
    def download_win(self):
        download_window = Download(self.getDomain())
        download_window.createWindow(self.radio.get())
        download_window.run()

    # Uploads file from the file explorer.
    def upload_win(self):
        # Choosing file to upload.
        file_path = filedialog.askopenfilename()
        # Checking If he chose nothing.
        if not file_path:
            pass
        # Checking which radio button is selected (RUDP / TCP ).
        else:
            if self.radio.get() == 1:
                uploadToServerTCP(self, file_path)
            if self.radio.get() == 2:
                # Choosing way to upload.
                upload_type_win = UploadType()
                upload_type_win.createWindow()
                upload_type_win.run()
                if upload_type_win.method_type == 1:
                    uploadToServerRUDP(file_path, regularSend)
                    return
                elif upload_type_win.method_type == 2:
                    uploadToServerRUDP(file_path, delaySend)
                    return
                elif upload_type_win.method_type == 3:
                    uploadToServerRUDP(file_path, packetLossSend)
                    return
                else:
                    uploadToServerRUDP(file_path, regularSend)
                    return

    # Choose RUDP as the communication protocol.
    def chooseRUDP(self):
        self.okButton.configure(True, state=NORMAL)
        self.rudpRadio.configure(True, state=DISABLED)
        self.tcpRadio.pack_forget()
        sendCommunicationType("RUDP")

    # Choose TCP as the communication protocol.
    def chooseTCP(self):
        self.okButton.configure(True, state=NORMAL)
        self.tcpRadio.configure(True, state=DISABLED)
        self.rudpRadio.pack_forget()
        sendCommunicationType("TCP")

    # Clear the entry text field.
    def clear_entry(self):
        self.entry.delete(0, tkinter.END)

    # Enable the download/upload button's usage.
    def enable_buttons(self):
        self.downloadButton.configure(True, state=NORMAL)
        self.uploadButton.configure(True, state=NORMAL)

    # Disable the download/upload button's usage.
    def disable_buttons(self):
        self.downloadButton.configure(True, state=DISABLED)
        self.uploadButton.configure(True, state=DISABLED)

    # Returns the domain the user entered.
    def getDomain(self):
        if len(self.entry.get()) != 0:
            return self.entry.get()
        else:
            # Disable the buttons.
            self.downloadButton.configure(True, state=DISABLED)
            self.uploadButton.configure(True, state=DISABLED)
            self.entry.delete(0, tkinter.END)
            return ""

    def userUploadChoice(self):
        userChoice = StopUpload()
        userChoice.createWindow()
        userChoice.run()
        return userChoice.getChoice()

    def runGUI(self):
        self.root.mainloop()
