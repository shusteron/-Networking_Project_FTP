import tkinter
from tkinter import NORMAL, messagebox, filedialog

import customtkinter

from Application.FTP_client import *


class Download:

    def __init__(self, domain):
        self.sortedList = None
        self.temp_list = None
        self.downloadNowBtn = None
        self.root = None
        self.listbox = None
        self.protocol = None
        self.domain = domain

    def createWindow(self, protocol):
        # Define the window appearance.
        self.root = customtkinter.CTk()
        self.root.title(self.domain)
        self.root.geometry("500x400")
        self.root.winfo_toplevel()
        self.root.protocol("WM_DELETE_WINDOW", self.root.quit())

        # Define the protocol the user chose.
        self.protocol = protocol

        # Define the frame.
        frame = customtkinter.CTkFrame(master=self.root)
        frame.pack(side="bottom", pady=20, padx=60, expand=True)
        frame.configure(width=90, height=150)

        # Creating the listbox.
        self.listbox = tkinter.Listbox(master=self.root, width=90, height=150, selectmode="SINGLE",
                                       bg="black", fg="white")
        self.listbox.pack(pady=120, padx=10)
        # Get the list of files in the directory.
        directory = "../Domains/" + self.domain
        file_list = os.listdir(directory)
        # Create a list to hold all the file names.
        self.temp_list = []
        for file_name in file_list:
            self.temp_list.append(file_name)
        self.sortedList = sorted(self.temp_list, key=str.lower)
        # Loop through the list and add each file name to the Listbox.
        for file in self.sortedList:
            self.listbox.insert(tkinter.END, file)

        # Creating the download button.
        self.downloadNowBtn = customtkinter.CTkButton(master=frame, text="Download Now", command=self.downloadNow,
                                                      state=NORMAL, bg_color="green", fg_color="green",
                                                      hover_color="green")
        self.downloadNowBtn.pack(side="bottom")

    # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> WINDOW Methods <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< #
    def run(self):
        self.root.mainloop()

    # Occurs when clicking on the download now button.
    def downloadNow(self):
        # Handle selected file.
        index = self.listbox.curselection()
        if not index:
            self.error_message()
        else:
            # Ask the user where to download the file.
            save_path = filedialog.askdirectory()
            # Save the requested file's name.
            file_name = self.temp_list[index[0]]
            if self.protocol == 1:
                downloadFromServerTCP(file_name, save_path)
            if self.protocol == 2:
                downloadFromServerRUDP(file_name, save_path)

    # Define a function to display a pop-up message if bo file selected.
    def error_message(self):
        messagebox.showinfo("Error", "No file was selected!")

