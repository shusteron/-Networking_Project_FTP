import tkinter
from tkinter import DISABLED, NORMAL

import customtkinter


class UploadType:
    def __init__(self):
        self.method_type = None
        self.submitButton = None
        self.packetLossRadio = None
        self.delayRadio = None
        self.regularlyRadio = None
        self.radio = None
        self.root = None

    def createWindow(self):
        # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> CREATE WINDOW <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< #
        # Define the window appearance.
        self.root = customtkinter.CTk()
        self.root.title("Upload style.")
        self.root.geometry("350x250")
        self.root.geometry("+1920+0")
        self.root.winfo_toplevel()
        self.root.protocol("WM_DELETE_WINDOW", self.root.quit())

        # Define the frame.
        frame = customtkinter.CTkFrame(master=self.root)
        frame.pack(pady=20, padx=60, fill="both", expand=True)

        # ---------------------------------- WINDOW LABEL ----------------------------------#
        label = customtkinter.CTkLabel(master=frame, text="Choose uploading method type.")
        label.pack(pady=1, padx=10)

        # ---------------------------------- WINDOW RADIO BUTTONS ----------------------------------#
        self.radio = tkinter.IntVar()

        # Regular radio button.
        self.regularlyRadio = customtkinter.CTkRadioButton(frame, text="Regularly", variable=self.radio, value=1,
                                                           command=self.enableSubmitButton)
        self.regularlyRadio.pack(pady=10, anchor="center")

        # Delay radio button.
        self.delayRadio = customtkinter.CTkRadioButton(frame, text="Delay", variable=self.radio, value=2,
                                                       command=self.enableSubmitButton)
        self.delayRadio.pack(pady=10, anchor="center")

        # Packet loss radio button.
        self.packetLossRadio = customtkinter.CTkRadioButton(frame, text="Packet loss", variable=self.radio, value=3,
                                                            command=self.enableSubmitButton)
        self.packetLossRadio.pack(pady=10, anchor="center")

        # ---------------------------------- WINDOW BUTTONS ----------------------------------#
        self.submitButton = customtkinter.CTkButton(master=frame, text="Submit", command=self.submit, state=DISABLED)
        self.submitButton.pack(pady=12, padx=10)

    # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> GUI Methods <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< #
    # Getting user's choice of which uploading method to use.
    def submit(self):
        self.regularlyRadio.configure(True, state=DISABLED)
        self.delayRadio.configure(True, state=DISABLED)
        self.packetLossRadio.configure(True, state=DISABLED)
        self.submitButton.configure(True, state=DISABLED)
        self.method_type = self.radio.get()
        self.root.quit()

    # Enabling submit button after any radio button selected.
    def enableSubmitButton(self):
        self.submitButton.configure(True, state=NORMAL)

    # Starts gui
    def run(self):
        self.root.mainloop()
