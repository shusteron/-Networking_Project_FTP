from tkinter import DISABLED

import customtkinter


class StopUpload:
    def __init__(self):
        self.noButton = None
        self.yesButton = None
        self.root = None
        self.choice = None

    def createWindow(self):
        # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> CREATE WINDOW <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< #
        # Define the window appearance.
        self.root = customtkinter.CTk()
        self.root.title("File upload reached to half!")
        self.root.geometry("300x170")
        self.root.geometry("+1920+0")
        self.root.winfo_toplevel()

        # Define the frame.
        frame = customtkinter.CTkFrame(master=self.root)
        frame.pack(pady=20, padx=60, fill="both", expand=True)

        # ---------------------------------- WINDOW LABEL ----------------------------------#
        label = customtkinter.CTkLabel(master=frame, text="Do you want to continue?")
        label.pack(pady=1, padx=10)

        # ---------------------------------- WINDOW BUTTONS ----------------------------------#
        self.yesButton = customtkinter.CTkButton(master=frame, text="YES", command=self.yes)
        self.yesButton.pack(pady=12, padx=10)

        self.noButton = customtkinter.CTkButton(master=frame, text="NO", command=self.no)
        self.noButton.pack(pady=12, padx=10)

    # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> WINDOW METHODS <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< #
    # Handling situation if the user chose yes.
    def yes(self):
        self.disable_buttons()
        print("(+) Continuing to upload.")
        self.choice = True
        self.root.protocol("WM_DELETE_WINDOW", self.root.quit())

    # Handling situation if the user chose no.
    def no(self):
        self.disable_buttons()
        print("(-) Stopping upload.")
        self.choice = False
        self.root.protocol("WM_DELETE_WINDOW", self.root.quit())

    # Disable the yes/no button's usage.
    def disable_buttons(self):
        self.yesButton.configure(True, state=DISABLED)
        self.noButton.configure(True, state=DISABLED)

    # Returns user's choice.
    def getChoice(self):
        return self.choice

    # Starts gui
    def run(self):
        self.root.mainloop()
