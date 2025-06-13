import socket
import threading
import tkinter as tk
from tkinter import messagebox

# Global variable to control scanning
stop_scan = False  

# Function to scan a single port
def scan_port(target, port, output_box):
    global stop_scan
    if stop_scan:  # Stop scanning if the flag is set
        return

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        sock.close()

        if result == 0:
            output_box.insert(tk.END, f"✅ Port {port} is OPEN\n")
        else:
            output_box.insert(tk.END, f"❌ Port {port} is CLOSED\n")

        output_box.update()  # Refresh the output in real-time

    except Exception as e:
        output_box.insert(tk.END, f"Error scanning port {port}: {e}\n")

# Function to scan multiple ports using threading
def start_scan():
    global stop_scan
    stop_scan = False  # Reset the stop flag

    target_ip = ip_entry.get()
    try:
        start_port = int(start_port_entry.get())
        end_port = int(end_port_entry.get())
    except ValueError:
        messagebox.showerror("Error", "Please enter valid port numbers.")
        return

    if not target_ip:
        messagebox.showerror("Error", "Please enter a target IP address.")
        return

    output_box.delete(1.0, tk.END)  # Clear previous results
    output_box.insert(tk.END, f"🔍 Scanning {target_ip} from port {start_port} to {end_port}...\n\n")

    def threaded_scan():
        for port in range(start_port, end_port + 1):
            if stop_scan:  # Stop scanning if button is pressed
                output_box.insert(tk.END, "\n⛔ Scan Stopped!\n")
                break
            scan_port(target_ip, port, output_box)

    scan_thread = threading.Thread(target=threaded_scan)
    scan_thread.start()

# Function to stop the scan
def stop_scan_now():
    global stop_scan
    stop_scan = True  # Set flag to stop scanning

# Create the main GUI window
root = tk.Tk()
root.title("Port Scanner")
root.geometry("500x450")
root.config(bg="#f0f0f0")

# Heading
tk.Label(root, text="Port Scanner", font=("Arial", 16, "bold"), bg="#f0f0f0").pack(pady=10)

# IP Address Input
tk.Label(root, text="Enter Target IP:", font=("Arial", 12), bg="#f0f0f0").pack()
ip_entry = tk.Entry(root, font=("Arial", 12))
ip_entry.pack(pady=5)

# Port Range Inputs
tk.Label(root, text="Start Port:", font=("Arial", 12), bg="#f0f0f0").pack()
start_port_entry = tk.Entry(root, font=("Arial", 12))
start_port_entry.pack(pady=5)
start_port_entry.insert(0, "1")  # Default value

tk.Label(root, text="End Port:", font=("Arial", 12), bg="#f0f0f0").pack()
end_port_entry = tk.Entry(root, font=("Arial", 12))
end_port_entry.pack(pady=5)
end_port_entry.insert(0, "1024")  # Default value

# Buttons (Start & Stop Scan)
button_frame = tk.Frame(root, bg="#f0f0f0")
button_frame.pack(pady=10)

scan_button = tk.Button(button_frame, text="Start Scan", font=("Arial", 12), bg="#4CAF50", fg="white", command=start_scan)
scan_button.pack(side=tk.LEFT, padx=10)

stop_button = tk.Button(button_frame, text="Stop Scan", font=("Arial", 12), bg="red", fg="white", command=stop_scan_now)
stop_button.pack(side=tk.LEFT, padx=10)

# Output Box
output_box = tk.Text(root, height=10, width=50, font=("Arial", 10))
output_box.pack(pady=10)

# Run the GUI
root.mainloop()
