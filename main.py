import customtkinter as ctk
import util
from tkinter import messagebox
import threading, time, random, os, subprocess, webbrowser
from PIL import Image
from customtkinter import CTkImage
from util import (
    run_rustscan, analyze_results, detect_environments, 
    get_local_ip, export_html_report, calculate_threat_score
)

ctk.set_appearance_mode("dark")

# =========================
# GLOBAL STATE
# =========================
is_scanning = False

# =========================
# APP SETUP
# =========================
root = ctk.CTk()
root.title("Fredo Super Cyber Analyst")
root.geometry("1200x700")

# =========================
# FULLSCREEN HANDLERS
# =========================
def toggle_fullscreen(event=None):
    root.attributes("-fullscreen", not root.attributes("-fullscreen"))
def exit_fullscreen(event=None):
    root.attributes("-fullscreen", False)
root.bind("<F4>", toggle_fullscreen)
root.bind("<Escape>", exit_fullscreen)

# =========================
# TOP STATUS BAR
# =========================
top_frame = ctk.CTkFrame(root)
top_frame.pack(fill="x")
status_label = ctk.CTkLabel(top_frame, text="STATUS: IDLE", font=("Consolas",14))
status_label.pack(side="left", padx=15)
def update_status(status):
    colors = {
        "READY": "#00ff9c", "DEGRADED": "#ff3b3b", 
        "ERROR": "#666666", "SCANNING": "#ffaa00", "IDLE": "#00aaff"
    }
    status_label.configure(text=f"STATUS: {status}", text_color=colors.get(status,"white"))
update_status("IDLE")

# =========================
# MAIN FRAME (CONSOLES + RIGHT PANEL)
# =========================
main_frame = ctk.CTkFrame(root)
main_frame.pack(fill="both", expand=True)

# Red console
left_console = ctk.CTkTextbox(main_frame, fg_color="#ff3b3b", text_color="#ffffff", font=("Consolas",11), wrap="none")
left_console.pack(side="left", fill="both", expand=True, padx=(5,2), pady=5)

# Blue console
right_console = ctk.CTkTextbox(main_frame, fg_color="#000814", text_color="#3ba6ff", font=("Consolas",11), wrap="none")
right_console.pack(side="left", fill="both", expand=True, padx=(2,5), pady=5)

# Right panel (must be packed after consoles)
right_panel = ctk.CTkFrame(main_frame, width=200, fg_color="#111111")
right_panel.pack(side="right", fill="y", padx=5, pady=5)

# Icon
icon_path = os.path.join("assets","Fredo_Cyber_Analyst.ico")
if os.path.exists(icon_path):
    icon_img = CTkImage(Image.open(icon_path), size=(120,120))
    ctk.CTkLabel(right_panel, image=icon_img, text="").pack(pady=10)
else:
    ctk.CTkLabel(right_panel, text="[ICON MISSING]", text_color="gray").pack(pady=10)

# Kali launch button
def launch_kali_terminal():
    try:
        result = subprocess.run(["wsl","-l","-q"], capture_output=True,text=True,timeout=5)
        distros = [d.strip() for d in result.stdout.splitlines() if d.strip()]
        kali_distro = next((d for d in distros if "kali" in d.lower()),None)
        if not kali_distro:
            messagebox.showerror("Kali Not Found","No Kali Linux detected in WSL.")
            return
        subprocess.Popen(["wsl","-d",kali_distro,"--","bash"], creationflags=subprocess.CREATE_NEW_CONSOLE)
    except Exception as e:
        messagebox.showerror("Error",f"Failed to launch Kali:\n{e}")
ctk.CTkButton(right_panel,text="💻 Launch Kali", fg_color="#ff4444", hover_color="#ff6666", command=launch_kali_terminal).pack(pady=10, padx=10, fill="x")

# =========================
# ENV STATUS
# =========================
env_frame = ctk.CTkFrame(right_panel, fg_color="#0a0a0a")
env_frame.pack(pady=10,padx=10,fill="x")
ctk.CTkLabel(env_frame,text="ENV STATUS", font=("Consolas",10,"bold")).pack()
env_labels={}
for env in ["WSL","Kali","Docker","Ollama"]:
    lbl = ctk.CTkLabel(env_frame,text=f"{env}: ...", anchor="w", font=("Consolas",9))
    lbl.pack(fill="x", padx=5, pady=2)
    env_labels[env]=lbl
def update_env_status():
    try:
        envs = detect_environments()
        for key,val in envs.items():
            if key in env_labels:
                color="#00ff9c" if val else "#ff3b3b"
                status="✓" if val else "✗"
                env_labels[key].configure(text=f"{key}: {status}", text_color=color)
    except:
        for lbl in env_labels.values():
            lbl.configure(text="ERROR", text_color="#ff3b3b")
update_env_status()

# =========================
# BOTTOM FRAME (TARGET DROPDOWN FIXED)
# =========================
bottom_frame = ctk.CTkFrame(root)
bottom_frame.pack(fill="x", padx=10, pady=10)

ip_data = {"localhost":"127.0.0.1","lan":get_local_ip(),"vpn":"N/A"}
target_var = ctk.StringVar(value="localhost")

ctk.CTkLabel(bottom_frame,text="TARGET:", font=("Consolas",10)).pack(side="left", padx=5)

# Ensure dropdown shows
target_dropdown = ctk.CTkOptionMenu(bottom_frame, values=list(ip_data.keys())+["custom"], variable=target_var, width=120)
target_dropdown.pack(side="left", padx=5)

target_entry = ctk.CTkEntry(bottom_frame, width=250, placeholder_text="Enter IP/domain/CIDR")
target_entry.pack(side="left", padx=5)
target_entry.insert(0, ip_data["localhost"])

def update_target_entry(*args):
    sel = target_var.get()
    if sel in ip_data: target_entry.delete(0,"end"); target_entry.insert(0,ip_data[sel])
    else: target_entry.delete(0,"end")
target_var.trace_add("write", update_target_entry)

red_progress = ctk.CTkProgressBar(bottom_frame,width=200)
red_progress.pack(side="left", padx=5)
blue_progress = ctk.CTkProgressBar(bottom_frame,width=200)
blue_progress.pack(side="left", padx=5)

# =========================
# BUTTONS
# =========================
def threaded_scan():
    global is_scanning
    if is_scanning: return
    is_scanning=True
    update_status("SCANNING")
    target = target_entry.get()
    if not target or target=="N/A":
        left_console.insert("end","[ERROR] Invalid target\n")
        update_status("IDLE"); is_scanning=False
        return
    left_console.delete("1.0","end"); right_console.delete("1.0","end")
    red_progress.set(0); blue_progress.set(0)
    left_console.insert("end",f"[SCAN STARTED] {target}\n\n")

    result = run_rustscan(target, mode="red")

    def typewriter(console,text,delay=0.002,progress=None):
        for i,ch in enumerate(text):
            console.insert("end",ch)
            console.see("end")
            if progress: progress.set((i+1)/len(text))
            console.update()
            time.sleep(delay)
    typewriter(left_console,result.get("output","No output"),progress=red_progress)

    analysis = analyze_results(result)
    typewriter(right_console,analysis,progress=blue_progress)

    result["threat_score"]=calculate_threat_score(result.get("open_ports",[]),analysis)

    try:
        report_file = export_html_report(target,result,analysis)
        webbrowser.open(report_file)
    except Exception as e:
        right_console.insert("end",f"\n[REPORT ERROR] {e}\n")

    update_env_status()
    update_status(result.get("status","READY"))
    is_scanning=False

ctk.CTkButton(right_panel,text="Analyze", fg_color="#339933", hover_color="#55ff55", command=lambda: threading.Thread(target=threaded_scan).start()).pack(pady=5, padx=5, fill="x")
ctk.CTkButton(right_panel,text="Clear Consoles", fg_color="#666666", hover_color="#999999", command=lambda: [left_console.delete("1.0","end"),right_console.delete("1.0","end")]).pack(pady=5, padx=5, fill="x")

# =========================
# ASCII AQUARIUM / MATRIX
# =========================
def asciiquarium_matrix():
    width, height = 60, 20
    fish_shapes = ["<°)))><", "<)))°>", "<(((((°>"]
    bubbles = ["o", ".", "O"]
    left_creatures, right_creatures = [], []
    left_rain = [random.randint(0, height-1) for _ in range(width)]
    right_rain = [random.randint(0, height-1) for _ in range(width)]

    def update_frame():
        nonlocal left_creatures, right_creatures, left_rain, right_rain
        buf_left = [[" "] * width for _ in range(height)]
        buf_right = [[" "] * width for _ in range(height)]
        # fish spawn
        if random.random() < 0.2:
            left_creatures.append({"row": random.randint(0, height-1), "col": width, "shape": random.choice(fish_shapes), "speed": random.randint(1,2)})
        if random.random() < 0.2:
            right_creatures.append({"row": random.randint(0, height-1), "col": width, "shape": random.choice(fish_shapes), "speed": random.randint(1,2)})
        # move left
        new_left=[]
        for c in left_creatures:
            c["col"] -= c["speed"]
            if c["col"] + len(c["shape"]) > 0:
                row,col=c["row"],c["col"]
                for i,ch in enumerate(c["shape"]):
                    if 0 <= col+i < width: buf_left[row][col+i]=ch
                new_left.append(c)
        left_creatures=new_left
        # move right
        new_right=[]
        for c in right_creatures:
            c["col"] -= c["speed"]
            if c["col"] + len(c["shape"]) > 0:
                row,col=c["row"],c["col"]
                for i,ch in enumerate(c["shape"]):
                    if 0 <= col+i < width: buf_right[row][col+i]=ch
                new_right.append(c)
        right_creatures=new_right
        # bubbles
        for _ in range(3):
            buf_left[random.randint(0,height-1)][random.randint(0,width-1)] = random.choice(bubbles)
            buf_right[random.randint(0,height-1)][random.randint(0,width-1)] = random.choice(bubbles)
        # matrix rain
        for x,row_idx in enumerate(left_rain):
            buf_left[row_idx][x] = str(random.randint(0, 9))
            left_rain[x] = (row_idx + 1) % height
        for x,row_idx in enumerate(right_rain):
            buf_right[row_idx][x] = str(random.randint(0, 9))
            right_rain[x] = (row_idx + 1) % height
        left_console.delete("1.0","end")
        left_console.insert("end","\n".join("".join(r) for r in buf_left))
        right_console.delete("1.0","end")
        right_console.insert("end","\n".join("".join(r) for r in buf_right))
        left_console.after(100, update_frame)
    update_frame()

asciiquarium_matrix()

root.mainloop()