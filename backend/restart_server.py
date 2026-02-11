#!/usr/bin/env python3
"""
Quick server restart script
"""
import subprocess
import time
import os
import signal

# Kill any existing uvicorn processes
print("Stopping old server processes...")
os.system('taskkill /F /IM python.exe /FI "COMMANDLINE eq *uvicorn*" 2>nul || true')
time.sleep(2)

# Start new server
print("Starting fresh server on port 8000...")
os.chdir(r"C:\Users\namit\Videos\student_projects\ATICE\backend")
subprocess.Popen([
    "python", "-m", "uvicorn", 
    "app.main:app", 
    "--host", "0.0.0.0", 
    "--port", "8000",
    "--reload"
])

print("✅ Server started successfully!")
print("Access at: http://localhost:8000")
