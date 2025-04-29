import subprocess
import sys
import os

def install_dependencies():
    """Install all required dependencies"""
    print("Installing dependencies...")
    
    # Core dependencies
    core_deps = [
        "pyyaml",
        "streamlit",
        "pandas",
        "plotly",
        "scapy",
        "pyshark",
        "psutil",
        "nest-asyncio",
        "watchdog",
        "pywin32",
        "pefile",
        "joblib",
        "scikit-learn",
        "numpy",
        "colorama",
        "tqdm",
        "python-dotenv"
    ]
    
    # Install each dependency
    for dep in core_deps:
        print(f"Installing {dep}...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", dep])
            print(f"✓ {dep} installed successfully")
        except subprocess.CalledProcessError:
            print(f"✗ Failed to install {dep}")
            return False
    
    print("\nAll dependencies installed successfully!")
    return True

if __name__ == "__main__":
    if install_dependencies():
        print("\nYou can now run the EDR system with:")
        print("python start_edr.py")
    else:
        print("\nSome dependencies failed to install. Please check the errors above.") 