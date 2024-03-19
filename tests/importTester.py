# Try importing the authenticate function
try:
    # Import the function directly from the file path
    from src.client.client import authenticate

    print("Import successful!")
except ModuleNotFoundError as e:
    print(f"Import error: {e}")