import ctypes
from ctypes import wintypes
import win32security  # You may need to install pywin32

# Load bcrypt.dll
bcrypt = ctypes.WinDLL('bcrypt.dll')

# Define constants
BCRYPT_ALG_HANDLE = 1
BCRYPT_KEY_HANDLE = 2
BCRYPT_PROV_HANDLE = 3

# Error codes
STATUS_SUCCESS = 0
STATUS_INVALID_PARAMETER = 0xC000000D
STATUS_BUFFER_TOO_SMALL = 0xC0000023

# Algorithm providers
BCRYPT_RSA_ALGORITHM = ctypes.c_wchar_p('RSA')
BCRYPT_ECDSA_P256_ALGORITHM = ctypes.c_wchar_p('ECDSA_P256')
BCRYPT_AES_ALGORITHM = ctypes.c_wchar_p('AES')

# Property names
BCRYPT_CHAINING_MODE = ctypes.c_wchar_p('ChainingMode')
BCRYPT_BLOCK_LENGTH = ctypes.c_wchar_p('BlockLength')
BCRYPT_KEY_LENGTH = ctypes.c_wchar_p('KeyLength')
BCRYPT_CHAINING_MODE_ECB = ctypes.c_wchar_p('ChainingModeECB')
BCRYPT_CHAINING_MODE_CBC = ctypes.c_wchar_p('ChainingModeCBC')

# Define function prototypes
BCryptOpenAlgorithmProvider = bcrypt.BCryptOpenAlgorithmProvider
BCryptOpenAlgorithmProvider.argtypes = [
    ctypes.POINTER(ctypes.c_void_p),  # phAlgorithm
    ctypes.c_wchar_p,                  # pszAlgId
    ctypes.c_wchar_p,                  # pszImplementation (use None for default)
    wintypes.DWORD                      # dwFlags
]
BCryptOpenAlgorithmProvider.restype = wintypes.LONG

BCryptSetProperty = bcrypt.BCryptSetProperty
BCryptSetProperty.argtypes = [
    ctypes.c_void_p,    # hObject
    ctypes.c_wchar_p,    # pszProperty
    ctypes.c_void_p,     # pbInput
    wintypes.DWORD,      # cbInput
    wintypes.DWORD       # dwFlags
]
BCryptSetProperty.restype = wintypes.LONG

BCryptGetProperty = bcrypt.BCryptGetProperty
BCryptGetProperty.argtypes = [
    ctypes.c_void_p,    # hObject
    ctypes.c_wchar_p,    # pszProperty
    ctypes.c_void_p,     # pbOutput
    wintypes.DWORD,      # cbOutput
    ctypes.POINTER(wintypes.DWORD),  # pcbResult
    wintypes.DWORD       # dwFlags
]
BCryptGetProperty.restype = wintypes.LONG

BCryptCloseAlgorithmProvider = bcrypt.BCryptCloseAlgorithmProvider
BCryptCloseAlgorithmProvider.argtypes = [
    ctypes.c_void_p,    # hAlgorithm
    wintypes.DWORD       # dwFlags
]
BCryptCloseAlgorithmProvider.restype = wintypes.LONG

class BCryptProvider:
    """Wrapper class for BCrypt algorithm provider"""
    
    def __init__(self):
        self.handle = None
    
    def open_provider(self, algorithm, implementation=None, flags=0):
        """Open an algorithm provider"""
        if self.handle is not None:
            raise Exception("Provider already open")
        
        ph_algorithm = ctypes.c_void_p()
        result = BCryptOpenAlgorithmProvider(
            ctypes.byref(ph_algorithm),
            algorithm,
            implementation,
            flags
        )
        
        if result != STATUS_SUCCESS:
            raise Exception(f"Failed to open algorithm provider. Error: {hex(result)}")
        
        self.handle = ph_algorithm.value
        return self.handle
    
    def set_property(self, property_name, value, flags=0):
        """Set a property on the algorithm provider"""
        if self.handle is None:
            raise Exception("Provider not opened")
        
        # Convert string to bytes if it's a string property
        if isinstance(value, str):
            # Add null terminator for string properties
            value_bytes = (value + '\0').encode('utf-16le')
            pb_input = ctypes.c_char_p(value_bytes)
            cb_input = len(value_bytes)
        elif isinstance(value, int):
            # Convert integer to DWORD
            value_bytes = ctypes.c_ulong(value)
            pb_input = ctypes.byref(value_bytes)
            cb_input = ctypes.sizeof(value_bytes)
        elif isinstance(value, bytes):
            pb_input = ctypes.c_char_p(value)
            cb_input = len(value)
        else:
            raise TypeError(f"Unsupported value type: {type(value)}")
        
        result = BCryptSetProperty(
            self.handle,
            property_name,
            pb_input,
            cb_input,
            flags
        )
        
        if result != STATUS_SUCCESS:
            raise Exception(f"Failed to set property. Error: {hex(result)}")
        
        return True
    
    def get_property(self, property_name, buffer_size=1024):
        """Get a property from the algorithm provider"""
        if self.handle is None:
            raise Exception("Provider not opened")
        
        # First call to get required buffer size
        pcb_result = wintypes.DWORD()
        result = BCryptGetProperty(
            self.handle,
            property_name,
            None,
            0,
            ctypes.byref(pcb_result),
            0
        )
        
        if result == STATUS_BUFFER_TOO_SMALL:
            # Allocate buffer of required size
            buffer = ctypes.create_string_buffer(pcb_result.value)
            
            # Second call to actually get the property
            result = BCryptGetProperty(
                self.handle,
                property_name,
                buffer,
                pcb_result.value,
                ctypes.byref(pcb_result),
                0
            )
            
            if result == STATUS_SUCCESS:
                # Try to decode as UTF-16 string if it looks like one
                try:
                    return buffer.raw.decode('utf-16le').rstrip('\0')
                except UnicodeDecodeError:
                    return buffer.raw
            else:
                raise Exception(f"Failed to get property. Error: {hex(result)}")
        else:
            raise Exception(f"Failed to get property size. Error: {hex(result)}")
    
    def close(self):
        """Close the algorithm provider"""
        if self.handle is not None:
            BCryptCloseAlgorithmProvider(self.handle, 0)
            self.handle = None

def example_usage():
    """Example of using BCryptSetProperty with different algorithms"""
    
    # Example 1: Set chaining mode for AES algorithm
    print("Example 1: AES algorithm - Setting chaining mode")
    aes_provider = BCryptProvider()
    try:
        # Open AES provider
        aes_provider.open_provider(BCRYPT_AES_ALGORITHM)
        print("AES provider opened successfully")
        
        # Set chaining mode to CBC
        aes_provider.set_property(
            BCRYPT_CHAINING_MODE,
            BCRYPT_CHAINING_MODE_CBC.value
        )
        print("Set chaining mode to CBC")
        
        # Verify the property was set
        current_mode = aes_provider.get_property(BCRYPT_CHAINING_MODE)
        print(f"Current chaining mode: {current_mode}")
        
    except Exception as e:
        print(f"Error in AES example: {e}")
    finally:
        aes_provider.close()
    
    print("\n" + "="*50 + "\n")
    
    # Example 2: Get available key lengths for RSA
    print("Example 2: RSA algorithm - Getting key length info")
    rsa_provider = BCryptProvider()
    try:
        # Open RSA provider
        rsa_provider.open_provider(BCRYPT_RSA_ALGORITHM)
        print("RSA provider opened successfully")
        
        # Get key length property
        try:
            key_lengths = rsa_provider.get_property(BCRYPT_KEY_LENGTH)
            print(f"Key length info: {key_lengths}")
        except Exception as e:
            print(f"Could not get key length: {e}")
        
    except Exception as e:
        print(f"Error in RSA example: {e}")
    finally:
        rsa_provider.close()
    
    print("\n" + "="*50 + "\n")
    
    # Example 3: Demonstrate error handling with invalid property
    print("Example 3: Error handling with invalid property")
    error_provider = BCryptProvider()
    try:
        error_provider.open_provider(BCRYPT_AES_ALGORITHM)
        print("AES provider opened successfully")
        
        # Try to set an invalid property
        error_provider.set_property("InvalidProperty", "InvalidValue")
        
    except Exception as e:
        print(f"Expected error: {e}")
    finally:
        error_provider.close()

if __name__ == "__main__":
    # Note: This script requires the pywin32 package
    # Install with: pip install pywin32
    
    print("Windows BCryptSetProperty Demo")
    print("="*50)
    
    # Run examples
    example_usage()
    
    # Additional example with raw ctypes calls
    print("\n" + "="*50)
    print("Raw ctypes example:")
    
    # Raw ctypes approach
    h_algorithm = ctypes.c_void_p()
    
    try:
        # Open algorithm provider
        result = BCryptOpenAlgorithmProvider(
            ctypes.byref(h_algorithm),
            BCRYPT_AES_ALGORITHM,
            None,
            0
        )
        
        if result == STATUS_SUCCESS:
            print("Algorithm provider opened successfully")
            
            # Set property using raw ctypes
            chaining_mode = "ChainingModeCBC\0"  # Include null terminator
            chaining_mode_bytes = chaining_mode.encode('utf-16le')
            
            result = BCryptSetProperty(
                h_algorithm.value,
                BCRYPT_CHAINING_MODE,
                chaining_mode_bytes,
                len(chaining_mode_bytes),
                0
            )
            
            if result == STATUS_SUCCESS:
                print("Property set successfully using raw ctypes")
            else:
                print(f"Failed to set property: {hex(result)}")
        else:
            print(f"Failed to open provider: {hex(result)}")
            
    finally:
        if h_algorithm.value:
            BCryptCloseAlgorithmProvider(h_algorithm.value, 0)
