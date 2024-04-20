def bytes_to_hex_string(byte_string):
    '''
        This function converts a bytes data to hexadecimal string

        Parameters:
        byte_string (byte): The data to convert

        Returns:
        string: the data converted to hexadecimal string  
    '''
    hex_string = byte_string.hex()
    return hex_string

def hex_string_to_bytes(hex_string):
    '''
        This function converts a hexadecimal string data to bytes

        Parameters:
        hex_string (string): The data to convert

        Returns:
        bytes: the data converted to bytes  
    '''
    byte_key = bytes.fromhex(hex_string)
    return byte_key

def to_bytes_like(data):
    '''
        This function converts a string, a list or a tuple in bytes-like data

        Parameters:
        data (string|list|tuple): The data to convert

        Returns:
        bytes: the data converted to bytes  
    '''
    if isinstance(data, str):
        byte_data = data.encode()
    elif isinstance(data, (list, tuple)):
        byte_data = bytes(data)
    else:
        raise TypeError("The data type is not supported. Supported types are: string, list and tuple")
    
    return byte_data