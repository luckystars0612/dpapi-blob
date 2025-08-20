import argparse
import base64
import logging
import os
from typing import Optional, Union
from impacket.dpapi import DPAPI_BLOB

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DPAPIDecryptor:
    """Class to handle DPAPI blob decryption using a masterkey."""
    
    @staticmethod
    def load_blob(data: str, from_file: bool = False) -> bytes:
        """
        Load and decode DPAPI blob from string or file, attempting base64 or hex decoding.
        
        Args:
            data: Input string or file path containing the encoded blob
            from_file: Whether to treat data as a file path
            
        Returns:
            Decoded blob bytes
            
        Raises:
            FileNotFoundError: If the specified file does not exist
            ValueError: If data cannot be decoded as base64 or hex
        """
        try:
            if from_file:
                if not os.path.exists(data):
                    raise FileNotFoundError(f"File not found: {data}")
                with open(data, "r", encoding='utf-8') as file:
                    data = file.read().strip()
                
            # Try base64 decoding first
            try:
                return base64.b64decode(data, validate=True)
            except base64.binascii.Error:
                # Fallback to hex decoding
                return bytes.fromhex(data)
                
        except (ValueError, base64.binascii.Error) as e:
            logger.error(f"Failed to decode blob: {str(e)}")
            raise ValueError("Input must be valid base64 or hex encoded string")

    @staticmethod
    def load_masterkey(data: str, from_file: bool = False) -> bytes:
        """
        Load and decode masterkey from string or file, attempting hex decoding.
        
        Args:
            data: Input string or file path containing the encoded masterkey
            from_file: Whether to treat data as a file path
            
        Returns:
            Decoded masterkey bytes
            
        Raises:
            FileNotFoundError: If the specified file does not exist
            ValueError: If data cannot be decoded as hex
        """
        try:
            if from_file:
                if not os.path.exists(data):
                    raise FileNotFoundError(f"File not found: {data}")
                with open(data, "r", encoding='utf-8') as file:
                    data = file.read().strip()
                
            return bytes.fromhex(data)
                
        except ValueError as e:
            logger.error(f"Failed to decode masterkey: {str(e)}")
            raise ValueError("Masterkey must be valid hex encoded string")

    @staticmethod
    def decrypt_blob(blob_bytes: bytes, masterkey_bytes: bytes) -> Optional[bytes]:
        """
        Decrypt DPAPI blob using the provided masterkey.
        
        Args:
            blob_bytes: Raw DPAPI blob bytes
            masterkey_bytes: Masterkey bytes for decryption
            
        Returns:
            Decrypted data bytes or None if decryption fails
        """
        try:
            blob = DPAPI_BLOB(blob_bytes)
            return blob.decrypt(masterkey_bytes)
        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            return None

    @classmethod
    def format_output(cls, decrypted_data: bytes) -> None:
        """
        Format and display decrypted data in multiple encodings.
        
        Args:
            decrypted_data: Decrypted data bytes
        """
        logger.info("Decrypted data:")
        try:
            logger.info(f"UTF-8  : {decrypted_data.decode('utf-8')}")
        except UnicodeDecodeError:
            logger.info("UTF-8  : [decode error]")
        logger.info(f"Hex    : {decrypted_data.hex()}")
        logger.info(f"Base64 : {base64.b64encode(decrypted_data).decode()}")

def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.
    
    Returns:
        Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="Decrypt DPAPI blob using a masterkey",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "-b", "--blob",
        help="DPAPI blob as base64 or hex string"
    )
    parser.add_argument(
        "-bf", "--blob-file",
        help="File containing DPAPI blob (base64 or hex)"
    )
    parser.add_argument(
        "-m", "--masterkey",
        help="Masterkey as hex string"
    )
    parser.add_argument(
        "-mf", "--masterkey-file",
        help="File containing masterkey (hex)"
    )
    
    return parser.parse_args()

def main():
    """Main function to orchestrate DPAPI blob decryption."""
    try:
        args = parse_arguments()
        
        # Validate input arguments
        if not (args.blob or args.blob_file):
            raise ValueError("You must provide either --blob or --blob-file")
        if not (args.masterkey or args.masterkey_file):
            raise ValueError("You must provide either --masterkey or --masterkey-file")
            
        # Load blob and masterkey
        decryptor = DPAPIDecryptor()
        blob_bytes = decryptor.load_blob(args.blob or args.blob_file, bool(args.blob_file))
        masterkey_bytes = decryptor.load_masterkey(args.masterkey or args.masterkey_file, bool(args.masterkey_file))
        
        # Perform decryption
        decrypted_data = decryptor.decrypt_blob(blob_bytes, masterkey_bytes)
        
        if decrypted_data:
            decryptor.format_output(decrypted_data)
        else:
            logger.error("Decryption failed. Verify the masterkey and blob are correct.")
            exit(1)
            
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        exit(1)

if __name__ == "__main__":
    main()