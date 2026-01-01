"""
Project Airdump - Encryption Utilities

GPG and SQLCipher key management helpers.
"""

import os
import logging
import subprocess
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class KeyManager:
    """Manage encryption keys (SQLCipher, GPG)."""
    
    def __init__(
        self,
        key_file: str = "/run/airdump/db.key",
        gpg_home: Optional[str] = None,
    ):
        """
        Initialize key manager.
        
        Args:
            key_file: Path for SQLCipher key (should be on tmpfs)
            gpg_home: GPG home directory
        """
        self.key_file = Path(key_file)
        self.gpg_home = gpg_home
        
    def set_db_key(self, key: str) -> bool:
        """
        Store SQLCipher key in RAM-only location.
        
        Args:
            key: Encryption key
            
        Returns:
            True if successful
        """
        try:
            # Ensure parent directory exists (should be tmpfs /run)
            self.key_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Write key with restricted permissions
            self.key_file.write_text(key)
            os.chmod(self.key_file, 0o600)
            
            logger.info(f"SQLCipher key stored in {self.key_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store DB key: {e}")
            return False
            
    def get_db_key(self) -> Optional[str]:
        """
        Retrieve SQLCipher key from storage.
        
        Returns:
            Key string or None if not found
        """
        try:
            if self.key_file.exists():
                return self.key_file.read_text().strip()
        except Exception as e:
            logger.error(f"Failed to read DB key: {e}")
        return None
        
    def clear_db_key(self) -> bool:
        """
        Securely remove SQLCipher key.
        
        Returns:
            True if successful
        """
        try:
            if self.key_file.exists():
                # Overwrite with random data before deletion
                size = self.key_file.stat().st_size
                self.key_file.write_bytes(os.urandom(size))
                self.key_file.unlink()
                logger.info("SQLCipher key cleared")
            return True
        except Exception as e:
            logger.error(f"Failed to clear DB key: {e}")
            return False
            

class GPGEncryption:
    """GPG encryption for pcap files."""
    
    def __init__(
        self,
        public_key_path: Optional[str] = None,
        gpg_home: Optional[str] = None,
    ):
        """
        Initialize GPG encryption.
        
        Args:
            public_key_path: Path to GPG public key for encryption
            gpg_home: GPG home directory
        """
        self.public_key_path = Path(public_key_path) if public_key_path else None
        self.gpg_home = gpg_home
        self._recipient: Optional[str] = None
        
    def import_public_key(self, key_path: str) -> bool:
        """
        Import GPG public key.
        
        Args:
            key_path: Path to public key file
            
        Returns:
            True if successful
        """
        try:
            cmd = ["gpg"]
            if self.gpg_home:
                cmd.extend(["--homedir", self.gpg_home])
            cmd.extend(["--import", key_path])
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info(f"Imported GPG key from {key_path}")
                return True
            else:
                logger.error(f"GPG import failed: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"GPG import error: {e}")
            return False
            
    def encrypt_file(
        self,
        input_path: str,
        output_path: Optional[str] = None,
        recipient: Optional[str] = None,
        delete_original: bool = False,
    ) -> Optional[str]:
        """
        Encrypt file with GPG.
        
        Args:
            input_path: Path to file to encrypt
            output_path: Output path (default: input_path + .gpg)
            recipient: GPG recipient ID/email
            delete_original: Delete original after encryption
            
        Returns:
            Path to encrypted file or None on failure
        """
        input_file = Path(input_path)
        if not input_file.exists():
            logger.error(f"Input file not found: {input_path}")
            return None
            
        output_file = Path(output_path) if output_path else Path(f"{input_path}.gpg")
        recipient = recipient or self._recipient
        
        if not recipient:
            logger.error("No GPG recipient specified")
            return None
            
        try:
            cmd = ["gpg"]
            if self.gpg_home:
                cmd.extend(["--homedir", self.gpg_home])
            cmd.extend([
                "--batch",
                "--yes",
                "--encrypt",
                "--recipient", recipient,
                "--output", str(output_file),
                str(input_file),
            ])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                logger.info(f"Encrypted {input_path} -> {output_file}")
                
                if delete_original:
                    input_file.unlink()
                    logger.info(f"Deleted original: {input_path}")
                    
                return str(output_file)
            else:
                logger.error(f"GPG encryption failed: {result.stderr}")
                return None
                
        except subprocess.TimeoutExpired:
            logger.error(f"GPG encryption timeout for {input_path}")
            return None
        except Exception as e:
            logger.error(f"GPG encryption error: {e}")
            return None
            
    def encrypt_directory(
        self,
        directory: str,
        pattern: str = "*.pcapng",
        recipient: Optional[str] = None,
        delete_originals: bool = False,
    ) -> int:
        """
        Encrypt all files matching pattern in directory.
        
        Args:
            directory: Directory to process
            pattern: Glob pattern for files
            recipient: GPG recipient
            delete_originals: Delete originals after encryption
            
        Returns:
            Number of files encrypted
        """
        encrypted = 0
        dir_path = Path(directory)
        
        for file_path in dir_path.glob(pattern):
            if self.encrypt_file(str(file_path), recipient=recipient, delete_original=delete_originals):
                encrypted += 1
                
        return encrypted


def prompt_for_key(prompt: str = "Enter encryption key: ") -> str:
    """
    Prompt user for encryption key (hidden input).
    
    Args:
        prompt: Prompt message
        
    Returns:
        Key string
    """
    import getpass
    return getpass.getpass(prompt)


def generate_random_key(length: int = 32) -> str:
    """
    Generate random encryption key.
    
    Args:
        length: Key length in bytes
        
    Returns:
        Hex-encoded key string
    """
    return os.urandom(length).hex()


def verify_key_strength(key: str, min_length: int = 16) -> bool:
    """
    Verify encryption key meets minimum requirements.
    
    Args:
        key: Key to verify
        min_length: Minimum length
        
    Returns:
        True if key is acceptable
    """
    if len(key) < min_length:
        return False
        
    # Check for some complexity (not all same character)
    if len(set(key)) < 4:
        return False
        
    return True
