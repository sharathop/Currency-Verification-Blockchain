from django.db import models
from django.contrib.auth.models import User
import hashlib
import json

# ==========================================
# 1. BLOCKCHAIN LEDGER (LOCAL MIRROR)
# ==========================================
class Block(models.Model):
    index = models.IntegerField()
    timestamp = models.DateTimeField(auto_now_add=True)
    serial_no = models.CharField(max_length=100)
    
    # Value of the note (e.g. 500, 2000)
    denomination = models.CharField(max_length=10, default="Unknown")

    previous_hash = models.CharField(max_length=64)
    hash = models.CharField(max_length=64)
    
    # Metadata path (image location)
    meta_data_path = models.CharField(max_length=255, default="N/A") 

    def calculate_hash(self):
        # Hash includes denomination for security
        block_string = f"{self.index}{self.serial_no}{self.denomination}{self.previous_hash}{self.meta_data_path}"
        return hashlib.sha256(block_string.encode()).hexdigest()

    def save(self, *args, **kwargs):
        if not self.hash:
            self.hash = self.calculate_hash()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Block #{self.index} - ₹{self.denomination} [{self.serial_no}]"


# ==========================================
# 2. TRACKING & AUDIT LOGS
# ==========================================
class TrackingLog(models.Model):
    serial_number = models.CharField(max_length=100)
    scanned_by = models.ForeignKey(User, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=100) 
    location = models.CharField(max_length=100, default="Online Portal")
    
    # Security Flags
    is_suspicious = models.BooleanField(default=False)
    alert_message = models.CharField(max_length=200, blank=True)

    def __str__(self):
        return f"{self.serial_number} - {self.scanned_by.username}"


# ==========================================
# 3. INSTITUTE REGISTRY (AUTHORIZATION)
# ==========================================
class Institute(models.Model):
    institute_name = models.CharField(max_length=200)
    license_id = models.CharField(max_length=100, unique=True)
    registration_date = models.DateTimeField(auto_now_add=True)
    is_authorized = models.BooleanField(default=True) 

    def __str__(self):
        return f"{self.institute_name} ({self.license_id})"


# ==========================================
# 4. USER PROFILE (PHOTO & MOBILE)
# ==========================================
class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    mobile = models.CharField(max_length=15)
    # Stores profile picture in 'media/profiles/' folder
    profile_picture = models.ImageField(upload_to='profiles/', default='profiles/default.png', blank=True)
    
    def __str__(self):
        return self.user.username